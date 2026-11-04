#!/usr/bin/env python3
"""Ciphey's end-to-end benchmark: run decoders on corpus v1 and report accuracy and time.

    python3 benches/e2e/run.py target/release/ciphey                    # one binary, every case
    python3 benches/e2e/run.py --subset quick OLD/ciphey NEW/ciphey      # A/B, interleaved per case
    python3 benches/e2e/run.py python-ciphey:.tools/pyciphey/bin/python  # Python Ciphey 5.x
    python3 benches/e2e/run.py cyberchef:.tools/node                     # CyberChef Magic (depth 3)
    python3 benches/e2e/run.py cyberchef-intensive:.tools/node           # ... with intensive mode
    python3 benches/e2e/run.py --selftest                                # the parsers and verdict rules
    python3 benches/e2e/run.py --summarize target/e2e/*/results.tsv     # one table from saved runs

A tool is `[name=][adapter:]path`; the adapter defaults to `ciphey` (any ciphey binary). With
two tools the cases run interleaved, A then B on even cases and B then A on odd ones, so host
load hits both alike, and the summary lists every case whose verdict changed.

Every run of a case gets a fresh HOME (so nothing is cached), the input on its command line,
no terminal and no prompts: `ciphey -d -c TIMEOUT --text=INPUT`, RAYON_NUM_THREADS=--threads.
A run is killed after TIMEOUT + 1 s of wall-clock time. Accuracy is deterministic up to cases
that finish close to the timeout; `--repeat 2` (or the same binary as A and B) shows them.

Outputs go to target/e2e/<UTC time>/: results.tsv, summary.md and meta.json. The summary is
printed too, with the host load (`uptime`) before and after. Standard library only.
"""

import argparse
import datetime
import fnmatch
import hashlib
import json
import math
import os
import platform
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
from cyberchef import CyberChef, CyberChefError  # noqa: E402  (stdlib only, next to this file)
CONFIG_TOML = os.path.join(ROOT, "benches", "data", "config.toml")
CATEGORIES = ["encoding", "classical", "hash", "chain", "flag", "short", "long", "language", "plaintext", "no_answer"]
ADAPTERS = ["ciphey", "python-ciphey", "cyberchef", "cyberchef-intensive"]
GRACE = 1.0  # seconds past --timeout before a run is killed
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


# ---------------------------------------------------------------------------------------
# Corpus


def unesc(s):
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            out.append({"\\": "\\", "t": "\t", "n": "\n", "r": "\r"}[s[i + 1]])
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


class Case:
    def __init__(self, row):
        self.id, self.category, layers, tools, self.xfail, self.match, subset, self.source, inp, exp = row
        self.layers = layers.split(",") if layers else []
        self.tools = set(tools.split(","))
        self.subset = set(subset.split(",")) if subset else set()
        self.input, self.expected = unesc(inp), unesc(exp)


def corpora():
    """The corpora in benches/data/e2e, by file name."""
    data = os.path.join(ROOT, "benches", "data", "e2e")
    return {name: os.path.join(data, name) for name in sorted(os.listdir(data)) if re.fullmatch(r"corpus-v\d+\.tsv", name)}


def load_corpus(path):
    with open(path, encoding="utf-8") as fh:
        raw = fh.read()
    lines = [ln for ln in raw.split("\n") if ln and not ln.startswith("#")]
    header = lines[0].split("\t")
    assert header[0] == "id", header
    return [Case(ln.split("\t")) for ln in lines[1:]], hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------------------
# Matching


def normalize(s, mode):
    s = s.replace("\r\n", "\n")
    if mode == "fold":
        return " ".join(s.casefold().split())
    if mode == "letters":
        return "".join(c for c in s.casefold() if c.isalnum())
    if mode == "json":
        try:
            return json.dumps(json.loads(s), sort_keys=True)
        except ValueError:
            return " ".join(s.split())
    return s.rstrip()


def verdict(case, status, output):
    """correct / wrong / nothing for one run."""
    if status == "error":  # a crash or unreadable output is never a correct give-up
        return "nothing"
    if case.expected == "-":  # no plaintext: giving up is right, any answer is a false positive
        return "wrong" if status == "answer" else "correct"
    if status == "answer":
        return "correct" if normalize(output, case.match) == normalize(case.expected, case.match) else "wrong"
    if status == "none" and output is not None and output == case.input == case.expected:
        return "correct"  # CyberChef suggesting nothing better than an input that is the plaintext
    return "nothing"


# ---------------------------------------------------------------------------------------
# Tools


def kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def run_process(argv, env, timeout, cwd=None, stdin=None):
    """(stdout, stderr, returncode or None if killed, seconds). stdin is /dev/null unless given."""
    t0 = time.perf_counter()
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL if stdin is None else subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, cwd=cwd, start_new_session=True)
    try:
        out, err = proc.communicate(input=stdin, timeout=timeout)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        kill_group(proc)
        out, err = proc.communicate()
        rc = None
    return out.decode("utf-8", "replace"), err.decode("utf-8", "replace"), rc, time.perf_counter() - t0


class Tool:
    adapter = None

    def __init__(self, name, path, args):
        self.name, self.path, self.args = name, path, args
        self.scratch = tempfile.mkdtemp(prefix=f"ciphey-e2e-{self.adapter}-")

    def comparable(self, case):
        return self.adapter in case.tools

    def fresh_home(self):
        home = tempfile.mkdtemp(dir=self.scratch)
        return home, {**os.environ, "HOME": home, "TERM": "dumb", "NO_COLOR": "1", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                      "PYTHONIOENCODING": "utf-8", "RAYON_NUM_THREADS": str(self.args.threads)}

    def info(self):
        return {"adapter": self.adapter, "path": self.path}

    def close(self):
        shutil.rmtree(self.scratch, ignore_errors=True)


def parse_ciphey(out, err, rc):
    """(status, answer, decoder path) from a ciphey run's stdout, stderr and exit code (None if
    it was killed). The answer is the text between "The plaintext is:" and the last "the
    decoder(s) used" line. "none" needs ciphey's own failure message: other output that has no
    answer is an "error", so a broken binary doesn't get credited with giving up."""
    text = ANSI.sub("", out)
    marker = "The plaintext is:\n"
    if rc is None:
        return "timeout", None, ""
    i = text.find(marker)
    if i >= 0:
        rest = text[i + len(marker):]
        found = list(re.finditer(r"\nthe decoders? used (?:is|are) ", rest))
        if found:
            last = found[-1]
            return "answer", rest[: last.start()], rest[last.end():].split("\n", 1)[0].strip()
        return "answer", rest.rstrip("\n"), ""
    if rc != 0:
        return "error", None, f"exit {rc}: {err.strip()[-200:]}"
    if "ciphey has failed to decode the text." not in text:
        return "error", None, "no answer and no failure message: " + text.strip()[-200:]
    if "Timed out" in err:
        return "timeout", None, ""
    return "none", None, ""


def parse_python_ciphey(out, err, rc):
    """(status, answer, decoder path) from python_ciphey.py's JSON line."""
    if rc is None:
        return "timeout", None, ""
    lines = [ln for ln in out.splitlines() if ln.startswith("{")]
    if rc != 0 or not lines:
        return "error", None, f"exit {rc}: {err.strip()[-200:]}"
    res = json.loads(lines[-1])
    if res["status"] == "answer":
        return "answer", res["plaintext"], " → ".join(res["path"])
    return "none", None, ""


def magic_answer(reply, case_input):
    """(status, answer, recipe) from the worker's Magic reply: the first suggestion, or "none"
    with the input itself when nothing ranks above the input."""
    results = reply["results"]
    if not results:  # "Nothing of interest could be detected about the input data"
        return "none", case_input, ""
    top = results[0]
    if not top["recipe"]:
        return "none", case_input, ""
    if top["output"] is None:
        return "error", None, "recipe failed: " + " → ".join(top["recipe"])
    return "answer", top["output"], " → ".join(top["recipe"])


class CipheyTool(Tool):
    """Any ciphey binary: `ciphey -d -c T --text=INPUT` with a fresh HOME."""

    adapter = "ciphey"

    def comparable(self, case):
        return True  # every case is a Ciphey case; xfail marks the ones it can't do yet

    def run(self, case):
        home, env = self.fresh_home()
        os.makedirs(os.path.join(home, ".ciphey"))
        with open(CONFIG_TOML, encoding="utf-8") as fh:
            config = fh.read()
        config = re.sub(r"(?m)^timeout = \d+", f"timeout = {self.args.timeout}", config)
        with open(os.path.join(home, ".ciphey", "config.toml"), "w", encoding="utf-8") as fh:
            fh.write(config)
        argv = [self.path, "-d", "-c", str(self.args.timeout), "--text=" + case.input]
        out, err, rc, secs = run_process(argv, env, self.args.timeout + GRACE)
        shutil.rmtree(home, ignore_errors=True)
        return parse_ciphey(out, err, rc) + (secs,)

    def info(self):
        info = super().info()
        with open(self.path, "rb") as fh:
            info["sha256"] = hashlib.sha256(fh.read()).hexdigest()
        return info


class PythonCipheyTool(Tool):
    """Python Ciphey 5.x: `python python_ciphey.py < INPUT` (the human checker off, as `-q`)."""

    adapter = "python-ciphey"

    def run(self, case):
        home, env = self.fresh_home()
        out, err, rc, secs = run_process([self.path, os.path.join(HERE, "python_ciphey.py")], env,
                                         self.args.timeout + GRACE, stdin=case.input.encode("utf-8"))
        shutil.rmtree(home, ignore_errors=True)
        return parse_python_ciphey(out, err, rc) + (secs,)

    def info(self):
        info = super().info()
        info["version"] = subprocess.run([self.path, "-c", "import importlib.metadata as m; print(m.version('ciphey'))"],
                                         capture_output=True, text=True, timeout=60).stdout.strip()
        info["python"] = subprocess.run([self.path, "-V"], capture_output=True, text=True, timeout=60).stdout.strip()
        return info


class CyberChefTool(Tool):
    """CyberChef's Node API: Magic, depth 3, intensive mode off or on, in one warm Node process.
    The answer is Magic's first suggestion, baked on the whole input."""

    adapter = "cyberchef"
    intensive = False

    def __init__(self, name, path, args):
        super().__init__(name, path, args)
        self.chef = CyberChef(path, node=args.node)
        self.chef.start()

    def run(self, case):
        self.last_alternatives = []
        try:
            if self.chef.proc is None or self.chef.proc.poll() is not None:
                self.chef.start()  # after a timeout or a crash; its start-up isn't the case's time
            t0 = time.perf_counter()
            reply = self.chef.magic(case.input, depth=self.args.depth, intensive=self.intensive, top=5,
                                    timeout=self.args.timeout + GRACE)
        except CyberChefError as e:  # the worker died or failed: this case is an error, the next one restarts it
            self.chef.close()
            return "error", None, str(e).splitlines()[0][:200], 0.0
        if reply is None:
            return "timeout", None, "", time.perf_counter() - t0
        self.last_alternatives = [r["output"] for r in reply["results"]]
        return magic_answer(reply, case.input) + (reply["ms"] / 1000,)

    def info(self):
        info = super().info()
        info.update(version=self.chef.version(), depth=self.args.depth, intensive_mode=self.intensive,
                    extensive_language_support=False, crib="", startup_seconds=self.chef.startup_seconds)
        return info

    def close(self):
        self.chef.close()
        super().close()


class CyberChefIntensiveTool(CyberChefTool):
    adapter = "cyberchef-intensive"
    intensive = True


TOOL_CLASSES = {c.adapter: c for c in (CipheyTool, PythonCipheyTool, CyberChefTool, CyberChefIntensiveTool)}


def make_tool(spec, args, index):
    name = None
    if "=" in spec.split(":", 1)[0]:
        name, spec = spec.split("=", 1)
    adapter, path = "ciphey", spec
    head = spec.split(":", 1)[0]
    if ":" in spec and head in TOOL_CLASSES:
        adapter, path = spec.split(":", 1)
    path = os.path.abspath(path)
    if not name:
        name = adapter if adapter != "ciphey" else os.path.basename(os.path.dirname(path)) or f"ciphey{index}"
    return TOOL_CLASSES[adapter](name, path, args)


# ---------------------------------------------------------------------------------------
# Summary


def pct(a, b):
    return f"{100 * a / b:.1f}%" if b else "-"


def quantile(xs, q):
    if not xs:
        return float("nan")
    xs = sorted(xs)
    k = (len(xs) - 1) * q
    lo, hi = math.floor(k), math.ceil(k)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


T975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
        12: 2.179, 15: 2.131, 20: 2.086, 25: 2.060, 30: 2.042, 40: 2.021, 60: 2.000, 120: 1.980}


def t975(df):
    """Student's t, two-sided 95%, for df degrees of freedom (the next smaller tabulated df)."""
    if df >= 1000:
        return 1.960
    return T975[max(k for k in T975 if k <= max(df, 1))]


def fmt_s(x):
    if math.isnan(x):
        return "-"
    return f"{x * 1000:.0f} ms" if x < 0.1 else f"{x:.2f} s"


def summarize(rows, cases, names, adapters=None):
    """rows: dicts with tool, id, repeat, status, verdict, seconds. Returns markdown.

    Every tool is reported on the cases it ran (the ones tagged comparable on it). For Ciphey,
    cases tagged as expected failures (decoders and detection it doesn't have yet) are also
    counted on their own, so new decoders show up as gains."""
    adapters = adapters or {}
    by_id = {c.id: c for c in cases}
    lines = []
    first = {}
    for r in rows:
        first.setdefault((r["tool"], r["id"]), r)
    for name in names:
        mine = [r for (t, _), r in first.items() if t == name]
        if not mine:
            continue
        is_ciphey = adapters.get(name, "ciphey") == "ciphey"
        lines.append(f"### {name}\n")
        head = "| category | cases | correct | wrong | nothing |" + (" expected failures (passing) | correct without them |" if is_ciphey else "")
        lines.append(head)
        lines.append("|---|---:|---:|---:|---:|" + ("---:|---:|" if is_ciphey else ""))
        tot = {"n": 0, "c": 0, "w": 0, "z": 0, "xn": 0, "xp": 0}
        for cat in CATEGORIES:
            rs = [r for r in mine if by_id[r["id"]].category == cat]
            if not rs:
                continue
            n = len(rs)
            c = sum(r["verdict"] == "correct" for r in rs)
            w = sum(r["verdict"] == "wrong" for r in rs)
            z = sum(r["verdict"] == "nothing" for r in rs)
            xf = [r for r in rs if by_id[r["id"]].xfail]
            xp = sum(r["verdict"] == "correct" for r in xf)
            for k, v in (("n", n), ("c", c), ("w", w), ("z", z), ("xn", len(xf)), ("xp", xp)):
                tot[k] += v
            row = f"| {cat} | {n} | {c} ({pct(c, n)}) | {w} | {z} |"
            if is_ciphey:
                row += f" {f'{len(xf)} ({xp})' if xf else '-'} | {c - xp}/{n - len(xf)} ({pct(c - xp, n - len(xf))}) |"
            lines.append(row)
        row = f"| **all** | {tot['n']} | **{tot['c']} ({pct(tot['c'], tot['n'])})** | {tot['w']} | {tot['z']} |"
        if is_ciphey:
            row += f" {tot['xn']} ({tot['xp']}) | **{tot['c'] - tot['xp']}/{tot['n'] - tot['xn']} ({pct(tot['c'] - tot['xp'], tot['n'] - tot['xn'])})** |"
        lines.append(row)
        secs = [r["seconds"] for r in mine]
        solved = [r["seconds"] for r in mine if r["verdict"] == "correct" and by_id[r["id"]].expected != "-"]
        none = [r for r in mine if by_id[r["id"]].expected == "-"]
        giveup = [r["seconds"] for r in none if r["verdict"] == "correct"]
        lines.append("")
        lines.append(f"Time per case, all {len(secs)} cases: median {fmt_s(quantile(secs, 0.5))}, p90 {fmt_s(quantile(secs, 0.9))}, "
                     f"p99 {fmt_s(quantile(secs, 0.99))}, total {sum(secs):.0f} s. Correct answers ({len(solved)}): median "
                     f"{fmt_s(quantile(solved, 0.5))}, p90 {fmt_s(quantile(solved, 0.9))}.")
        if none:
            fp = sum(r["verdict"] == "wrong" for r in none)
            lines.append(f"No-answer inputs ({len(none)}): {fp} false positives ({pct(fp, len(none))}); time to give up: median "
                         f"{fmt_s(quantile(giveup, 0.5))}, p90 {fmt_s(quantile(giveup, 0.9))}, max {fmt_s(max(giveup) if giveup else float('nan'))}.")
        alts = [r for r in mine if r.get("alternatives_correct") in ("True", "False")]
        if alts:
            hit = sum(r["alternatives_correct"] == "True" for r in alts)
            lines.append(f"The answer is among Magic's first 5 suggestions in {hit} of {len(alts)} cases with an answer "
                         f"({sum(r['verdict'] == 'correct' for r in alts)} as the first).")
        lines.append("")
    # One table, a column per tool
    present = [n for n in names if any(t == n for (t, _) in first)]
    if len(present) > 1:
        lines.append("### All tools: correct / cases each tool ran\n")
        lines.append("| category | " + " | ".join(present) + " |")
        lines.append("|---|" + "---:|" * len(present))
        for cat in CATEGORIES + ["all"]:
            cells = []
            for n in present:
                rs = [r for (t, i), r in first.items() if t == n and (cat == "all" or by_id[i].category == cat)]
                c = sum(r["verdict"] == "correct" for r in rs)
                cells.append(f"{c}/{len(rs)} ({pct(c, len(rs))})" if rs else "-")
            lines.append(f"| {'**all**' if cat == 'all' else cat} | " + " | ".join(cells) + " |")
        cells = []
        for n in present:
            ts = [r["seconds"] for (t, _), r in first.items() if t == n]
            cells.append(f"{fmt_s(quantile(ts, 0.5))} / {fmt_s(quantile(ts, 0.9))} / {fmt_s(quantile(ts, 0.99))}")
        lines.append("| time median / p90 / p99 | " + " | ".join(cells) + " |")
        lines.append("")
    # Head to head on the cases every tool ran
    present = [n for n in names if any(t == n for (t, _) in first)]
    if len(present) > 1:
        common = sorted(set.intersection(*[{i for (t, i) in first if t == n} for n in present]))
        answer_ids = [i for i in common if by_id[i].expected != "-"]
        none_ids = [i for i in common if by_id[i].expected == "-"]
        if common:
            lines.append(f"### Head to head on the {len(common)} cases every tool ran\n")
            lines.append(f"| tool | correct of {len(answer_ids)} with an answer | wrong | nothing | false positives of {len(none_ids)} "
                         "without one | median time | p90 time |")
            lines.append("|---|---:|---:|---:|---:|---:|---:|")
            for n in present:
                rs = [first[(n, i)] for i in answer_ids]
                rn = [first[(n, i)] for i in none_ids]
                c = sum(r["verdict"] == "correct" for r in rs)
                fp = sum(r["verdict"] == "wrong" for r in rn)
                ts = [first[(n, i)]["seconds"] for i in common]
                lines.append(f"| {n} | {c} ({pct(c, len(rs))}) | {sum(r['verdict'] == 'wrong' for r in rs)} | "
                             f"{sum(r['verdict'] == 'nothing' for r in rs)} | {fp} ({pct(fp, len(rn))}) | "
                             f"{fmt_s(quantile(ts, 0.5))} | {fmt_s(quantile(ts, 0.9))} |")
            lines.append("")
    # Repeats that disagree
    flaky = {}
    for r in rows:
        flaky.setdefault((r["tool"], r["id"]), set()).add(r["verdict"])
    unstable = sorted(k for k, v in flaky.items() if len(v) > 1)
    if any(r["repeat"] > 1 for r in rows):
        lines.append(f"Repeats: {len(unstable)} cases whose verdict changed between repeats" + (": " + ", ".join(f"{t}/{i}" for t, i in unstable) if unstable else "."))
        lines.append("")
    return "\n".join(lines)


def ab_report(rows, cases, a, b):
    by_id = {c.id: c for c in cases}
    first = {}
    for r in rows:
        first.setdefault((r["tool"], r["id"]), r)
    ids = [c.id for c in cases if (a, c.id) in first and (b, c.id) in first]
    lines = [f"### A/B: A = {a}, B = {b}, {len(ids)} cases\n"]
    changed = [(i, first[(a, i)]["verdict"], first[(b, i)]["verdict"]) for i in ids if first[(a, i)]["verdict"] != first[(b, i)]["verdict"]]
    ca = sum(first[(a, i)]["verdict"] == "correct" for i in ids)
    cb = sum(first[(b, i)]["verdict"] == "correct" for i in ids)
    lines.append(f"Correct: A {ca}/{len(ids)}, B {cb}/{len(ids)}. Verdicts that changed: {len(changed)}.")
    for i, va, vb in changed:
        ra, rb = first[(a, i)], first[(b, i)]
        lines.append(f"- `{i}` ({by_id[i].category}{', xfail ' + by_id[i].xfail if by_id[i].xfail else ''}): {va} → {vb}"
                     f" (A {ra['seconds']:.2f} s via {ra['path'] or '-'}; B {rb['seconds']:.2f} s via {rb['path'] or '-'})")
    # Paired time ratio over all cases, and over the cases both solved
    def ratio(sel):
        pairs = [(first[(a, i)]["seconds"], first[(b, i)]["seconds"]) for i in sel]
        pairs = [(x, y) for x, y in pairs if x > 0 and y > 0]
        if not pairs:
            return "-"
        logs = [math.log(y / x) for x, y in pairs]
        mean = statistics.mean(logs)
        half = t975(len(logs) - 1) * statistics.stdev(logs) / math.sqrt(len(logs)) if len(logs) > 1 else float("inf")
        return f"{math.exp(mean):.3f} (95% CI {math.exp(mean - half):.3f} to {math.exp(mean + half):.3f}, {len(pairs)} cases)"
    both = [i for i in ids if first[(a, i)]["verdict"] == "correct" == first[(b, i)]["verdict"] and by_id[i].expected != "-"]
    ta = [first[(a, i)]["seconds"] for i in ids]
    tb = [first[(b, i)]["seconds"] for i in ids]
    lines.append("")
    lines.append(f"Time B/A, geometric mean of per-case ratios: all cases {ratio(ids)}; cases both solved {ratio(both)}.")
    lines.append(f"Median time: A {fmt_s(quantile(ta, 0.5))}, B {fmt_s(quantile(tb, 0.5))}; total A {sum(ta):.1f} s, B {sum(tb):.1f} s.")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------


def select_cases(cases, subset=None, categories=None, ids=None):
    """The cases of a subset, of some categories, and whose id contains `ids` or matches it as a glob."""
    sel = cases
    if subset:
        sel = [c for c in sel if subset in c.subset]
    if categories:
        sel = [c for c in sel if c.category in categories]
    if ids:
        sel = [c for c in sel if ids in c.id or fnmatch.fnmatchcase(c.id, ids)]
    return sel


def run_order(tools, k):
    """A/B: A first on even cases, B first on odd ones."""
    return tools if k % 2 == 0 else tools[::-1]


def check_failures(rows, cases, names):
    """The cases `--check` fails on: with one tool, those it didn't get right that aren't
    expected failures; with two (A/B), those A got right and B didn't."""
    by_id = {c.id: c for c in cases}
    first = {}
    for r in rows:
        first.setdefault((r["tool"], r["id"]), r)
    if len(names) == 1:
        return [i for (t, i), r in first.items() if r["verdict"] != "correct" and not by_id[i].xfail]
    a, b = names
    return [i for (t, i), r in first.items() if t == a and r["verdict"] == "correct" and (b, i) in first
            and first[(b, i)]["verdict"] != "correct"]


def process_selftest():
    """Fake binaries: a ciphey that ignores -c is killed after the timeout with its whole process
    group, and the Python Ciphey adapter gets the input on stdin. POSIX only, like the runner."""
    import argparse

    failures = []
    tmp = tempfile.mkdtemp(prefix="ciphey-e2e-selftest-")
    try:
        args = argparse.Namespace(timeout=1, threads=1, depth=3, node="node")
        pidfile = os.path.join(tmp, "child.pid")
        hang = os.path.join(tmp, "hang")
        with open(hang, "w", encoding="utf-8") as fh:
            fh.write(f"#!/bin/sh\nsleep 60 &\necho $! > {pidfile}\nsleep 60\n")
        echo = os.path.join(tmp, "python")
        with open(echo, "w", encoding="utf-8") as fh:
            fh.write('#!/bin/sh\nread -r line\nprintf \'{"status": "answer", "plaintext": "%s", "path": []}\\n\' "$line"\n')
        os.chmod(hang, 0o700)  # owner only
        os.chmod(echo, 0o700)
        text = "stdin works"
        c = Case(["p", "encoding", "", "ciphey,python-ciphey", "", "exact", "", "-", text, text])
        tool = CipheyTool("hang", hang, args)
        status, _, _, secs = tool.run(c)
        tool.close()
        if status != "timeout" or not 1.5 < secs < 3.0:  # --timeout 1: killed at 2 s, as the doc says (timeout + 1 s)
            failures.append(f"a hanging ciphey: {status} after {secs:.1f} s, want timeout after 2 s")
        try:
            with open(pidfile, encoding="utf-8") as fh:
                child = int(fh.read())
        except (FileNotFoundError, ValueError):
            child = None
        if child is not None:
            time.sleep(0.2)
            # gone, or a zombie that nothing has reaped yet (PID 1 in a container may not be an init)
            state = subprocess.run(["ps", "-o", "stat=", "-p", str(child)], capture_output=True, text=True).stdout.strip()
            if state and not state.startswith("Z"):
                failures.append("a hanging ciphey's child process survived the kill")
                os.kill(child, signal.SIGKILL)
        tool = PythonCipheyTool("echo", echo, args)
        status, answer, _, _ = tool.run(c)
        tool.close()
        if (status, answer) != ("answer", text):
            failures.append(f"the Python Ciphey adapter didn't get the input on stdin: {status} {answer!r}")
        failures += main_selftest(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return failures


def main_selftest(tmp):
    """main() end to end, with fake ciphey binaries: the selection, the A/B wiring and --check's
    exit codes (exit 2 for a selection with no case)."""
    failures = []
    good = os.path.join(tmp, "good")  # decodes Base64, like a working ciphey
    with open(good, "w", encoding="utf-8") as fh:
        fh.write('#!/bin/sh\nfor a; do last="$a"; done\n'
                 'printf "The plaintext is:\\n%s\\nthe decoder used is Base64\\n" "$(printf %s "${last#--text=}" | base64 -d)"\n')
    bad = os.path.join(tmp, "bad")  # always gives up
    with open(bad, "w", encoding="utf-8") as fh:
        fh.write('#!/bin/sh\necho "ciphey has failed to decode the text."\n')
    order_log = os.path.join(tmp, "order.log")
    named = {}
    for name in ("first", "second"):  # log the order they run in, and give up
        named[name] = os.path.join(tmp, name)
        with open(named[name], "w", encoding="utf-8") as fh:
            fh.write(f'#!/bin/sh\necho {name} >> {order_log}\necho "ciphey has failed to decode the text."\n')
    for path in (good, bad, *named.values()):
        os.chmod(path, 0o700)
    me = [sys.executable, os.path.abspath(__file__)]
    subprocess.run(me + ["--ids", "enc.base64", named["first"], named["second"]], capture_output=True, timeout=120)
    with open(order_log, encoding="utf-8") as fh:
        order = fh.read().split()
    if order != ["first", "second", "second", "first", "first", "second", "second", "first"]:
        failures.append(f"run.py A B ran in the order {order}, want A B, B A, ...")
    category = subprocess.run(me + ["--category", "encodings", good], capture_output=True, text=True, timeout=120)
    if category.returncode != 2 or "invalid choice" not in category.stderr:
        failures.append(f"--category encodings: exit {category.returncode}, {category.stderr.strip()[-80:]!r}")
    probes = [
        (["--ids", "enc.base64.1", "--check", good], 0),
        (["--ids", "enc.base64.1", "--check", bad], 1),
        (["--ids", "enc.base64.1", "--check", good, bad], 1),  # B lost a case
        (["--ids", "enc.base64.1", "--check", bad, good], 0),  # B gained one
        (["--ids", "no-such-case", good], 2),
        (["--repeat", "0", "--ids", "enc.base64.1", good], 2),
        (["--category", "hash", "--check", "python-ciphey:" + good], 1),  # nothing ran
    ]
    for argv, want in probes:
        rc = subprocess.run(me + argv, capture_output=True, text=True, timeout=120).returncode
        if rc != want:
            failures.append(f"run.py {' '.join(argv)} exited {rc}, want {want}")
    return failures


def selftest():
    """Canned outputs of master, 0.12.0, Python Ciphey and CyberChef through the parsers and the
    verdict rules (`--selftest`, run by CI before the smoke run), plus the summary, the A/B
    report and the process handling, with fake binaries. Needs no ciphey binary."""
    import argparse

    green, gold, reset = "\x1b[0m\x1b[1m\x1b[38;2;0;255;0m", "\x1b[0m\x1b[1m\x1b[38;2;255;215;0m", "\x1b[0m"
    fail = "\x1b[0m\x1b[1m\x1b[38;2;255;0;0m⛔️ ciphey has failed to decode the text.\nIf you want more help, ask.\x1b[0m\n"
    ciphey = [
        # (stdout, stderr, exit code, expected (status, answer, path))
        (f"\n🥳 ciphey has decoded 122 times.\n\nThe plaintext is:\n{green}Hello, World!{reset}\nthe decoder used is {gold}Base64{reset}\n",
         "", 0, ("answer", "Hello, World!", "Base64")),
        (f"\nThe plaintext is:\n{green}Ciphey is very fast{reset}\nthe decoders used are {gold}Base64 → Hexadecimal → caesar{reset}\n",
         "", 0, ("answer", "Ciphey is very fast", "Base64 → Hexadecimal → caesar")),
        (f"{green}Your input text is the plaintext 🥳{reset}\nThe plaintext is:\n{green}Hi there{reset}\nthe decoder used is {gold}Default decoder{reset}\n",
         "", 0, ("answer", "Hi there", "Default decoder")),
        ("\n🥳 ciphey has decoded 64 times.\n\nThe plaintext is:\nHello\nthe decoder used is Base64\n", "", 0,
         ("answer", "Hello", "Base64")),  # 0.12.0: no colours
        ("The plaintext is:\nline 1\nthe decoder used is a trick\nline 3\nthe decoders used are A → B\n", "", 0,
         ("answer", "line 1\nthe decoder used is a trick\nline 3", "A → B")),  # the last marker counts
        (fail, "Timed out after 5s, try a longer --cracking-timeout\n", 0, ("timeout", None, "")),
        (fail, "", 0, ("none", None, "")),
        ("", "thread 'main' panicked at src/main.rs:1:\n", 101, ("error", None, "exit 101: thread 'main' panicked at src/main.rs:1:")),
        ("", "", 0, ("error", None, "no answer and no failure message: ")),
        ("garbage", "", 0, ("error", None, "no answer and no failure message: garbage")),
        ("The plaintext is:\nhalf", "", None, ("timeout", None, "")),  # killed
    ]
    python = [
        ('{"status": "answer", "plaintext": "hello", "path": ["base64", "utf8"]}\n', "", 0, ("answer", "hello", "base64 → utf8")),
        ('{"status": "none"}\n{"status": "answer", "plaintext": "last", "path": []}\n', "", 0, ("answer", "last", "")),
        ('{"status": "none"}\n', "", 0, ("none", None, "")),
        ("", "Traceback ...", 1, ("error", None, "exit 1: Traceback ...")),
        ("", "", None, ("timeout", None, "")),
    ]
    b64op = "From Base64"
    magic = [
        ({"results": [{"recipe": [b64op], "output": "first"}, {"recipe": ["From Hex"], "output": "second"}]},
         ("answer", "first", b64op)),  # Magic's first suggestion is its answer
        ({"results": []}, ("none", "INPUT", "")),
        ({"results": [{"recipe": [], "output": "INPUT"}]}, ("none", "INPUT", "")),
        ({"results": [{"recipe": [b64op], "output": "hello"}]}, ("answer", "hello", b64op)),
        ({"results": [{"recipe": ["Gunzip"], "output": None}]}, ("error", None, "recipe failed: Gunzip")),
    ]

    def case(category, inp, expected, match="exact"):
        return Case(["t", category, "", "ciphey", "", match, "", "-", inp, expected])

    verdicts = [
        # (case, status, answer, verdict)
        (case("no_answer", "x1y2", "-", "none"), "answer", "junk", "wrong"),
        (case("no_answer", "x1y2", "-", "none"), "answer", "x1y2", "wrong"),  # "Your input text is the plaintext"
        (case("no_answer", "x1y2", "-", "none"), "none", None, "correct"),
        (case("no_answer", "x1y2", "-", "none"), "timeout", None, "correct"),
        (case("no_answer", "x1y2", "-", "none"), "error", None, "nothing"),
        (case("no_answer", "x1y2", "-", "none"), "none", "x1y2", "correct"),  # CyberChef suggesting nothing
        (case("plaintext", "Hi there", "Hi there"), "answer", "Hi there", "correct"),
        (case("plaintext", "Hi there", "Hi there"), "none", "Hi there", "correct"),  # CyberChef
        (case("plaintext", "Hi there", "Hi there"), "none", None, "nothing"),
        (case("encoding", "SGk=", "Hi there"), "none", "SGk=", "nothing"),
        (case("encoding", "SGk=", "Hi there"), "answer", "Hi there \n", "correct"),
        (case("encoding", "SGk=", "Hi there"), "answer", "hi there", "wrong"),
        (case("encoding", "x", "HELLO WORLD", "fold"), "answer", "hello   world", "correct"),
        (case("encoding", "x", "HELLO WORLD", "fold"), "answer", "helloworld", "wrong"),
        (case("encoding", "x", "HELLO WORLD", "letters"), "answer", "helloworld", "correct"),
        (case("encoding", "x", "HELLO WORLD", "letters"), "answer", "hello wor1d", "wrong"),
        (case("encoding", "x", '{"a":1,"b":[2]}', "json"), "answer", '{\n  "b": [2],\n  "a": 1\n}', "correct"),
        (case("encoding", "x", '{"a":1}', "json"), "answer", '{"a":2}', "wrong"),
        (case("encoding", "x", "Hi"), "timeout", None, "nothing"),
    ]
    xf = Case(["x", "encoding", "", "ciphey", "#1", "exact", "", "-", "i", "e"])
    ok = Case(["o", "encoding", "", "ciphey", "", "exact", "", "-", "i", "e"])

    def row(tool, cid, v):
        return {"tool": tool, "id": cid, "verdict": v}

    checks = [
        # (rows, names, failing ids)
        ([row("A", "o", "correct"), row("A", "x", "nothing")], ["A"], []),  # an expected failure doesn't fail
        ([row("A", "o", "wrong"), row("A", "x", "nothing")], ["A"], ["o"]),
        ([row("A", "o", "correct"), row("B", "o", "nothing")], ["A", "B"], ["o"]),  # B lost a case
        ([row("A", "o", "nothing"), row("B", "o", "correct")], ["A", "B"], []),  # B gained one
        ([row("A", "x", "correct"), row("B", "x", "wrong")], ["A", "B"], ["x"]),
    ]
    failures = []
    for rows, names, want in checks:
        got = check_failures(rows, [xf, ok], names)
        if got != want:
            failures.append(f"check_failures({rows}, {names}) = {got}, want {want}")
    for out, err, rc, want in ciphey:
        got = parse_ciphey(out, err, rc)
        if got != want:
            failures.append(f"parse_ciphey({out[:40]!r}, rc={rc}) = {got}, want {want}")
    for out, err, rc, want in python:
        got = parse_python_ciphey(out, err, rc)
        if got != want:
            failures.append(f"parse_python_ciphey({out[:40]!r}, rc={rc}) = {got}, want {want}")
    for reply, want in magic:
        got = magic_answer(reply, "INPUT")
        if got != want:
            failures.append(f"magic_answer({reply}) = {got}, want {want}")
    for c, status, answer, want in verdicts:
        got = verdict(c, status, answer)
        if got != want:
            failures.append(f"verdict({c.category}, {c.match}, {status}, {answer!r}) = {got}, want {want}")
    # t, the A/B report and the summary on canned rows
    for df, want in ((1, 12.706), (2, 4.303), (30, 2.042), (75, 2.000), (5000, 1.960)):
        if t975(df) != want:
            failures.append(f"t975({df}) = {t975(df)}, want {want}")
    ab_cases = [Case([f"c{i}", "encoding", "", "ciphey", "", "exact", "", "-", "i", "e"]) for i in range(3)]
    ab_rows = [{"tool": t, "id": f"c{i}", "verdict": "correct", "seconds": sec * (2 if t == "B" else 1), "path": ""}
               for i, sec in enumerate((1.0, 2.0, 4.0)) for t in ("A", "B")]
    report = ab_report(ab_rows, ab_cases, "A", "B")
    if "all cases 2.000 (95% CI 2.000 to 2.000, 3 cases)" not in report:  # B twice as slow is 2, not 0.5
        failures.append("ab_report: B taking twice as long isn't a ratio of 2.000: " + report.replace("\n", " ")[:300])
    # unequal ratios: the interval's t, n and spread, and "cases both solved" (worked out by hand)
    ab_cases = [Case([f"d{i}", "encoding", "", "ciphey", "", "exact", "", "-", "i", "e"]) for i in range(4)]
    ab_rows = [{"tool": "A", "id": f"d{i}", "verdict": "correct", "seconds": 1.0, "path": ""} for i in range(4)]
    ab_rows += [{"tool": "B", "id": f"d{i}", "verdict": v, "seconds": sec, "path": ""}
                for i, (sec, v) in enumerate(((1.0, "correct"), (2.0, "correct"), (8.0, "correct"), (4.0, "nothing")))]
    report = ab_report(ab_rows, ab_cases, "A", "B")
    want = "all cases 2.828 (95% CI 0.681 to 11.745, 4 cases); cases both solved 2.520 (95% CI 0.182 to 34.974, 3 cases)"
    if want not in report:
        failures.append(f"ab_report: want {want!r} in " + report.replace("\n", " ")[:400])
    sum_cases = [Case([f"n{k}", "no_answer", "", "ciphey", "", "none", "", "-", f"in{k}", "-"]) for k in range(3)]
    sum_cases.append(Case(["x1", "language", "base64", "ciphey", "gon6", "exact", "", "-", "c", "d"]))
    sum_rows = [{"tool": "T", "id": i, "verdict": v, "seconds": 1.0, "repeat": 1, "path": ""}
                for i, v in (("n0", "wrong"), ("n1", "wrong"), ("n2", "correct"), ("x1", "correct"))]
    text = summarize(sum_rows, sum_cases, ["T"], {"T": "ciphey"})
    for want in ("No-answer inputs (3): 2 false positives (66.7%)", "| no_answer | 3 | 1 (33.3%) | 2 | 0 | - | 1/3 (33.3%) |",
                 "| language | 1 | 1 (100.0%) | 0 | 0 | 1 (1) | 0/0 (-) |",
                 "| **all** | 4 | **2 (50.0%)** | 2 | 0 | 1 (1) | **1/3 (33.3%)** |"):
        if want not in text:
            failures.append(f"summarize: no {want!r} in " + text.replace("\n", " ")[:300])
    picked = [c.id for c in select_cases([Case([i, cat, "", "ciphey", "", "exact", sub, "-", "i", "e"]) for i, cat, sub in
                                          (("chain5.01", "chain", "quick"), ("chain4.01", "chain", ""), ("enc.base64.1", "encoding", "quick"))],
                                         ids="chain5.*")]
    if picked != ["chain5.01"]:
        failures.append(f"--ids chain5.* picked {picked}")
    picked = [c.id for c in select_cases([Case([i, "encoding", "", "ciphey", "", "exact", "", "-", "i", "e"]) for i in
                                          ("enc.base45.1", "enc.base64.1")], ids="base45")]
    if picked != ["enc.base45.1"]:
        failures.append(f"--ids base45 picked {picked}")
    picked = [c.id for c in select_cases([Case([i, cat, "", "ciphey", "", "exact", sub, "-", "i", "e"]) for i, cat, sub in
                                          (("chain5.01", "chain", "quick"), ("enc.base64.1", "encoding", "quick"),
                                           ("enc.hex.1", "encoding", ""))], subset="quick", categories=["encoding"])]
    if picked != ["enc.base64.1"]:
        failures.append(f"--subset quick --category encoding picked {picked}")
    if [run_order(["A", "B"], k) for k in range(3)] != [["A", "B"], ["B", "A"], ["A", "B"]]:
        failures.append("the A/B order doesn't alternate")

    class DeadChef:  # a CyberChef worker that has died
        proc = None

        def start(self):
            raise CyberChefError("CyberChef worker exited")

        def close(self):
            """Nothing to stop: it never started."""

    chef_tool = CyberChefTool.__new__(CyberChefTool)
    chef_tool.chef, chef_tool.intensive = DeadChef(), False
    chef_tool.args = argparse.Namespace(timeout=1, depth=3)
    if chef_tool.run(sum_cases[0])[0] != "error":
        failures.append("a dead CyberChef worker isn't an error for its case")
    h2h_cases = [Case([i, cat, "", "ciphey", "", "exact", "", "-", "i", e]) for i, cat, e in
                 (("n0", "no_answer", "-"), ("n1", "no_answer", "-"), ("a1", "encoding", "e"))]
    h2h_rows = [{"tool": t, "id": i, "verdict": v, "seconds": 1.0, "repeat": 1, "path": ""} for t, i, v in
                (("T", "n0", "wrong"), ("T", "n1", "correct"), ("T", "a1", "wrong"),
                 ("U", "n0", "correct"), ("U", "n1", "correct"), ("U", "a1", "nothing"))]
    text = summarize(h2h_rows, h2h_cases, ["T", "U"], {"T": "ciphey", "U": "ciphey"})
    for want in ("| T | 0 (0.0%) | 1 | 0 | 1 (50.0%) |", "| U | 0 (0.0%) | 0 | 1 | 0 (0.0%) |"):
        if want not in text:
            failures.append(f"summarize head to head: no {want!r} in " + text.replace("\n", " ")[-400:])
    failures += process_selftest()
    for f in failures:
        print("SELFTEST FAILED: " + f)
    n = len(checks) + len(ciphey) + len(python) + len(magic) + len(verdicts) + 5 + 2 + 4 + 2 + 5 + 3 + 9
    print(f"SELFTEST {'FAILED' if failures else 'OK'} ({n - len(failures)} of {n} checks)")
    return 1 if failures else 0


def uptime():
    try:
        return subprocess.run(["uptime"], capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return " ".join(f"{x:.2f}" for x in os.getloadavg())


RESULT_COLUMNS = ["tool", "adapter", "id", "category", "repeat", "status", "verdict", "seconds", "path", "output", "alternatives_correct"]


def esc(s):
    return (s or "").replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


def saved_results():
    """The results files that --summarize reads: every results.tsv under target/e2e and the
    baselines in benches/data/e2e, by absolute path and by path from the repository root."""
    found = {}
    for top in (os.path.join(ROOT, "target", "e2e"), os.path.join(ROOT, "benches", "data", "e2e")):
        for dirpath, _, files in os.walk(top):
            for name in files:
                if name == "results.tsv" or name.startswith("baseline-"):
                    full = os.path.join(dirpath, name)
                    found[full] = full
                    found[os.path.relpath(full, ROOT)] = full
    return found


def read_results(paths):
    rows = []
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            header = fh.readline().rstrip("\n").split("\t")
            for line in fh:
                r = dict(zip(header, line.rstrip("\n").split("\t")))
                r["repeat"] = int(r["repeat"])
                r["seconds"] = float(r["seconds"])
                r["path"] = unesc(r["path"])
                r.setdefault("adapter", r["tool"] if r["tool"] in ADAPTERS else "ciphey")
                rows.append(r)
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tools", nargs="*", help="[name=][adapter:]path, adapter one of " + ", ".join(ADAPTERS))
    ap.add_argument("--corpus", default="corpus-v1.tsv", choices=sorted(corpora()), help="a corpus in benches/data/e2e")
    ap.add_argument("--subset", choices=["quick", "smoke"], help="only the cases of this subset")
    ap.add_argument("--category", action="append", choices=CATEGORIES, help="only these categories (repeatable)")
    ap.add_argument("--ids", help="only cases whose id contains this text, or matches it as a glob (chain5.*)")
    ap.add_argument("--timeout", type=int, default=5, help="seconds per case (Ciphey's -c), default 5")
    ap.add_argument("--threads", type=int, default=4, help="RAYON_NUM_THREADS for Ciphey, default 4")
    ap.add_argument("--depth", type=int, default=3, help="CyberChef Magic depth, default 3 (Magic's default)")
    ap.add_argument("--repeat", type=int, default=1, help="run every case this many times")
    ap.add_argument("--node", default=os.environ.get("NODE", "node"), help="the node binary for CyberChef (default $NODE or node)")
    ap.add_argument("--all-cases", action="store_true", help="also run cases not tagged as comparable on the tool")
    ap.add_argument("--summarize", nargs="+", metavar="RESULTS_TSV",
                    help="summarize saved runs instead: results.tsv files under target/e2e, or benches/data/e2e/baseline-*.tsv")
    ap.add_argument("--selftest", action="store_true", help="check the output parsers and verdict rules, no binary needed")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if a case that isn't an expected failure isn't correct (one tool), or if a case "
                         "A got right isn't right for B (A/B)")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())
    corpus_path = corpora()[args.corpus]
    cases, corpus_sha = load_corpus(corpus_path)
    if args.summarize:
        known_files = saved_results()
        here = os.getcwd()
        files = []
        for p in args.summarize:
            key = p if os.path.isabs(p) else os.path.relpath(os.path.join(here, p), ROOT)
            if key not in known_files:
                ap.error(f"{p}: --summarize reads results.tsv files under target/e2e and benches/data/e2e/baseline-*.tsv")
            files.append(known_files[key])
        rows = read_results(files)
        known = {c.id for c in cases}
        unknown = sorted({r["id"] for r in rows} - known)
        if unknown:
            print(f"skipping {len(unknown)} ids that aren't in {args.corpus}: {', '.join(unknown[:5])} ...", file=sys.stderr)
            rows = [r for r in rows if r["id"] in known]
        names = list(dict.fromkeys(r["tool"] for r in rows))
        print(summarize(rows, cases, names, {r["tool"]: r["adapter"] for r in rows}))
        if len(names) == 2:
            print(ab_report(rows, cases, *names))
        return
    if not 1 <= len(args.tools) <= 2:
        ap.error("give one tool, or two for an A/B run")
    if args.repeat < 1:
        ap.error("--repeat must be at least 1")
    sel = select_cases(cases, args.subset, args.category, args.ids)
    if not sel:
        ap.error("no case matches the selection (--subset, --category, --ids)")
    tools = [make_tool(spec, args, i) for i, spec in enumerate(args.tools)]
    if len(tools) == 2 and tools[0].name == tools[1].name:
        tools[0].name, tools[1].name = tools[0].name + "-A", tools[1].name + "-B"
    names = [t.name for t in tools]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = os.path.join(ROOT, "target", "e2e", stamp)
    n = 1
    while os.path.exists(out_dir):
        n += 1
        out_dir = os.path.join(ROOT, "target", "e2e", f"{stamp}-{n}")
    os.makedirs(out_dir)
    meta = {
        "started_utc": stamp, "corpus": os.path.relpath(corpus_path, ROOT), "corpus_sha256": corpus_sha,
        "cases_selected": len(sel), "timeout_s": args.timeout, "kill_after_s": args.timeout + GRACE,
        "rayon_threads": args.threads, "repeat": args.repeat, "subset": args.subset, "category": args.category, "ids": args.ids,
        "host": f"{platform.node()}, {platform.machine()}, {os.cpu_count()} logical CPUs, {platform.system()} {platform.release()}",
        "uptime_start": uptime(), "tools": {t.name: t.info() for t in tools},
    }
    print(f"uptime before: {meta['uptime_start']}", flush=True)
    print(f"{len(sel)} cases, timeout {args.timeout} s, RAYON_NUM_THREADS={args.threads}, tools: {', '.join(names)}", flush=True)
    rows = []
    results = open(os.path.join(out_dir, "results.tsv"), "w", encoding="utf-8")
    results.write("\t".join(RESULT_COLUMNS) + "\n")
    try:
        k = 0
        for rep in range(1, args.repeat + 1):
            for case in sel:
                order = run_order(tools, k)
                k += 1
                for tool in order:
                    if not args.all_cases and not tool.comparable(case):
                        continue
                    status, output, path, secs = tool.run(case)
                    v = verdict(case, status, output)
                    alt = ""
                    if isinstance(tool, CyberChefTool) and case.expected != "-":
                        alt = str(v == "correct" or any(o is not None and normalize(o, case.match) == normalize(case.expected, case.match)
                                                        for o in getattr(tool, "last_alternatives", [])))
                    row = {"tool": tool.name, "adapter": tool.adapter, "id": case.id, "category": case.category, "repeat": rep, "status": status,
                           "verdict": v, "seconds": secs, "path": path or "", "output": output, "alternatives_correct": alt}
                    rows.append(row)
                    results.write("\t".join([tool.name, tool.adapter, case.id, case.category, str(rep), status, v, f"{secs:.3f}", esc(path),
                                             esc((output or "")[:300]), alt]) + "\n")
                    results.flush()
                    mark = {"correct": ".", "wrong": "W", "nothing": "-"}[v]
                    print(f"{mark} {tool.name:>18} {secs:6.2f}s {case.id}" + (f"  [{status}] {(output or '')[:60]!r}" if v != "correct" else ""), flush=True)
    finally:
        results.close()
        for t in tools:
            t.close()
    meta["uptime_end"] = uptime()
    meta["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report = [f"# E2E benchmark: {', '.join(names)}\n",
              f"Corpus {meta['corpus']} (sha256 {corpus_sha[:12]}), {len(sel)} cases, timeout {args.timeout} s, "
              f"RAYON_NUM_THREADS={args.threads}, repeat {args.repeat}.\n",
              f"Host: {meta['host']}.\n", f"uptime before: `{meta['uptime_start']}`\n", f"uptime after: `{meta['uptime_end']}`\n",
              summarize(rows, cases, names, {t.name: t.adapter for t in tools})]
    if len(tools) == 2:
        report.append(ab_report(rows, cases, *names))
    text = "\n".join(report)
    with open(os.path.join(out_dir, "summary.md"), "w", encoding="utf-8") as fh:
        fh.write(text + "\n")
    with open(os.path.join(out_dir, "meta.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=1)
        fh.write("\n")
    print()
    print(text)
    print(f"uptime after: {meta['uptime_end']}")
    print(f"wrote {out_dir}/results.tsv, summary.md, meta.json")
    if args.check:
        failed = check_failures(rows, sel, names)
        if not rows:
            print("CHECK FAILED: no case ran (none of the selected cases is comparable on the tool)")
            sys.exit(1)
        if failed:
            print("CHECK FAILED: " + ", ".join(failed))
            sys.exit(1)
        print("CHECK OK")


if __name__ == "__main__":
    main()
