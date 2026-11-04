"""Client for cyberchef.mjs, a long-lived Node process that runs CyberChef's Node API.

Used by run.py (the `cyberchef` tool: Magic) and corpus.py (CyberChef's encoders). One
process serves every case, so CyberChef's start-up (about 1.5 s to import its 500
operations) is paid once and not counted in a case's time. A request that doesn't answer
within its timeout kills the process; the next request starts a new one.
"""

import json
import os
import select
import subprocess
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.realpath(os.path.join(HERE, "..", ".."))


class CyberChefError(RuntimeError):
    pass


class CyberChef:
    def __init__(self, root, node="node"):
        """`root` is the directory that holds node_modules/cyberchef (setup.sh's .tools/node). It
        has to be inside the repository: the benchmark reads nothing outside it."""
        root = os.path.realpath(root)
        if not root.startswith(ROOT + os.sep):
            raise CyberChefError(f"{root} is outside the repository {ROOT} (setup.sh installs CyberChef in .tools/node)")
        self.root = root
        self.node = node
        self.proc = None
        self.startup_seconds = None
        self.stderr = tempfile.TemporaryFile()
        if not os.path.isdir(os.path.join(self.root, "node_modules", "cyberchef")):
            raise CyberChefError(f"no node_modules/cyberchef under {self.root} (run benches/e2e/setup.sh)")

    def version(self):
        with open(os.path.join(self.root, "node_modules", "cyberchef", "package.json"), encoding="utf-8") as fh:
            return json.load(fh)["version"]

    def start(self):
        t0 = time.perf_counter()
        self.proc = subprocess.Popen(
            [self.node, "--no-warnings", os.path.join(HERE, "cyberchef.mjs"), self.root],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        reply = self._read(180)
        if not reply or not reply.get("ready"):
            self.close()
            self.stderr.seek(0)
            raise CyberChefError("CyberChef worker didn't start: " + self.stderr.read().decode("utf-8", "replace")[-2000:])
        self.startup_seconds = time.perf_counter() - t0

    def _read(self, timeout):
        """One reply line, or None after `timeout` seconds."""
        deadline = time.monotonic() + timeout
        fd = self.proc.stdout.fileno()
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            ready, _, _ = select.select([fd], [], [], left)
            if ready:
                line = self.proc.stdout.readline()
                if not line:
                    raise CyberChefError("CyberChef worker exited")
                return json.loads(line)

    def request(self, req, timeout=600):
        """Sends one request. Returns the reply, or None on timeout (the worker is killed)."""
        if self.proc is None or self.proc.poll() is not None:
            self.start()
        self.proc.stdin.write(json.dumps(req, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()
        reply = self._read(timeout)
        if reply is None:
            self.close()
            return None
        if "error" in reply:
            raise CyberChefError(reply["error"])
        return reply

    def bake(self, text, recipe):
        return self.request({"op": "bake", "input": text, "recipe": recipe})["output"]

    def magic(self, text, depth=3, intensive=True, ext_lang=False, top=5, timeout=600):
        return self.request(
            {"op": "magic", "input": text, "depth": depth, "intensive": intensive, "extLang": ext_lang, "top": top},
            timeout,
        )

    def close(self):
        if self.proc is not None:
            try:
                self.proc.kill()
                self.proc.wait(10)
            except Exception:
                pass
            self.proc = None
