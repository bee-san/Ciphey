// CyberChef worker for benches/e2e: reads one JSON request per line on stdin and writes one
// JSON reply per line on stdout. Started by cyberchef.py (the runner's CyberChef adapter and
// corpus.py's CyberChef encoders), never by hand:
//
//   node cyberchef.mjs <dir that holds node_modules/cyberchef>
//
// Requests:
//   {"op": "magic", "input": "...", "depth": 3, "intensive": true, "extLang": false, "top": 5}
//     Runs the Magic operation (CyberChef's src/core/lib/Magic.mjs speculativeExecution, the
//     same call as the Magic operation in the web app) and bakes the recipe of the first `top`
//     suggestions on the whole input, because Magic only keeps the first 100 characters of
//     each result. `ms` is the time of Magic plus the bake of the first suggestion.
//   {"op": "bake", "input": "...", "recipe": [{"op": "To Base64", "args": [...]}]}
//     Runs a recipe and returns its output as text (UTF-8).
//   {"op": "checks", "hex": "..."}     (corpus.py) the operations Magic would try on these bytes:
//     the names of the operations whose detection patterns match (Magic's findMatchingInputOps)
//   {"op": "jsfuck", "input": "..."}   (corpus.py) JSFuck.encode from npm jsfuck, if installed
//   {"op": "eval", "code": "..."}      (corpus.py --verify) String(eval(code))
import { pathToFileURL } from "node:url";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { createRequire } from "node:module";

const dir = process.argv[2];
if (!dir) {
    process.stderr.write("usage: node cyberchef.mjs <dir with node_modules/cyberchef>\n");
    process.exit(2);
}
const chef = (await import(pathToFileURL(join(dir, "node_modules/cyberchef/src/node/index.mjs")).href)).default;
const MagicLib = (await import(pathToFileURL(join(dir, "node_modules/cyberchef/src/core/lib/Magic.mjs")).href)).default;

/** The text of a dish: UTF-8 decoded, as the web app shows it. */
function dishText(dish) {
    const buf = dish.get("ArrayBuffer");
    return new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(buf));
}

/** Runs a recipe on text input and returns its output as text, or null if it throws. */
async function bakeText(input, recipe) {
    try {
        return dishText(await chef.bake(input, recipe));
    } catch (e) {
        return null;
    }
}

async function handle(req) {
    if (req.op === "bake") {
        return { output: dishText(await chef.bake(req.input, req.recipe)) };
    }
    if (req.op === "checks") {
        const bytes = Uint8Array.from(req.hex.match(/../g) || [], h => parseInt(h, 16));
        const ops = new MagicLib(bytes.buffer).findMatchingInputOps().map(m => m.op);
        return { ops: [...new Set(ops)] };
    }
    if (req.op === "jsfuck") {
        const { JSFuck } = createRequire(join(dir, "package.json"))("jsfuck");
        return { output: JSFuck.encode(req.input, false, false) };
    }
    if (req.op === "eval") {
        return { output: String((0, eval)(req.code)) };
    }
    if (req.op === "magic") {
        const t0 = performance.now();
        const dish = await chef.magic(req.input, {
            depth: req.depth ?? 3,
            intensiveMode: !!req.intensive,
            extensiveLanguageSupport: !!req.extLang,
        });
        const options = dish.value;
        const top = Math.max(1, req.top ?? 5);
        const results = [];
        let ms = null;
        for (let i = 0; i < options.length && i < top; i++) {
            const o = options[i];
            const recipe = o.recipe.map(step => ({ op: step.op, args: step.args }));
            const output = recipe.length ? await bakeText(req.input, recipe) : req.input;
            if (i === 0) ms = performance.now() - t0;
            results.push({ recipe: recipe.map(step => step.op), recipe_full: recipe, output });
        }
        if (ms === null) ms = performance.now() - t0;
        return { ms, count: options.length, results };
    }
    throw new Error(`unknown op ${req.op}`);
}

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
process.stdout.write(JSON.stringify({ ready: true }) + "\n");
for await (const line of rl) {
    if (!line.trim()) continue;
    let reply;
    try {
        reply = await handle(JSON.parse(line));
    } catch (e) {
        reply = { error: String(e && e.stack || e) };
    }
    process.stdout.write(JSON.stringify(reply) + "\n");
}
