"""Run Python Ciphey (PyPI `ciphey`, 5.x) on one input and print the result as JSON.

run.py starts this once per case with the Python of a venv that has Python Ciphey installed
(see setup.sh), a fresh HOME and the input on stdin:

    <venv>/bin/python python_ciphey.py < INPUT

It does what `ciphey -q -t TEXT` does (ciphey/ciphey.py `main`): load the default config,
lower the verbosity below zero, which turns the human checker (the y/N prompt) off, and run
the default searcher and checker. `-q` only prints the plaintext; this prints the decoders
of the path too:

    {"status": "answer", "plaintext": "...", "path": ["base64", "caesar"]}
    {"status": "none"}
"""

import io
import json
import os
import sys


def main():
    text = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8").read()

    from ciphey import iface

    config = iface.Config()
    os.makedirs(iface.Config.get_default_dir(), exist_ok=True)
    config.load_file(create=True)
    # `-q`: verbosity -1. EzCheck only adds the human checker at verbosity >= 0.
    config.verbosity += -1
    config.update_log_level(config.verbosity)
    config.update("checker", None)
    config.update("searcher", None)
    config.update("default_dist", None)
    config.complete_config()

    res = config.objs["searcher"].search(text)
    if res is None:
        print(json.dumps({"status": "none"}))
        return
    value = res.path[-1].result.value
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    print(json.dumps({"status": "answer", "plaintext": value, "path": [step.name for step in res.path[1:]]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
