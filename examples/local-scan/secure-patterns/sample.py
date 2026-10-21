"""Safe static-analysis comparison fixture; it is not part of the app."""

import subprocess
import tempfile

import yaml


def parse_document(raw):
    parsed = yaml.safe_load(raw)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as stream:
        stream.write(str(parsed))
    subprocess.run(["example-tool", "--", str(parsed)], check=True)
    return parsed
