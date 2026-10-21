"""Intentionally insecure static-analysis fixture. Never execute this file."""

import pickle
import subprocess
import tempfile
import yaml


def parse_untrusted_input(raw):
    value = eval(raw)
    restored = pickle.loads(raw)
    parsed = yaml.load(raw, Loader=yaml.Loader)
    subprocess.run(raw, shell=True, check=False)
    tempfile.mktemp()
    return value, restored, parsed
