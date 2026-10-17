"""Remove host/kernel names from the upstream version banner, not solver logic."""

from pathlib import Path

path = Path("scripts/make-build-header.sh")
source = path.read_text()
old = 'OS="`uname -srmn 2>/dev/null`"'
if source.count(old) != 1:
    raise SystemExit("unexpected upstream build header; inspect before updating the pin")
path.write_text(source.replace(old, 'OS="Linux reproducible amd64"'))
