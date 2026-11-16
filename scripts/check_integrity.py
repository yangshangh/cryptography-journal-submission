"""Verify the exact bytes and file inventory of the distributed artifact."""
from pathlib import Path
import hashlib
import subprocess

ROOT = Path(__file__).resolve().parents[1]
listed = set()
for line in (ROOT / 'SHA256SUMS').read_text().splitlines():
    digest, relative = line.split('  ', 1)
    path = ROOT / relative
    assert relative not in listed and path.resolve().is_relative_to(ROOT.resolve()), relative
    assert path.is_file(), ('missing', relative)
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    assert actual == digest, ('checksum mismatch', relative, digest, actual)
    listed.add(relative)
# Git archives do not contain .git; hashes still validate all listed files there.
if (ROOT / '.git').is_dir():
    tracked = set(subprocess.check_output(['git', '-C', str(ROOT), 'ls-files'], text=True).splitlines())
    assert listed == tracked - {'SHA256SUMS'}, ('inventory mismatch', sorted(listed ^ (tracked - {'SHA256SUMS'})))
print(f'PASS: {len(listed)} distributed files match SHA256SUMS.')
