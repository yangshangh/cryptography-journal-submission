"""Build and optionally run the packaged local proof benchmarks."""
import argparse
import csv
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('command', choices=['build', 'smoke', 'common', 'all'])
args = parser.parse_args()
env = os.environ.copy()
# Fixed distribution recipe: default features, no additional compiler flags.
env.pop('RUSTFLAGS', None)
env.pop('CARGO_ENCODED_RUSTFLAGS', None)
print(platform.platform(), flush=True)
subprocess.run(['rustc', '--version'], cwd=ROOT, env=env, check=True)
subprocess.run(['cargo', '--version'], cwd=ROOT, env=env, check=True)
print('Release mode; --locked; default features; no extra RUSTFLAGS', flush=True)
for scheme in ['inverse', 'auxiliary', 'gk15']:
    manifest = ROOT / 'code' / scheme / 'Cargo.toml'
    command = ['cargo', 'build' if args.command == 'build' else 'run',
               '--release', '--locked', '--manifest-path', str(manifest)]
    if scheme != 'gk15':
        command += ['-p', 'ringsignature', '--bin', 'paper_benchmark']
    if args.command == 'build':
        subprocess.run(command, cwd=ROOT, env=env, check=True)
        continue
    modes = ['smoke'] if args.command == 'smoke' else (
        ['common'] if args.command == 'common' else ['default', 'main-k4', 'common'])
    destination = ROOT / 'benchmark_runs'
    destination.mkdir(exist_ok=True)
    for mode in modes:
        flag = {'smoke': '--smoke', 'common': '--secure-main',
                'main-k4': '--main-k4', 'default': None}[mode]
        run = command + (['--', flag] if flag else [])
        output = destination / f'{scheme}_{mode}.csv'
        # Do not overwrite a preceding measurement run.
        suffix = 1
        while output.exists():
            output = destination / f'{scheme}_{mode}_{suffix}.csv'
            suffix += 1
        with output.open('x', newline='') as stream:
            subprocess.run(run, cwd=ROOT, env=env, stdout=stream, check=True)
        with output.open(newline='') as stream:
            rows = list(csv.DictReader(stream))
        assert rows, (scheme, mode, 'empty output')
        if mode == 'smoke':
            assert len(rows) == 1 and rows[0]['ring_size'] == '128' and rows[0]['k'] == '1'
        print(f'PASS: {scheme} {mode}: {len(rows)} verified observations in {output.relative_to(ROOT)}', flush=True)
