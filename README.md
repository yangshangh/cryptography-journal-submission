# Compact Multi-Party Ring Signatures with Signer Count Anonymity

Code and experimental data accompanying the article by Shanghua Yang, Yubo Song, and Shang Gao.

## Reproduce the tables and figures

Use Python 3.12:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/reproduce.py
```

The script reads the eight recorded CSV files, generates four tables and three figures in `results/`, and checks the tables against `expected/`.

## Run the benchmarks

Install Rust with rustup; `rust-toolchain.toml` selects the compiler version.

```sh
python3 scripts/benchmarks.py build
python3 scripts/benchmarks.py smoke
```

Use `common` or `all` instead of `smoke` for new timing experiments. Results are saved in `benchmark_runs/`; timings depend on the machine and build.

The programs measure local proof generation and verification. Implementation details and measurement scope are described in the article and `code/README.md`; CSV fields are documented in `data/README.md`.
