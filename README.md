# Compact Multi-Party Ring Signatures with Signer Count Anonymity

Code and experimental data accompanying the article by Shanghua Yang, Yubo Song, and Shang Gao.

## Directory structure

| Directory | Contents |
|---|---|
| `code/` | Rust implementations of the inverse, auxiliary-vector, and GK15 proof benchmarks, with their dependency files. |
| `data/` | Eight raw experimental CSV files: `common/` contains the common-domain comparison and `main/` contains the large-ring, signer-count, and encoding-cost experiments. |
| `expected/` | Reference CSV and LaTeX tables from the article, used to check the regenerated results. |
| `scripts/` | `reproduce.py` regenerates tables and figures from the recorded data; `benchmarks.py` builds and runs new experiments. |

The scripts create `results/` for regenerated tables and figures and `benchmark_runs/` for new timing measurements. These output directories are excluded from Git.

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
