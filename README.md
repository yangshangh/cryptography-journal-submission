# Compact Multi-Party Ring Signatures with Signer Count Anonymity

Code and experimental data accompanying the article by Shanghua Yang, Yubo Song, and Shang Gao.

This repository contains the three local proof implementations, the eight CSV files used in the article, and a script that regenerates its four numerical tables and three figures. It contains 1,350 retained observations in 45 configuration groups, with 30 measurements per group.

## Reproduce the published tables and figures

Python 3.12 was used to validate the analysis. Rust is not required for this step. `requirements.txt` pins the two direct dependencies; `requirements-lock.txt` also pins the transitive dependencies used for validation.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-lock.txt
python scripts/check_integrity.py
python scripts/reproduce.py
```

The analysis takes about 10–30 seconds on a recent laptop once dependencies are installed. It writes CSV statistics, LaTeX tables, and PDF/PNG figures into `results/`. It checks all 34 table rows against `expected/`, using a numerical tolerance of `1e-10` absolute or `1e-12` relative, and requires the four LaTeX tables to match exactly, including captions. It reads the recorded measurements; it does not rerun the timing experiments.

| Article result | Data | Generated outputs under `results/` |
|---|---|---|
| Common-domain comparison, `k=4`, `N=16,32,64,128` | `data/common/*.csv` | `valid_parameters.csv`, `tables/valid_parameters.tex`, `figures/secure_protocol_comparison.*` |
| Large-ring comparison, `k=4`, `N=128,256,512,1024` | `data/main/*.csv` | `large_ring.csv`, `tables/large_ring.tex`, `figures/large_ring_scalability.*` |
| Signer-count comparison, `N=1024`, `k=1,2,4,8,16` | `data/main/*.csv` | `signer_count.csv`, `tables/signer_count.tex`, `figures/k_sensitivity_large_ring.*` |
| Nonemptiness-encoding comparison, `k=16` | Inverse and auxiliary files in `data/main/` | `implementation_comparison.csv`, `tables/implementation_comparison.tex` |

At `N=128,k=4` in the common-domain experiment, inverse and auxiliary generation medians are 79.670 and 148.258 ms; verification medians are 24.949 and 43.086 ms. The corresponding auxiliary/inverse ratios are approximately 1.86 and 1.73. Format sizes are 851 and 980 bytes under the article's 33-byte group-element and 32-byte scalar convention.

## Build the benchmark programs

Install Rust with rustup. The root `rust-toolchain.toml` selects `nightly-2025-03-02`, whose `rustc` version is `1.87.0-nightly (8c392966a 2025-03-01)`. Each program has a committed `Cargo.lock`.

```sh
python3 scripts/benchmarks.py build
python3 scripts/benchmarks.py smoke
```

The build uses Release mode, default Cargo features, no extra `RUSTFLAGS`, and `--locked`. A first build requires network access for dependencies and several minutes. Smoke mode runs one warmup and one measured proof-generation/verification call at `N=128,k=1` for each scheme. Each executable checks its generated proofs. CSV output goes to the ignored `benchmark_runs/` directory.

To run new measurements for the common-domain configurations:

```sh
python3 scripts/benchmarks.py common
```

To run all configurations represented in the article:

```sh
python3 scripts/benchmarks.py all
```

These commands generate new timing files separately from the distributed data. The full campaign can take tens of minutes depending on hardware. Timing values and ratios can change across machines and builds; the exact original Windows binaries and run-to-binary records are not available. The source programs and new measurements should not be treated as a reconstruction of those missing execution records.

## Measurement scope

The recorded environment was an AMD Ryzen 9 7945HX, 16 GB RAM, Windows build 26200.9168, Rust 1.87.0-nightly, arkworks 0.4, and secp256k1. Each configuration used three warmups followed by 30 retained measurements. Schemes ran sequentially. Medians and quartiles are recomputed from individual observations; quartiles use linear interpolation.

Timings cover local proof generation and verification, including transcript operations, and exclude setup, ring/key generation, initial witness preparation, and size accounting. They do not measure network communication or the complete collaborative signing process. Inverse and auxiliary generate one aggregate proof from a local witness for all signers; GK15 generates and verifies `k` independent proofs, revealing the proof count `k`.

The included programs use randomized Pedersen setup. The inverse program compresses outer context into an IPA scalar. The auxiliary program omits public parameters from its outer transcript and outer context from its IPA transcript; its message-digest append receives an empty slice, with the digest checked separately. These are the local computation baselines described in the article, with the implementation scope stated there; they do not implement every setup and transcript requirement of the complete signature specification.

Auxiliary measurements for `N>=256` are used only in the encoding-cost comparison: the auxiliary relation's condition `2^N-1<q` does not hold there. Format bytes are construction calculations, and `implementation_size_bytes` is retained separately. For the two vector programs it is not a measurement of complete-signature serialization. GK15 explicitly serializes its proof fields.

Common-domain and large-ring `N=128,k=4` records are distinct experiments. Ratios must be formed within the same experiment. The main `N=1024,k=4` observations are reused in the large-ring and signer-count tables.

## Repository contents

- `code/`: inverse, auxiliary-vector, and GK15 implementations and locked dependencies.
- `data/`: eight unmodified raw CSV files; see `data/README.md` for their schema and selection.
- `scripts/`: analysis, file-integrity verification, and optional benchmark commands.
- `expected/`: the four numerical tables and LaTeX fragments used to check regeneration.
- `SHA256SUMS`: checksums for the distributed files.

The raw CSV bytes and executable Rust code are preserved from the experimental source snapshot. Three source comments are made self-contained. Other packaging changes remove an unused Triptych workspace member, reduce the corresponding lockfiles, rename data paths, and make the analysis self-contained. See `code/README.md` for the source entry points. Dependency packages retain their own licenses; this repository does not assign a new license to the bundled source code.
