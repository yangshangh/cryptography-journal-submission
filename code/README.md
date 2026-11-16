# Source programs

| Scheme | Directory | Benchmark entry point |
|---|---|---|
| Inverse constraint | `inverse/` | `ringsignature/src/bin/paper_benchmark.rs` |
| Auxiliary vector | `auxiliary/` | `ringsignature/src/bin/paper_benchmark.rs` |
| GK15 k-fold | `gk15/` | `src/main.rs` |

For inverse and auxiliary, the compressed proof is in `ringsignature/src/ringsig/protocol_compressed.rs`, the non-folded relation is in `protocol_linear.rs`, the inner-product argument is in `bulletproofs/src/ipa.rs`, and shared arithmetic/transcript helpers are in `toolbox/`.

GK15 implements the one-out-of-many commitment-opening proof from Groth and Kohlweiss, *One-Out-of-Many Proofs: Or How to Leak a Secret and Spend a Coin*, EUROCRYPT 2015. Its k-fold benchmark generates and verifies k separate proofs.

Of the 39 Rust source files, 37 are byte-identical to the experimental source snapshot. Three comments in the inverse linear/compressed proof files are rewritten as self-contained descriptions; executable Rust code is unchanged. The two workspace manifests and corresponding workspace lockfiles are adjusted to remove an unused Triptych benchmark and its dependencies. Cargo resolves the same retained registry package versions as the source lockfiles.

The programs use fixed random seeds for repeatable experimental inputs: inverse uses `[0x49;32]`, auxiliary uses `[0x41;32]`, and GK15 uses the seed in `src/main.rs`. They generate local Pedersen parameters rather than loading an external SRS. See the root README for the precise implementation and measurement scope.

Use `python3 scripts/benchmarks.py build` from the repository root, then `smoke`, `common`, or `all`. These commands keep new timings in `benchmark_runs/`. They never replace the article's distributed CSVs.
