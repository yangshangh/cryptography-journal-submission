# Source programs

| Scheme | Directory | Benchmark entry point |
|---|---|---|
| Inverse constraint | `inverse/` | `ringsignature/src/bin/paper_benchmark.rs` |
| Auxiliary vector | `auxiliary/` | `ringsignature/src/bin/paper_benchmark.rs` |
| GK15 k-fold | `gk15/` | `src/main.rs` |

For inverse and auxiliary, the compressed proof is in `ringsignature/src/ringsig/protocol_compressed.rs`, the non-folded relation is in `protocol_linear.rs`, the inner-product argument is in `bulletproofs/src/ipa.rs`, and shared arithmetic/transcript helpers are in `toolbox/`.

GK15 implements the one-out-of-many commitment-opening proof from Groth and Kohlweiss, *One-Out-of-Many Proofs: Or How to Leak a Secret and Spend a Coin*, EUROCRYPT 2015. Its k-fold benchmark generates and verifies k separate proofs.

The programs use fixed random seeds for repeatable experimental inputs: inverse uses `[0x49;32]`, auxiliary uses `[0x41;32]`, and GK15 uses the seed in `src/main.rs`. They generate local Pedersen parameters rather than loading an external SRS.

Use `python3 scripts/benchmarks.py build` from the repository root, then `smoke`, `common`, or `all`. These commands keep new timings in `benchmark_runs/`. They never replace the article's distributed CSVs.

## Measurement scope

Timings cover local proof generation and verification, including transcript operations, and exclude setup, ring/key generation, initial witness preparation, and size accounting. Inverse and auxiliary use one local aggregate witness; GK15 generates and verifies `k` separate proofs. These measurements exclude network communication and the complete collaborative signing process. The original Windows binaries and run-to-binary records are unavailable.

These are the local computation baselines described in the article. They use randomized Pedersen setup. Inverse compresses outer context into an IPA scalar. Auxiliary omits public parameters from its outer transcript and outer context from its IPA transcript; its message-digest append receives an empty slice, with the digest checked separately. These programs do not implement every setup and transcript requirement of the complete signature specification.

Auxiliary measurements for `N>=256` are used only for encoding-cost comparison, outside the auxiliary relation's valid domain. Format sizes follow construction element counts; vector-program object sizes do not measure complete-signature serialization.
