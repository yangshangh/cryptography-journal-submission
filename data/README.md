# Benchmark measurements

There are eight CSV files, 1,350 observations, and 45 distinct experiment/scheme/ring-size/signer-count groups. Every group contains 30 recorded runs after three warmups.

## Files

| File | Selected configurations |
|---|---|
| `common/auxiliary.csv` | Auxiliary, `N=16,32,64,128`, `k=4` |
| `common/inverse.csv` | Inverse, `N=16,32,64,128`, `k=4` |
| `common/gk15.csv` | GK15 k-fold, `N=16,32,64,128`, `k=4` |
| `main/auxiliary_default.csv` | Auxiliary, `k=16` at `N=128,256,512,1024`; `N=1024`, `k=1,2,4,8` |
| `main/auxiliary_main_k4.csv` | Auxiliary, `N=128,256,512`, `k=4` |
| `main/inverse_default.csv` | Inverse, same default configurations as auxiliary |
| `main/inverse_main_k4.csv` | Inverse, `N=128,256,512`, `k=4` |
| `main/gk15.csv` | GK15 k-fold, the default configurations and `N=128,256,512`, `k=4` |

The default files also provide `N=1024,k=4`, which is shared between the two main table families. Main auxiliary `k=4` observations are retained as part of the selected input set; the large-ring table compares inverse with GK15. Auxiliary configurations outside the valid domain are used only for encoding-cost accounting, as explained in the article.

## Columns

| Column | Meaning |
|---|---|
| `scheme` | `inverse_constraint`, `auxiliary_vector`, or `gk15_oom_kfold` |
| `ring_size` | Public ring size `N` |
| `k` | Number of participating signers / independent GK15 proofs |
| `iteration` | Recorded run index, from 0 to 29 within each group |
| `prove_ms` | Local proof-generation elapsed time, milliseconds |
| `verify_ms` | Local proof-verification elapsed time, milliseconds |
| `paper_size_bytes` | Construction-format size with 33-byte group elements and 32-byte scalars |
| `implementation_size_bytes` | Program-reported object-size accounting; not a common wire-size metric for the vector schemes |

Raw files retain their original byte representation, including line endings. File renaming changes only repository paths. Statistics use the median and linearly interpolated first and third quartiles; IQR is Q3 minus Q1. The distributed analysis validates the format-size formulas, the expected configuration sets, finite positive timings, and unique run indices.
