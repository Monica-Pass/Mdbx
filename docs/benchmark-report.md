# MDBX Benchmark Report

本报告记录 MDBX storage benchmark harness 的一组可复现 release 测量。数值用于比较实现变化和发现异常，不构成硬件容量承诺，也不等同于客户端实际体验。

## Run Metadata

| Field | Value |
| --- | --- |
| Report format | `mdbx-benchmark-report-v1` |
| Source commit | `71565d23289851904c3c838842c302f6ce44e177` |
| Profile | `release` |
| Iterations | `20` per operation |
| OS | Windows 11 Insider Preview, build `27919` |
| CPU | 12th Gen Intel(R) Core(TM) i7-12800HX, 16 cores / 24 logical processors |
| Rust | `rustc 1.86.0 (05f9846f8 2025-03-31)` |
| Cargo command | `cargo run --release -p mdbx-cli -- benchmark --iterations 20 --output <report.json>` |

The machine-readable source for this run was generated as `.codex-tasks/20260722-benchmark-report/raw/benchmark-71565d2.json` and intentionally remains outside Git history. Re-run the command above from the `mdbx` directory to produce a new report with the current commit and host metadata.

## Results

`avg us/op` is `duration_us / ops` from one run. `output bytes/op` is operation-specific and is not a storage amplification ratio.

| Operation | Ops | Total ms | Avg us/op | Ops/s | Output bytes/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| `vault_create` | 20 | 141.991 | 7,099.545 | 140.9 | 0 |
| `entry_create` | 20 | 12.174 | 608.675 | 1,642.9 | 77.5 |
| `entry_edit_small` | 20 | 7.003 | 350.125 | 2,856.1 | 32.5 |
| `search_by_title` | 20 | 2.553 | 127.645 | 7,834.2 | 170.5 |
| `attachment_create_small` | 20 | 19.205 | 960.225 | 1,041.4 | 27.5 |
| `attachment_rename` | 20 | 8.517 | 425.860 | 2,348.2 | 12.5 |
| `attachment_replace_1k` | 20 | 7.520 | 376.010 | 2,659.5 | 1,024.0 |
| `snapshot_create` | 20 | 11.748 | 587.405 | 1,702.4 | 24,908.55 |
| `vault_open` | 20 | 130.388 | 6,519.405 | 153.4 | 0 |
| `vault_compaction` | 20 | 420.882 | 21,044.100 | 47.5 | 1,083,801.6 |
| `sync_delta_materialize` | 20 | 1.393 | 69.650 | 14,357.5 | 3,133.85 |

Suite wall time was `1,966.140 ms`.

## Dataset

The harness uses fixed, small datasets so smoke tests remain bounded:

- Search creates 100 projects and indexes 50 titles.
- Snapshot creates 20 projects with one login entry each.
- Compaction creates a synthetic 1,048,576-byte fragmentation table, deletes half the rows, then measures `PRAGMA wal_checkpoint(TRUNCATE); VACUUM;`.
- Sync delta materialization selects one existing entry and its commit, then measures envelope materialization and JSON encoding.
- Attachment replacement writes a 1 KiB inline payload per operation.

## Interpretation Limits

- This is one wall-clock run on one Windows host. No warm-up phase, percentile distribution, confidence interval, concurrency test, or cross-machine comparison is included.
- The benchmark initializes a vault without attaching a field keyring. It measures storage and transaction behavior in the compatibility/plaintext test mode, not a production unlocked vault with field encryption and Tiga authorization overhead.
- `vault_create` and `vault_open` include file/schema setup and migration checks appropriate to the harness. They are not isolated SQLite open calls.
- `vault_compaction` measures maintenance against the synthetic fragmentation table. It does not predict compaction time for a particular user's vault.
- `output_bytes` reports encoded sync payload bytes or logical content/result bytes selected by the operation. It does not claim on-disk encryption overhead or WAL growth.
- KDBX values in `kdbx_reference_numbers()` remain estimates and are excluded from this measured report.

## Reproduction

The CLI preserves human-readable output by default. JSON can be printed or written to a file:

```powershell
cargo run --release -p mdbx-cli -- benchmark --iterations 20 --json
cargo run --release -p mdbx-cli -- benchmark --iterations 20 --output .codex-tasks/benchmark.json
```

The JSON document contains the source commit, host metadata, fixed dataset description, per-operation durations, successful operation counts, output bytes, and the same limitations listed here.

