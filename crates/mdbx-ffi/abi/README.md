# MDBX FFI ABI baselines

`mdbx2-uniffi-bindings-v1.json` freezes the native contract used by Kotlin bindings generated from MDBX2 commit `1070dee739dbe564806654359b6c6caa68156de5` with UniFFI 0.31.1.

The baseline records:

1. UniFFI contract version.
2. Every native function declared by the generated MDBX2 Kotlin bindings.
3. Every API checksum and its expected 16-bit value.
4. The SHA-256 of the generated bindings source.

MDBX3 may add functions and types. Every baseline symbol and checksum must remain available so an application can replace `libmdbx_ffi.so` without regenerating MDBX2 bindings.

Build the current library and verify it with:

```powershell
cargo build -p mdbx-ffi
python scripts/verify-mdbx3-ffi-abi.py verify `
  --baseline crates/mdbx-ffi/abi/mdbx2-uniffi-bindings-v1.json `
  --library target/debug/mdbx_ffi.dll
```

Linux uses `target/debug/libmdbx_ffi.so`; macOS uses the corresponding dylib.
