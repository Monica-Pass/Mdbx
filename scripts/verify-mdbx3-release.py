#!/usr/bin/env python3
"""Verify a staged MDBX3 Android drop-in release directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


EXPECTED_ABIS = {
    "arm64-v8a": ("elf", "aarch64"),
    "armeabi-v7a": ("elf", "arm"),
    "x86_64": ("elf", "x86_64"),
}
EXPECTED_LIBRARY_NAME = "libmdbx_ffi.so"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def binary_identity(path: Path) -> tuple[str, str]:
    data = path.read_bytes()
    if not data.startswith(b"\x7fELF") or len(data) < 20:
        raise ValueError(f"{path} is not a complete ELF shared object")
    byte_order = "little" if data[5] == 1 else "big" if data[5] == 2 else None
    if byte_order is None:
        raise ValueError(f"{path} has an unsupported ELF byte order")
    machine_id = int.from_bytes(data[18:20], byte_order)
    machine = {40: "arm", 62: "x86_64", 183: "aarch64"}.get(
        machine_id, f"elf-machine-{machine_id}"
    )
    return "elf", machine


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def verify(root: Path, abi_baseline_path: Path) -> dict:
    root = root.resolve()
    report_root = root / "reports"
    manifest = load_json(report_root / "mdbx3-build-manifest.json")
    abi = load_json(report_root / "mdbx3-android-ffi-abi.json")
    artifacts = load_json(report_root / "mdbx3-android-artifacts.json")
    abi_baseline = load_json(abi_baseline_path)
    if abi_baseline.get("uniffi_contract_version") != 30:
        raise ValueError("ABI baseline contract version must be 30")
    if len(abi_baseline.get("required_symbols", [])) != 535:
        raise ValueError("ABI baseline must contain 535 required symbols")
    if len(abi_baseline.get("checksums", {})) != 237:
        raise ValueError("ABI baseline must contain 237 checksum entries")

    runtime = manifest.get("runtime", {})
    required_runtime = {
        "runtime_name": "MDBX3",
        "storage_format": "MDBX-2",
        "writable_storage_format": "MDBX-2",
        "current_schema_version": 17,
        "ffi_namespace": "mdbx_ffi",
        "native_library_name": "mdbx_ffi",
        "android_shared_object_name": EXPECTED_LIBRARY_NAME,
        "compatibility_profile": "mdbx3-mdbx2-drop-in-v1",
    }
    for key, expected in required_runtime.items():
        if runtime.get(key) != expected:
            raise ValueError(f"manifest runtime {key} must be {expected!r}")

    if abi.get("status") != "compatible":
        raise ValueError("Android ABI report is not compatible")
    if abi.get("required_symbols") != 535:
        raise ValueError("Android ABI report must require 535 symbols")
    abi_entries = {entry.get("label"): entry for entry in abi.get("artifacts", [])}
    if set(abi_entries) != set(EXPECTED_ABIS):
        raise ValueError("Android ABI report must contain exactly the three supported ABIs")
    for label, entry in abi_entries.items():
        if entry.get("status") != "compatible" or entry.get("verified_symbols") != 535:
            raise ValueError(f"ABI entry is incomplete for {label}")

    if artifacts.get("profile") != "mdbx-runtime-artifact-report-v1":
        raise ValueError("unexpected artifact report profile")
    if artifacts.get("build_profile") != "mdbx3-release":
        raise ValueError("artifact report was not produced by mdbx3-release")
    if artifacts.get("artifact_postprocess") != "llvm-strip --strip-all":
        raise ValueError("artifacts must be postprocessed with llvm-strip --strip-all")
    artifact_entries = {entry.get("label"): entry for entry in artifacts.get("artifacts", [])}
    if set(artifact_entries) != set(EXPECTED_ABIS):
        raise ValueError("artifact report must contain exactly the three supported ABIs")

    verified = []
    for label, (container, machine) in EXPECTED_ABIS.items():
        library = root / "android-jniLibs" / label / EXPECTED_LIBRARY_NAME
        if not library.is_file():
            raise ValueError(f"missing staged library: {library}")
        if library.name != EXPECTED_LIBRARY_NAME:
            raise ValueError(f"unexpected library basename for {label}")
        actual_identity = binary_identity(library)
        if actual_identity != (container, machine):
            raise ValueError(
                f"{label} has identity {actual_identity}, expected {(container, machine)}"
            )
        entry = artifact_entries[label]
        if entry.get("file_name") != EXPECTED_LIBRARY_NAME:
            raise ValueError(f"artifact report has an unexpected basename for {label}")
        if int(entry.get("bytes", -1)) != library.stat().st_size:
            raise ValueError(f"artifact size report does not match {label}")
        actual_hash = sha256(library)
        if entry.get("sha256") != actual_hash:
            raise ValueError(f"artifact SHA-256 does not match {label}")
        verified.append({"label": label, "bytes": library.stat().st_size, "sha256": actual_hash})

    comparison = artifacts.get("comparison", {})
    totals = comparison.get("totals", {})
    if int(totals.get("byte_delta", 0)) >= 0:
        raise ValueError("MDBX3 raw artifact total must be smaller than the baseline")
    if int(totals.get("deflate_byte_delta", 0)) >= 0:
        raise ValueError("MDBX3 compressed artifact total must not regress")

    return {
        "profile": "mdbx3-release-gate-v1",
        "status": "ready",
        "runtime": "MDBX3",
        "storage_format": "MDBX-2",
        "verified_symbols": 535,
        "verified_checksums": 237,
        "uniffi_contract_version": 30,
        "artifacts": verified,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("target/mdbx3-android"),
        help="staged MDBX3 Android output root",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--abi-baseline",
        type=Path,
        default=Path("crates/mdbx-ffi/abi/mdbx2-uniffi-bindings-v1.json"),
    )
    args = parser.parse_args()
    try:
        result = verify(args.root, args.abi_baseline)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"MDBX3 release gate failed: {error}", file=sys.stderr)
        return 1
    rendered = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
