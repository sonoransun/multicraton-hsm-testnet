#!/usr/bin/env bash
# CPU-tuned local build. NOT for distribution: binaries built with
# target-cpu=native may SIGILL on older CPUs.
# Note: setting RUSTFLAGS replaces the rustflags from .cargo/config.toml,
# so on aarch64 we must re-add the AES/PMULL backend cfgs here.
set -euo pipefail
FLAGS="-C target-cpu=native"
case "$(uname -m)" in
  arm64|aarch64) FLAGS="$FLAGS --cfg aes_armv8 --cfg polyval_armv8" ;;
esac
echo "Building with RUSTFLAGS=\"$FLAGS\" (local machine only — do not distribute)" >&2
RUSTFLAGS="$FLAGS" exec cargo build --release "$@"
