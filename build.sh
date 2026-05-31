#!/usr/bin/env bash
set -euo pipefail

cargo +nightly build --release \
    --target=bpfel-unknown-none \
    -Z build-std=core \
    --package shield-ebpf

cargo build --release --package shield
