# ebpf-active-shield

An eBPF/LSM security agent for Linux, written in Rust with [Aya](https://aya-rs.dev).
It attaches to the `bprm_check_security` LSM hook to control which processes are
allowed to execute other programs (execution-origin control), enforced from
within the kernel.

## Status

Working prototype. The agent maintains a kernel-side allowlist of processes that
may spawn other programs. It runs in two modes:

- **log-only** (default): logs would-be blocks without enforcing. Safe.
- **enforce**: actually denies execution (`EPERM`) for callers not in the allowlist.

This is effective against patterns like a compromised service spawning a shell
(reverse shells, arbitrary command execution).

> Note: identification is based on the caller's `comm` (process name, max 16
> chars). Distinguishing two binaries with the same name is a known limitation,
> planned for a later version using the full executable path.

## Architecture

| Crate | Runs in | Role |
|-------|---------|------|
| `shield-ebpf` | kernel (eBPF VM) | LSM program attached to `bprm_check_security` |
| `shield` | user space | loads the eBPF program and reads its events |
| `shield-common` | both | shared data types |

## Requirements

- Linux kernel with BPF LSM enabled (`CONFIG_BPF_LSM=y`, and `bpf` listed in
  `/sys/kernel/security/lsm`)
- Rust stable + nightly (nightly is needed to build the eBPF object via `build-std`)
- `bpf-linker` (`cargo install bpf-linker`)

## Build

```bash
./build.sh
```

## Run

Loading an eBPF LSM program requires elevated privileges:

```bash
# log-only (default, safe)
sudo RUST_LOG=info ./target/release/shield

# enforce (actually blocks; pass the variable through sudo)
sudo SHIELD_MODE=enforce RUST_LOG=info ./target/release/shield
```

## License

MIT
