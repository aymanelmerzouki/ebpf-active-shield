# ebpf-active-shield

An eBPF/LSM security agent for Linux, written in Rust with [Aya](https://aya-rs.dev).
It attaches to the `bprm_check_security` LSM hook to observe (and, in later
versions, control) process execution from within the kernel.

## Status

Early stage. The current version runs in **observe mode**: it logs every process
execution attempt without blocking anything. Enforcement (allowlist-based blocking)
is the next milestone.

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
sudo RUST_LOG=info ./target/release/shield
```

## License

MIT
