use aya::maps::{Array, HashMap, RingBuf};
use aya::programs::Lsm;
use aya::{Btf, Ebpf};
use log::{info, warn};
use serde::Deserialize;
use shield_common::{BlockEvent, MODE_ENFORCE, MODE_LOG_ONLY};
use std::fs;
use tokio::io::unix::AsyncFd;

#[derive(Deserialize)]
struct Config {
    #[serde(default = "default_mode")]
    mode: String,
    #[serde(default)]
    allowed_callers: Vec<String>,
}

fn default_mode() -> String {
    "log-only".to_string()
}

fn hash_comm(name: &str) -> u64 {
    let mut h: u64 = 14695981039346656037;
    for &b in name.as_bytes().iter().take(15) {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

fn load_config() -> Config {
    let path = std::env::var("SHIELD_CONFIG").unwrap_or_else(|_| "shield.toml".to_string());
    match fs::read_to_string(&path) {
        Ok(s) => toml::from_str(&s).unwrap_or_else(|e| {
            warn!("invalid config {path}: {e}; using defaults");
            Config { mode: default_mode(), allowed_callers: vec![] }
        }),
        Err(_) => {
            warn!("config {path} not found; using defaults (log-only, empty allowlist)");
            Config { mode: default_mode(), allowed_callers: vec![] }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cfg = load_config();
    let mode = if cfg.mode == "enforce" { MODE_ENFORCE } else { MODE_LOG_ONLY };

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/shield"
    ))?;

    {
        let mut allowlist: HashMap<_, u64, u8> =
            HashMap::try_from(ebpf.map_mut("ALLOWLIST").unwrap())?;
        for name in &cfg.allowed_callers {
            allowlist.insert(hash_comm(name), 1, 0)?;
        }
    }
    {
        let mut mode_map: Array<_, u8> = Array::try_from(ebpf.map_mut("MODE").unwrap())?;
        mode_map.set(0, mode, 0)?;
    }

    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = ebpf.program_mut("shield").unwrap().try_into()?;
    program.load("bprm_check_security", &btf)?;
    program.attach()?;

    let mode_str = if mode == MODE_ENFORCE { "enforce" } else { "log-only" };
    info!("shield active (mode: {mode_str}, {} allowed callers)", cfg.allowed_callers.len());

    let ring = RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    let mut async_fd = AsyncFd::new(ring)?;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutting down");
                break;
            }
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                let ring = guard.get_inner_mut();
                while let Some(item) = ring.next() {
                    if item.len() >= std::mem::size_of::<BlockEvent>() {
                        let ev = unsafe { &*(item.as_ptr() as *const BlockEvent) };
                        let comm = String::from_utf8_lossy(&ev.comm);
                        let comm = comm.trim_end_matches('\0');
                        let tag = if ev.blocked == 1 { "BLOCKED" } else { "would-block" };
                        info!("[{tag}] pid={} comm={}", ev.pid, comm);
                    }
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}
