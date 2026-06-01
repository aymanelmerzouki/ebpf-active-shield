use aya::maps::{Array, HashMap};
use aya::programs::Lsm;
use aya::{Btf, Ebpf};
use log::{info, warn};
use shield_common::{MODE_ENFORCE, MODE_LOG_ONLY};
use std::env;

const ALLOWED_CALLERS: &[&str] = &[
    "bash", "sh", "zsh", "fish", "cargo", "rustc", "shield", "sudo", "systemd",
    "gnome-shell", "Xorg", "code", "git", "rustup", "waybar", "hyprland", "sway",
    "kitty", "alacritty", "foot", "dbus-daemon", "make",
];

fn hash_comm(name: &str) -> u64 {
    let mut h: u64 = 14695981039346656037;
    for &b in name.as_bytes().iter().take(15) {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mode = match env::var("SHIELD_MODE").as_deref() {
        Ok("enforce") => MODE_ENFORCE,
        _ => MODE_LOG_ONLY,
    };

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/shield"
    ))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    {
        let mut allowlist: HashMap<_, u64, u8> =
            HashMap::try_from(ebpf.map_mut("ALLOWLIST").unwrap())?;
        for name in ALLOWED_CALLERS {
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
    info!("shield active (mode: {mode_str}); press Ctrl-C to stop");

    tokio::signal::ctrl_c().await?;
    info!("shutting down");
    Ok(())
}
