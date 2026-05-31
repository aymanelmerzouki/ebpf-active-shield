use aya::programs::Lsm;
use aya::{Btf, Ebpf};
use log::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/shield"
    ))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = ebpf.program_mut("shield").unwrap().try_into()?;
    program.load("bprm_check_security", &btf)?;
    program.attach()?;

    info!("shield active (observe mode); press Ctrl-C to stop");

    tokio::signal::ctrl_c().await?;
    info!("shutting down");
    Ok(())
}
