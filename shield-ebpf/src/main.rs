#![no_std]
#![no_main]

use aya_ebpf::{macros::lsm, programs::LsmContext};
use aya_log_ebpf::info;

#[lsm(hook = "bprm_check_security")]
pub fn shield(ctx: LsmContext) -> i32 {
    match try_shield(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_shield(ctx: LsmContext) -> Result<i32, i32> {
    info!(&ctx, "bprm_check_security: program exec attempt");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
