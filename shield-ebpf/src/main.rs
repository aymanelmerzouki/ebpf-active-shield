#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{lsm, map},
    maps::{Array, HashMap, RingBuf},
    programs::LsmContext,
};
use shield_common::{BlockEvent, MODE_ENFORCE, MODE_LOG_ONLY};

#[map]
static ALLOWLIST: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static MODE: Array<u8> = Array::with_max_entries(1, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4096 * 64, 0);

const EPERM: i32 = -1;

fn hash_comm(comm: &[u8; 16]) -> u64 {
    let mut h: u64 = 14695981039346656037;
    let mut i = 0;
    while i < 16 {
        let b = comm[i];
        if b == 0 {
            break;
        }
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
        i += 1;
    }
    h
}

#[lsm(hook = "bprm_check_security")]
pub fn shield(ctx: LsmContext) -> i32 {
    match try_shield(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_shield(_ctx: &LsmContext) -> Result<i32, i32> {
    let comm = bpf_get_current_comm().map_err(|_| 0i32)?;
    let key = hash_comm(&comm);

    if unsafe { ALLOWLIST.get(&key).is_some() } {
        return Ok(0);
    }

    let mode = MODE.get(0).copied().unwrap_or(MODE_LOG_ONLY);
    let blocked = if mode == MODE_ENFORCE { 1 } else { 0 };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let event = BlockEvent { pid, comm, blocked };
    let _ = EVENTS.output(&event, 0);

    if mode == MODE_ENFORCE {
        Ok(EPERM)
    } else {
        Ok(0)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
