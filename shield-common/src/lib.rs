#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlockEvent {
    pub pid: u32,
    pub comm: [u8; 16],
    pub blocked: u8,
}

unsafe impl Send for BlockEvent {}

pub const MODE_LOG_ONLY: u8 = 0;
pub const MODE_ENFORCE: u8 = 1;
