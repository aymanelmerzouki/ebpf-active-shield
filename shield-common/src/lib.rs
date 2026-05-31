#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlockEvent {
    pub pid: u32,
    pub comm: [u8; 16],
}

unsafe impl Send for BlockEvent {}
