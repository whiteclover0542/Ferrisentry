#![no_std]

pub const KIND_EXEC: u32 = 0;
pub const KIND_SETUID: u32 = 1;
pub const KIND_CONNECT: u32 = 2;
pub const KIND_OPENAT: u32 = 3;
pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 128;

/// Fixed-size event shared by the kernel probes and userspace.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub kind: u32,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    /// openat: flags; setuid: target UID; otherwise zero.
    pub arg: u64,
    pub comm: [u8; COMM_LEN],
    pub path: [u8; PATH_LEN],
    /// Destination address; IPv4 occupies the first four bytes.
    pub addr: [u8; 16],
    /// Destination port in host byte order.
    pub port: u16,
    pub family: u16,
    /// Explicit tail padding keeps all ring-buffer bytes initialized.
    pub reserved: [u8; 4],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}
