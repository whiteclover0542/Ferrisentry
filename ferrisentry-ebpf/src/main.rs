#![no_std]
#![no_main]

use aya_ebpf::{
    cty::c_long,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use ferrisentry_common::{Event, KIND_EXEC, KIND_SETUID, PATH_LEN};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Common metadata for all probes. Task 6 will populate ppid and cgroup_id.
fn base_event(kind: u32) -> Result<Event, c_long> {
    Ok(Event {
        kind,
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        ppid: 0,
        uid: bpf_get_current_uid_gid() as u32,
        cgroup_id: 0,
        arg: 0,
        comm: bpf_get_current_comm()?,
        path: [0; PATH_LEN],
        addr: [0; 16],
        port: 0,
        family: 0,
        reserved: [0; 4],
    })
}

/// Drop when the ring buffer is full; Task 5 will count these drops.
fn emit(event: &Event) {
    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        entry.write(*event);
        entry.submit(0);
    }
}

#[tracepoint]
pub fn trace_exec(_ctx: TracePointContext) -> u32 {
    if let Ok(event) = base_event(KIND_EXEC) {
        emit(&event);
    }
    0
}

// The uid argument is a syscall register slot; uid_t uses its low 32 bits.
const SETUID_UID_OFFSET: usize = 16;

#[tracepoint]
pub fn trace_setuid(ctx: TracePointContext) -> u32 {
    try_trace_setuid(&ctx).unwrap_or(0)
}

fn try_trace_setuid(ctx: &TracePointContext) -> Result<u32, c_long> {
    let target_uid =
        unsafe { ctx.read_at::<u64>(SETUID_UID_OFFSET) }.map_err(|error| error as c_long)?;
    let mut event = base_event(KIND_SETUID)?;
    event.arg = target_uid as u32 as u64;
    emit(&event);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
