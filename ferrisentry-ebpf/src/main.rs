#![no_std]
#![no_main]

use aya_ebpf::{
    cty::c_long,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use ferrisentry_common::ExecEvent;

#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn trace_exec(ctx: TracePointContext) -> u32 {
    match try_trace_exec(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_trace_exec(_ctx: &TracePointContext) -> Result<u32, c_long> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = bpf_get_current_comm()?;

    if let Some(mut entry) = EXEC_EVENTS.reserve::<ExecEvent>(0) {
        entry.write(ExecEvent { pid, comm });
        entry.submit(0);
    }

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
