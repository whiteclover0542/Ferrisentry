use anyhow::{Context, Result};
use aya::{Ebpf, include_bytes_aligned, maps::RingBuf, programs::TracePoint};
use ferrisentry_common::{Event, KIND_CONNECT, KIND_EXEC, KIND_OPENAT, KIND_SETUID};
use log::info;
use tokio::{signal, time};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ferrisentry"
    )))?;

    let program: &mut TracePoint = ebpf
        .program_mut("trace_exec")
        .context("trace_exec program not found")?
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    let mut ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS map not found")?)?;

    info!("Monitoring process execution... (Ctrl+C to stop)");

    let mut tick = time::interval(time::Duration::from_millis(50));
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => break,
            _ = tick.tick() => {
                while let Some(data) = ring_buf.next() {
                    if data.len() < std::mem::size_of::<Event>() {
                        continue;
                    }
                    let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Event) };
                    println!("{}", format_event(&event));
                }
            }
        }
    }

    Ok(())
}

fn format_event(event: &Event) -> String {
    let kind = match event.kind {
        KIND_EXEC => "exec",
        KIND_SETUID => "setuid",
        KIND_CONNECT => "connect",
        KIND_OPENAT => "openat",
        _ => "unknown",
    };
    let detail = match event.kind {
        KIND_SETUID => format!("target_uid={}", event.arg),
        KIND_OPENAT => format!("path={} flags=0x{:x}", cstr(&event.path), event.arg),
        _ => String::new(),
    };
    let mut output = format!(
        "[{}] pid={} ppid={} uid={} comm={} cgroup={}",
        kind,
        event.pid,
        event.ppid,
        event.uid,
        cstr(&event.comm),
        event.cgroup_id
    );
    if !detail.is_empty() {
        output.push(' ');
        output.push_str(&detail);
    }
    output
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::{cstr, format_event};
    use ferrisentry_common::{COMM_LEN, Event, KIND_EXEC, KIND_OPENAT, KIND_SETUID, PATH_LEN};
    fn event(kind: u32) -> Event {
        let mut event = Event {
            kind,
            pid: 4242,
            ppid: 12,
            uid: 1000,
            cgroup_id: 99,
            arg: 0,
            comm: [0; COMM_LEN],
            path: [0; PATH_LEN],
            addr: [0; 16],
            port: 0,
            family: 0,
            reserved: [0; 4],
        };
        event.comm[..4].copy_from_slice(b"echo");
        event
    }
    #[test]
    fn formats_exec_metadata() {
        assert_eq!(
            format_event(&event(KIND_EXEC)),
            "[exec] pid=4242 ppid=12 uid=1000 comm=echo cgroup=99"
        );
    }
    #[test]
    fn formats_setuid_target() {
        let mut event = event(KIND_SETUID);
        event.arg = 123;
        assert_eq!(
            format_event(&event),
            "[setuid] pid=4242 ppid=12 uid=1000 comm=echo cgroup=99 target_uid=123"
        );
    }
    #[test]
    fn formats_openat_path_and_flags() {
        let mut event = event(KIND_OPENAT);
        event.path[..4].copy_from_slice(b"/etc");
        event.arg = 0x241;
        assert_eq!(
            format_event(&event),
            "[openat] pid=4242 ppid=12 uid=1000 comm=echo cgroup=99 path=/etc flags=0x241"
        );
    }
    #[test]
    fn cstr_stops_at_first_nul_and_handles_full_buffers() {
        assert_eq!(cstr(b"echo\0ignored"), "echo");
        assert_eq!(cstr(b"abcdefghijklmnop"), "abcdefghijklmnop");
        assert_eq!(cstr(b""), "");
    }
    #[test]
    fn cstr_decodes_invalid_utf8_lossily() {
        assert_eq!(cstr(&[b'a', 0xff, 0, b'b']), "a\u{fffd}");
    }
}
