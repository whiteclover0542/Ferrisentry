use anyhow::{Context, Result};
use aya::{include_bytes_aligned, maps::RingBuf, programs::TracePoint, Ebpf};
use ferrisentry_common::ExecEvent;
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

    let mut ring_buf = RingBuf::try_from(
        ebpf.take_map("EXEC_EVENTS")
            .context("EXEC_EVENTS map not found")?,
    )?;

    info!("Monitoring process execution... (Ctrl+C to stop)");

    let mut tick = time::interval(time::Duration::from_millis(50));
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => break,
            _ = tick.tick() => {
                while let Some(data) = ring_buf.next() {
                    if data.len() < std::mem::size_of::<ExecEvent>() {
                        continue;
                    }
                    let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const ExecEvent) };
                    println!("{}", format_event(&event));
                }
            }
        }
    }

    Ok(())
}

fn format_event(event: &ExecEvent) -> String {
    let comm = String::from_utf8_lossy(&event.comm);
    format!("PID: {} COMM: {}", event.pid, comm.trim_end_matches('\0'))
}

#[cfg(test)]
mod tests {
    use ferrisentry_common::ExecEvent;

    use super::format_event;

    #[test]
    fn formats_a_nul_terminated_command_name() {
        let event = ExecEvent {
            pid: 4242,
            comm: *b"ferrisentry\0\0\0\0\0",
        };

        assert_eq!(format_event(&event), "PID: 4242 COMM: ferrisentry");
    }
}
