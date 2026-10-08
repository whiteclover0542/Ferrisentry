use core::mem::size_of;

use ferrisentry_common::ExecEvent;

#[test]
fn exec_event_has_the_shared_kernel_userspace_abi() {
    let event = ExecEvent {
        pid: 4242,
        comm: *b"ferrisentry\0\0\0\0\0",
    };

    assert_eq!(size_of::<ExecEvent>(), 20);
    assert_eq!(event.pid, 4242);
    assert_eq!(&event.comm[..11], b"ferrisentry");
}
