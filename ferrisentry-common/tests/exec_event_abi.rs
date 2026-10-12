use core::mem::{align_of, offset_of, size_of};

use ferrisentry_common::{
    COMM_LEN, Event, KIND_CONNECT, KIND_EXEC, KIND_OPENAT, KIND_SETUID, PATH_LEN,
};

#[test]
fn event_has_a_stable_kernel_userspace_abi() {
    assert_eq!(align_of::<Event>(), 8);
    assert_eq!(size_of::<Event>(), 200);
    assert_eq!(COMM_LEN, 16);
    assert_eq!(PATH_LEN, 128);
    assert_eq!(
        [KIND_EXEC, KIND_SETUID, KIND_CONNECT, KIND_OPENAT],
        [0, 1, 2, 3]
    );
    assert_eq!(offset_of!(Event, kind), 0);
    assert_eq!(offset_of!(Event, pid), 4);
    assert_eq!(offset_of!(Event, ppid), 8);
    assert_eq!(offset_of!(Event, uid), 12);
    assert_eq!(offset_of!(Event, cgroup_id), 16);
    assert_eq!(offset_of!(Event, arg), 24);
    assert_eq!(offset_of!(Event, comm), 32);
    assert_eq!(offset_of!(Event, path), 48);
    assert_eq!(offset_of!(Event, addr), 176);
    assert_eq!(offset_of!(Event, port), 192);
    assert_eq!(offset_of!(Event, family), 194);
    assert_eq!(offset_of!(Event, reserved), 196);
}
