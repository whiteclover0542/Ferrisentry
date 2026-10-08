# Phase 1: 핵심 probe + 이벤트 파이프라인 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Phase 0의 execve 하나짜리 파이프라인을 네 종류(`execve`, `connect`, `openat`, `setuid`)로 늘리고, 모든 이벤트에 "누가(pid/ppid/uid/comm), 어디서(cgroup)" 정보를 붙인다. 이벤트 유실은 숨기지 않고 카운트해서 드러낸다.

**Architecture:** 공용 `Event` 구조체 하나로 네 종류 이벤트를 모두 표현하고, 커널의 네 tracepoint가 같은 `EVENTS` ring buffer로 push한다. 유저스페이스는 ring buffer를 읽어 `kind`에 따라 포맷해 출력하고, cgroup ID를 cgroup 경로/컨테이너 ID로 변환한다.

```
sched_process_exec ┐
sys_enter_setuid   ├─▶ EVENTS (RingBuf) ─▶ 유저스페이스: 포맷 + cgroup 매핑 ─▶ stdout
sys_enter_connect  │                        DROPS (PerCpuArray) ─▶ 유실 수 출력
sys_enter_openat   ┘
```

**Tech Stack:** Phase 0과 동일 (Rust, aya 0.14 / aya-ebpf 0.2.1, tokio, WSL2 Ubuntu). 추가로 `aya-tool`(vmlinux 바인딩 생성, Task 6에서만).

**Docs:**
- Spec: [2026-09-22-ferrisentry-design.md](../specs/2026-09-22-ferrisentry-design.md) — 로드맵 7장 "1단계"
- 기획서: [PLANNING.md](../../../PLANNING.md) — Phase 1은 MVP 범위
- 진행 현황: [PROGRESS.md](../../../PROGRESS.md)
- 직전 plan: [Phase 0](2026-09-22-phase0-foundation.md)

## Global Constraints

- 모든 빌드/실행/테스트는 **WSL2 Ubuntu** 안에서 한다. 커밋도 같은 셸에서.
- eBPF 로드는 권한이 필요하다. 실행/통합테스트는 root(또는 sudo)로.
- 유닛 테스트는 cargo runner를 덮어쓴다: `cargo test --config 'target."cfg(all())".runner="env"'`
- **probe는 관찰만 한다. "이 행동이 위험한가" 판단은 Phase 2 룰 엔진의 일이다.** 이 plan에서 커널 쪽 필터를 넣는 유일한 이유는 이벤트 양 조절(`openat`)이며, 정책이 아니다.
- Phase 1 범위 밖: 룰 엔진, 알림, K8s/CRI 연동, Collector, 대시보드.
- 검증 환경(WSL)에는 컨테이너 런타임이 없다. 그래서 Task 7의 컨테이너 ID 추출은 **경로 파싱 유닛 테스트로 검증**하고, 실제 컨테이너 환경 확인은 Phase 3(kind 클러스터)으로 넘긴다.
- **각 Task를 끝낼 때마다 [PROGRESS.md](../../../PROGRESS.md)의 해당 행을 ✅로 바꾸고 같은 커밋에 포함한다.**

## 확인된 사실 (이 환경에서 직접 조회함, 2026-10-08)

| 항목 | 값 |
|---|---|
| 커널 | `6.6.87.2-microsoft-standard-WSL2` |
| BTF | `/sys/kernel/btf/vmlinux` 존재 → `aya-tool`로 `task_struct` 바인딩 생성 가능 |
| cgroup | v2 (`cgroup2fs`), WSL의 현재 경로는 `/init.scope` |
| tracepoint | `syscalls:sys_enter_connect`, `sys_enter_openat`, `sys_enter_setuid` 모두 존재 |
| `sys_enter_openat` 오프셋 | `dfd` 16, `filename` 24, `flags` 32, `mode` 40 |
| `sys_enter_connect` 오프셋 | `fd` 16, `uservaddr` 24, `addrlen` 32 |
| `sys_enter_setuid` 오프셋 | `uid` 16 |
| 테스트에 쓸 도구 | `python3`, `curl`, `su`, `touch` 모두 있음 |

[확실] 위 오프셋은 이 커널의 `/sys/kernel/tracing/events/.../format`에서 읽은 값이다.
[추정] 오프셋은 커널 버전/아키텍처마다 달라질 수 있다. 다른 커널에서 값이 틀리면 같은 파일을 다시 읽어 상수를 고친다.

---

### Task 1: 공용 Event 포맷으로 교체

**Files:**
- Modify: `ferrisentry-common/src/lib.rs`
- Modify: `ferrisentry-common/tests/exec_event_abi.rs` → 이름 유지, 내용 교체
- Modify: `ferrisentry-ebpf/src/main.rs`
- Modify: `ferrisentry/src/main.rs`

**Interfaces:**
- Produces: `Event`, `EventKind` 상수, `EVENTS` ring buffer — Task 2~6의 모든 probe가 이걸 쓴다.
- Produces: 유저스페이스 출력 포맷 `[<kind>] pid=<n> ppid=<n> uid=<n> comm=<name> cgroup=<id> <상세>` — 통합 테스트가 이 포맷을 grep한다.

- [ ] **Step 1: `ferrisentry-common/src/lib.rs`를 아래 내용으로 교체**

```rust
#![no_std]

pub const KIND_EXEC: u32 = 0;
pub const KIND_SETUID: u32 = 1;
pub const KIND_CONNECT: u32 = 2;
pub const KIND_OPENAT: u32 = 3;

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 128;

// ponytail: 네 종류 이벤트를 고정 크기 구조체 하나로 표현한다. 종류별로 안 쓰는 필드가
// 남지만(최대 176바이트 중 일부) 파싱 경로가 하나로 끝난다. 이벤트량이 많아져서
// ring buffer 대역폭이 문제가 되면 종류별 구조체로 쪼갠다.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub kind: u32,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    /// openat: flags, setuid: 대상 uid, 그 외: 0
    pub arg: u64,
    pub comm: [u8; COMM_LEN],
    /// openat: 열려는 경로. 그 외: 0
    pub path: [u8; PATH_LEN],
    /// connect: 목적지 IP (IPv4는 앞 4바이트). 그 외: 0
    pub addr: [u8; 16],
    /// connect: 목적지 포트 (host byte order로 변환해 저장)
    pub port: u16,
    /// connect: AF_INET(2) / AF_INET6(10)
    pub family: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}
```

- [ ] **Step 2: ABI 테스트를 Event 기준으로 교체 (`ferrisentry-common/tests/exec_event_abi.rs`)**

커널과 유저스페이스가 같은 바이트 레이아웃을 본다는 걸 고정한다. 크기 상수는 실제 컴파일 값을 확인해서 넣는다 (`cargo test` 실패 메시지에 실제 값이 나온다).

```rust
use core::mem::{align_of, size_of};

use ferrisentry_common::{Event, COMM_LEN, KIND_OPENAT, PATH_LEN};

#[test]
fn event_has_a_stable_kernel_userspace_abi() {
    assert_eq!(align_of::<Event>(), 8);
    assert_eq!(COMM_LEN, 16);
    assert_eq!(PATH_LEN, 128);
    // 레이아웃이 바뀌면 커널/유저스페이스 한쪽만 고치는 실수를 여기서 잡는다.
    assert_eq!(size_of::<Event>(), 200);
}

#[test]
fn path_is_nul_terminated_when_shorter_than_the_buffer() {
    let mut event = Event {
        kind: KIND_OPENAT,
        pid: 1,
        ppid: 1,
        uid: 0,
        cgroup_id: 0,
        arg: 0,
        comm: [0; COMM_LEN],
        path: [0; PATH_LEN],
        addr: [0; 16],
        port: 0,
        family: 0,
    };
    event.path[..4].copy_from_slice(b"/etc");

    assert_eq!(&event.path[..4], b"/etc");
    assert_eq!(event.path[4], 0);
}
```

- [ ] **Step 3: eBPF 쪽을 새 포맷으로 (`ferrisentry-ebpf/src/main.rs`)**

맵 이름을 `EXEC_EVENTS` → `EVENTS`로 바꾸고, 이벤트를 만드는 공통 함수를 하나 둔다. `ppid`/`cgroup_id`는 Task 6에서 채우므로 지금은 0.

```rust
#![no_std]
#![no_main]

use aya_ebpf::{
    cty::c_long,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use ferrisentry_common::{Event, COMM_LEN, KIND_EXEC, PATH_LEN};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// 모든 probe가 공유하는 기본 필드 채우기. ppid/cgroup_id는 Task 6에서 채운다.
fn base_event(kind: u32) -> Result<Event, c_long> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let comm = bpf_get_current_comm()?;

    Ok(Event {
        kind,
        pid,
        ppid: 0,
        uid,
        cgroup_id: 0,
        arg: 0,
        comm,
        path: [0; PATH_LEN],
        addr: [0; 16],
        port: 0,
        family: 0,
    })
}

/// ring buffer에 이벤트 하나 밀어넣기. 자리가 없으면 버린다 (Task 5에서 카운트).
fn emit(event: &Event) {
    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        entry.write(*event);
        entry.submit(0);
    }
}

#[tracepoint]
pub fn trace_exec(ctx: TracePointContext) -> u32 {
    let _ = &ctx;
    match base_event(KIND_EXEC) {
        Ok(event) => {
            emit(&event);
            0
        }
        Err(_) => 0,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
```

`COMM_LEN` import가 안 쓰이면 지운다 (경고 0을 유지).

- [ ] **Step 4: 유저스페이스 출력 포맷 (`ferrisentry/src/main.rs`)**

`take_map("EVENTS")`로 바꾸고, `format_event`를 종류별로 분기한다. 포맷 함수는 순수 함수로 두고 유닛 테스트를 붙인다 (커널 없이 검증되는 유일한 부분).

```rust
fn format_event(event: &Event) -> String {
    let kind = match event.kind {
        KIND_EXEC => "exec",
        KIND_SETUID => "setuid",
        KIND_CONNECT => "connect",
        KIND_OPENAT => "openat",
        _ => "unknown",
    };
    let comm = cstr(&event.comm);
    let detail = match event.kind {
        KIND_OPENAT => format!("path={} flags=0x{:x}", cstr(&event.path), event.arg),
        KIND_SETUID => format!("target_uid={}", event.arg),
        KIND_CONNECT => format!("dest={}", format_dest(event)),
        _ => String::new(),
    };

    format!(
        "[{}] pid={} ppid={} uid={} comm={} cgroup={} {}",
        kind, event.pid, event.ppid, event.uid, comm, event.cgroup_id, detail
    )
    .trim_end()
    .to_string()
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
```

`format_dest`는 Task 3에서 추가한다. 지금은 `String::new()`로 두거나 `KIND_CONNECT` 분기를 Task 3에서 넣는다.

- [ ] **Step 5: 기존 통합 테스트 문구 맞추기 (`tests/verify_execve_capture.sh`)**

grep 문구를 새 포맷에 맞춘다: `grep -q "\[exec\].*comm=echo"`.

- [ ] **Step 6: 빌드 + 테스트 + 통합 테스트**

```bash
cargo test --config 'target."cfg(all())".runner="env"'
sudo ./tests/verify_execve_capture.sh
```

Expected: 유닛 테스트 전부 통과, 통합 테스트 PASS.
`size_of::<Event>()` assert가 실패하면 메시지에 나온 실제 값으로 테스트 상수를 고친다 (구조체를 바꾸지 말 것).

- [ ] **Step 7: 커밋**

```bash
git add -A && git commit -m "refactor: replace ExecEvent with a shared Event format"
```

---

### Task 2: setuid probe

가장 단순한 probe부터 붙여서 "tracepoint 인자 읽기" 패턴을 만든다.

**Files:**
- Modify: `ferrisentry-ebpf/src/main.rs`
- Modify: `ferrisentry/src/main.rs` (attach 추가)
- Modify: `tests/verify_execve_capture.sh` → `tests/verify_probes.sh`로 이름 변경

**Interfaces:**
- Consumes: Task 1의 `Event`, `emit`, `base_event`
- Produces: `trace_setuid` 프로그램 (`syscalls:sys_enter_setuid`), 출력 `[setuid] ... target_uid=<n>`

- [ ] **Step 1: eBPF에 probe 추가**

```rust
const SETUID_UID_OFFSET: usize = 16; // /sys/kernel/tracing/events/syscalls/sys_enter_setuid/format

#[tracepoint]
pub fn trace_setuid(ctx: TracePointContext) -> u32 {
    match try_trace_setuid(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_trace_setuid(ctx: &TracePointContext) -> Result<u32, c_long> {
    let target_uid: u64 = unsafe { ctx.read_at(SETUID_UID_OFFSET) }.map_err(|e| e as c_long)?;
    let mut event = base_event(KIND_SETUID)?;
    event.arg = target_uid;
    emit(&event);
    Ok(0)
}
```

[추정] `read_at`은 `Result<T, i32>`를 돌려주므로 에러 타입 변환이 필요하다. 컴파일 에러가 나면 시그니처를 보고 맞춘다.

- [ ] **Step 2: 유저스페이스에서 attach**

프로그램이 여러 개가 되므로 attach를 헬퍼로 묶는다.

```rust
fn attach(ebpf: &mut Ebpf, name: &str, category: &str, event: &str) -> Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(name)
        .with_context(|| format!("{name} program not found"))?
        .try_into()?;
    program.load()?;
    program.attach(category, event)?;
    Ok(())
}
```

```rust
attach(&mut ebpf, "trace_exec", "sched", "sched_process_exec")?;
attach(&mut ebpf, "trace_setuid", "syscalls", "sys_enter_setuid")?;
```

- [ ] **Step 3: 통합 테스트를 probe별 케이스 구조로 바꾸기**

`tests/verify_execve_capture.sh`를 `tests/verify_probes.sh`로 옮기고(`git mv`), 에이전트를 한 번만 띄운 뒤 여러 동작을 실행해서 각각을 grep한다.

```bash
#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --release
sudo -v

LOG_FILE=$(mktemp)
sudo ./target/release/ferrisentry > "$LOG_FILE" 2>&1 &
AGENT_PID=$!
trap 'sudo kill "$AGENT_PID" 2>/dev/null || true; rm -f "$LOG_FILE"' EXIT

sleep 2

# --- 각 probe를 자극하는 동작 ---
/bin/echo "hello-ferrisentry-test" > /dev/null          # exec
sudo python3 -c 'import os; os.setuid(0)'               # setuid

sleep 1

FAILED=0
check() {  # check <설명> <grep 패턴>
    if grep -qE "$2" "$LOG_FILE"; then
        echo "PASS: $1"
    else
        echo "FAIL: $1 (패턴: $2)"
        FAILED=1
    fi
}

check "execve 캡처"  '\[exec\].*comm=echo'
check "setuid 캡처"  '\[setuid\].*target_uid=0'

if [ "$FAILED" -ne 0 ]; then
    echo "--- 에이전트 출력 ---"
    cat "$LOG_FILE"
    exit 1
fi
echo "ALL PASS"
```

- [ ] **Step 4: 실행 + 커밋**

```bash
chmod +x tests/verify_probes.sh && sudo ./tests/verify_probes.sh
git add -A && git commit -m "feat: add setuid tracepoint probe"
```

---

### Task 3: connect probe

**Files:**
- Modify: `ferrisentry-ebpf/src/main.rs`
- Modify: `ferrisentry/src/main.rs`
- Modify: `tests/verify_probes.sh`

**Interfaces:**
- Produces: `trace_connect` (`syscalls:sys_enter_connect`), 출력 `[connect] ... dest=<ip>:<port>`

- [ ] **Step 1: eBPF probe 추가**

`uservaddr`는 유저 공간 포인터이므로 `bpf_probe_read_user`로 읽는다. `sockaddr`의 앞 2바이트가 family, 그다음 2바이트가 포트(네트워크 바이트 오더), IPv4는 그 뒤 4바이트가 주소다.

```rust
const CONNECT_USERVADDR_OFFSET: usize = 24;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[tracepoint]
pub fn trace_connect(ctx: TracePointContext) -> u32 {
    match try_trace_connect(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_trace_connect(ctx: &TracePointContext) -> Result<u32, c_long> {
    let addr_ptr: u64 = unsafe { ctx.read_at(CONNECT_USERVADDR_OFFSET) }.map_err(|e| e as c_long)?;
    if addr_ptr == 0 {
        return Ok(0);
    }

    // sockaddr_in / sockaddr_in6의 앞 부분만 읽는다: family(2) + port(2) + addr
    let family: u16 = unsafe { bpf_probe_read_user(addr_ptr as *const u16) }?;
    if family != AF_INET && family != AF_INET6 {
        return Ok(0); // 유닉스 소켓 등은 Phase 1 관심 밖
    }
    let port_be: u16 = unsafe { bpf_probe_read_user((addr_ptr + 2) as *const u16) }?;

    let mut event = base_event(KIND_CONNECT)?;
    event.family = family;
    event.port = u16::from_be(port_be);

    if family == AF_INET {
        let v4: [u8; 4] = unsafe { bpf_probe_read_user((addr_ptr + 4) as *const [u8; 4]) }?;
        event.addr[..4].copy_from_slice(&v4);
    } else {
        // sockaddr_in6: family(2) + port(2) + flowinfo(4) + addr(16)
        let v6: [u8; 16] = unsafe { bpf_probe_read_user((addr_ptr + 8) as *const [u8; 16]) }?;
        event.addr.copy_from_slice(&v6);
    }

    emit(&event);
    Ok(0)
}
```

[추정] `sockaddr_in`/`sockaddr_in6` 레이아웃은 위와 같다 (`man 7 ip`, `man 7 ipv6`). 출력된 IP가 이상하면 오프셋을 먼저 의심한다.

- [ ] **Step 2: 유저스페이스 포맷 + attach**

```rust
fn format_dest(event: &Event) -> String {
    match event.family {
        2 => {
            let o = &event.addr[..4];
            format!("{}.{}.{}.{}:{}", o[0], o[1], o[2], o[3], event.port)
        }
        10 => {
            let mut parts = [0u16; 8];
            for (i, part) in parts.iter_mut().enumerate() {
                *part = u16::from_be_bytes([event.addr[i * 2], event.addr[i * 2 + 1]]);
            }
            let hex: Vec<String> = parts.iter().map(|p| format!("{p:x}")).collect();
            format!("[{}]:{}", hex.join(":"), event.port)
        }
        other => format!("family={other}"),
    }
}
```

```rust
attach(&mut ebpf, "trace_connect", "syscalls", "sys_enter_connect")?;
```

IPv6 축약(`::`)은 하지 않는다 — 읽을 수만 있으면 충분하고, 축약 로직은 버그만 늘린다.

- [ ] **Step 3: 포맷 유닛 테스트 추가**

```rust
#[test]
fn formats_an_ipv4_destination() {
    let mut event = /* KIND_CONNECT 이벤트 */;
    event.family = 2;
    event.addr[..4].copy_from_slice(&[127, 0, 0, 1]);
    event.port = 9;
    assert!(format_event(&event).contains("dest=127.0.0.1:9"));
}
```

- [ ] **Step 4: 통합 테스트 케이스 추가**

bash의 `/dev/tcp`를 쓰면 외부 도구 없이 connect를 일으킬 수 있다. 연결이 거부돼도 `connect` syscall은 호출된다.

```bash
(exec 3<>/dev/tcp/127.0.0.1/9) 2>/dev/null || true     # connect
```

```bash
check "connect 캡처" '\[connect\].*dest=127\.0\.0\.1:9'
```

- [ ] **Step 5: 실행 + 커밋**

```bash
sudo ./tests/verify_probes.sh
git add -A && git commit -m "feat: add connect tracepoint probe"
```

---

### Task 4: openat probe (쓰기 의도만)

**Files:**
- Modify: `ferrisentry-ebpf/src/main.rs`
- Modify: `ferrisentry/src/main.rs`
- Modify: `tests/verify_probes.sh`

**Interfaces:**
- Produces: `trace_openat` (`syscalls:sys_enter_openat`), 출력 `[openat] ... path=<경로> flags=0x<n>`

**왜 필터를 넣는가:** 프로세스 하나가 뜨고 지는 동안 `openat`은 수백 번 불린다. 전부 올리면 ring buffer가 넘치고(Task 5의 drop 급증) 정작 중요한 이벤트가 밀려난다. 그래서 **쓰기 의도가 있는 호출만** 커널에서 통과시킨다. 어떤 경로가 민감한지 판단하는 건 Phase 2 룰 엔진의 몫이다.

- [ ] **Step 1: eBPF probe 추가**

```rust
const OPENAT_FILENAME_OFFSET: usize = 24;
const OPENAT_FLAGS_OFFSET: usize = 32;

// 쓰기 의도 플래그 (asm-generic/fcntl.h)
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const WRITE_INTENT: u64 = O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND;

#[tracepoint]
pub fn trace_openat(ctx: TracePointContext) -> u32 {
    match try_trace_openat(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_trace_openat(ctx: &TracePointContext) -> Result<u32, c_long> {
    let flags: u64 = unsafe { ctx.read_at(OPENAT_FLAGS_OFFSET) }.map_err(|e| e as c_long)?;
    if flags & WRITE_INTENT == 0 {
        return Ok(0); // 읽기 전용 열기는 양이 너무 많아서 커널에서 끊는다
    }

    let filename_ptr: u64 = unsafe { ctx.read_at(OPENAT_FILENAME_OFFSET) }.map_err(|e| e as c_long)?;
    if filename_ptr == 0 {
        return Ok(0);
    }

    let mut event = base_event(KIND_OPENAT)?;
    event.arg = flags;
    // 경로가 PATH_LEN보다 길면 잘린다. ponytail: 잘린 경로는 Phase 2 규칙에서
    // 접두사 매칭으로 쓰기엔 충분하다. 전체 경로가 필요해지면 길이를 늘린다.
    unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.path) }?;

    emit(&event);
    Ok(0)
}
```

- [ ] **Step 2: attach 추가**

```rust
attach(&mut ebpf, "trace_openat", "syscalls", "sys_enter_openat")?;
```

- [ ] **Step 3: 통합 테스트 케이스 추가**

```bash
touch /tmp/ferrisentry-openat-test                      # openat (O_CREAT|O_WRONLY)
```

```bash
check "openat 캡처" '\[openat\].*path=/tmp/ferrisentry-openat-test'
```

읽기 전용 열기가 걸러지는지도 같이 본다 (필터가 살아 있는지 확인):

```bash
cat /etc/hostname > /dev/null
if grep -q 'path=/etc/hostname' "$LOG_FILE"; then
    echo "FAIL: 읽기 전용 openat이 필터를 통과했다"
    FAILED=1
else
    echo "PASS: 읽기 전용 openat 필터링"
fi
```

- [ ] **Step 4: 실행 + 커밋**

이 단계에서 출력량이 눈에 띄게 늘어난다. 평상시 `cargo build` 한 번만 돌려도 이벤트가 쏟아지면 필터가 제대로 걸렸는지 다시 본다.

```bash
sudo ./tests/verify_probes.sh
git add -A && git commit -m "feat: add openat probe limited to write-intent flags"
```

---

### Task 5: ring buffer 유실 카운터

스펙의 에러 처리 항목: "이벤트 유실 시 drop 카운트를 메트릭으로 노출 (조용히 삼키지 않음)".

**Files:**
- Modify: `ferrisentry-ebpf/src/main.rs`
- Modify: `ferrisentry/src/main.rs`

**Interfaces:**
- Produces: `DROPS` (`PerCpuArray<u64>`, 길이 1) — 유저스페이스가 주기적으로 합산해 출력

- [ ] **Step 1: eBPF 쪽에서 reserve 실패를 센다**

```rust
#[map]
static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

fn emit(event: &Event) {
    match EVENTS.reserve::<Event>(0) {
        Some(mut entry) => {
            entry.write(*event);
            entry.submit(0);
        }
        None => {
            if let Some(counter) = DROPS.get_ptr_mut(0) {
                unsafe { *counter += 1 };
            }
        }
    }
}
```

- [ ] **Step 2: 유저스페이스에서 주기적으로 출력**

10초마다, 지난번과 값이 다를 때만 한 줄 찍는다 (조용할 때 로그를 더럽히지 않는다).

```rust
let drops: PerCpuArray<_, u64> = PerCpuArray::try_from(
    ebpf.take_map("DROPS").context("DROPS map not found")?,
)?;
```

```rust
_ = report.tick() => {
    let total: u64 = drops.get(&0, 0)?.iter().sum();
    if total != last_reported {
        println!("[metric] dropped_events={total}");
        last_reported = total;
    }
}
```

[불확실] `PerCpuArray`의 유저스페이스 제네릭 인자 순서와 `get` 시그니처는 aya 0.14 문서를 확인할 것. 컴파일 에러 메시지가 정확한 형태를 알려준다.

- [ ] **Step 3: 동작 확인**

유실을 일부러 만들려면 이벤트를 쏟아붓는다.

```bash
sudo ./target/release/ferrisentry > /tmp/flood.log 2>&1 &
for i in $(seq 1 20000); do /bin/true; done
sleep 12
grep "dropped_events" /tmp/flood.log || echo "유실 없음 (버퍼가 충분함 — 정상)"
```

유실이 0이어도 실패가 아니다. 중요한 건 카운터 경로가 컴파일되고 출력된다는 것.

- [ ] **Step 4: 커밋**

```bash
git add -A && git commit -m "feat: count and report dropped ring buffer events"
```

---

### Task 6: ppid와 cgroup_id 채우기

**Files:**
- Create: `ferrisentry-ebpf/src/vmlinux.rs` (aya-tool 생성물)
- Modify: `ferrisentry-ebpf/src/main.rs`
- Modify: `docs/DEV_SETUP.md` (aya-tool 설치 추가)

**Interfaces:**
- Produces: 모든 이벤트의 `ppid`, `cgroup_id`가 0이 아닌 실제 값 — Task 7이 `cgroup_id`를 쓴다.

- [ ] **Step 1: aya-tool로 task_struct 바인딩 생성**

`task_struct`는 aya-ebpf 바인딩에 opaque(`_unused: [u8; 0]`)로만 들어 있어서 부모 PID를 읽을 수 없다. 커널 BTF에서 바인딩을 생성한다. 이 환경에는 `/sys/kernel/btf/vmlinux`가 있다.

```bash
cargo install --git https://github.com/aya-rs/aya -- aya-tool
aya-tool generate task_struct > ferrisentry-ebpf/src/vmlinux.rs
```

[불확실] `aya-tool` 설치 경로와 인자 형태는 버전에 따라 다를 수 있다. 실패하면 Aya 저장소 README의 현재 안내를 따른다. 생성이 끝나면 파일 상단에 "자동 생성물, 직접 수정 금지" 주석을 추가한다.

- [ ] **Step 2: ppid 읽기**

```rust
#[allow(dead_code, non_camel_case_types, non_snake_case)]
mod vmlinux;

use vmlinux::task_struct;

fn current_ppid() -> Result<u32, c_long> {
    let task = unsafe { bpf_get_current_task() } as *const task_struct;
    let parent = unsafe { bpf_probe_read_kernel(&(*task).real_parent)? };
    let ppid = unsafe { bpf_probe_read_kernel(&(*parent).tgid)? };
    Ok(ppid as u32)
}
```

- [ ] **Step 3: cgroup_id 읽기**

`bpf_get_current_cgroup_id`는 안전한 helpers에 없고 raw 바인딩에 있다.

```rust
use aya_ebpf::bindings::helpers::bpf_get_current_cgroup_id;

// base_event 안에서
cgroup_id: unsafe { bpf_get_current_cgroup_id() },
```

[추정] 경로는 `aya_ebpf::bindings::helpers` 또는 `aya_ebpf::helpers::gen`이다. 실제 모듈 경로는 `grep -rn bpf_get_current_cgroup_id ~/.cargo/registry/src/*/aya-ebpf-0.2.1/`로 확인한다.

- [ ] **Step 4: 검증 — 값이 실제로 채워지는지**

```bash
sudo ./tests/verify_probes.sh
```

통합 테스트에 체크를 하나 추가한다 (0이 아닌 값이 나오는지):

```bash
check "ppid/cgroup 채움" '\[exec\].*ppid=[1-9][0-9]* .*cgroup=[1-9][0-9]*'
```

- [ ] **Step 5: DEV_SETUP에 aya-tool 추가 + 커밋**

```bash
git add -A && git commit -m "feat: fill in ppid and cgroup id from the kernel"
```

---

### Task 7: cgroup_id → cgroup 경로/컨테이너 ID 매핑

**Files:**
- Create: `ferrisentry/src/cgroup.rs`
- Modify: `ferrisentry/src/main.rs`

**Interfaces:**
- Produces: `CgroupResolver::resolve(cgroup_id) -> Option<CgroupInfo { path, container_id }>` — Phase 3의 CRI 메타데이터 조회가 `container_id`를 입력으로 받는다.
- Produces: 출력에 `cgroup=<id>` 대신 `cgroup=<경로>` 또는 `container=<짧은 ID>`

**설계:** cgroup v2에서 cgroup ID는 해당 cgroup 디렉터리의 inode 번호다. 그래서 `/sys/fs/cgroup` 아래를 한 번 훑어 `inode → 경로` 맵을 만들어 두고 조회한다. 새 컨테이너가 뜨면 맵에 없으므로, 조회 실패 시 1회 재스캔한다.

[추정] "cgroup v2의 cgroup id = 디렉터리 inode"는 널리 쓰이는 전제다. 실제 값이 맞는지 Step 3에서 직접 확인한다.

- [ ] **Step 1: 경로 → 컨테이너 ID 파싱 (순수 함수, 테스트 가능)**

컨테이너 런타임별 cgroup 경로 패턴에서 64자 16진수 ID를 뽑는다.

```rust
/// cgroup 경로에서 컨테이너 ID(64자 hex)를 뽑는다. 컨테이너가 아니면 None.
/// 예: /kubepods/besteffort/pod<uid>/cri-containerd-<64hex>.scope
///     /docker/<64hex>
///     /system.slice/docker-<64hex>.scope
pub fn container_id_from_path(path: &str) -> Option<String> {
    path.rsplit('/').find_map(|segment| {
        let s = segment
            .trim_end_matches(".scope")
            .rsplit('-')
            .next()
            .unwrap_or(segment);
        (s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())).then(|| s.to_string())
    })
}
```

- [ ] **Step 2: 유닛 테스트 (컨테이너 런타임 없이 검증되는 부분)**

```rust
#[test]
fn extracts_container_ids_from_known_cgroup_layouts() {
    let id = "a".repeat(64);
    for path in [
        format!("/docker/{id}"),
        format!("/system.slice/docker-{id}.scope"),
        format!("/kubepods/besteffort/pod1234/cri-containerd-{id}.scope"),
    ] {
        assert_eq!(container_id_from_path(&path).as_deref(), Some(id.as_str()), "{path}");
    }
}

#[test]
fn ignores_paths_that_are_not_containers() {
    assert_eq!(container_id_from_path("/init.scope"), None);
    assert_eq!(container_id_from_path("/user.slice/user-1000.slice"), None);
}
```

- [ ] **Step 3: inode → 경로 스캔**

`std::fs::read_dir`로 `/sys/fs/cgroup`을 재귀 순회하며 디렉터리의 `ino()`를 모은다 (`std::os::unix::fs::MetadataExt`). 스캔 실패(권한 등)는 치명적이지 않으므로 경고만 남기고 ID를 그대로 출력한다.

직접 확인:

```bash
stat -c '%i %n' /sys/fs/cgroup/init.scope
sudo ./target/release/ferrisentry | head -5
```

출력된 `cgroup=` 값과 `stat`의 inode가 맞는지 눈으로 확인한다. 안 맞으면 전제가 틀린 것이므로 `cgroup_id` 대신 `/proc/<pid>/cgroup`을 읽는 방식으로 바꾼다 (프로세스가 이미 종료됐으면 실패하는 한계가 있음 — 이 경우 PROGRESS에 기록).

- [ ] **Step 4: 출력에 반영 + 커밋**

컨테이너면 `container=<앞 12자>`, 아니면 `cgroup=<경로>`로 찍는다.

```bash
cargo test --config 'target."cfg(all())".runner="env"'
sudo ./tests/verify_probes.sh
git add -A && git commit -m "feat: resolve cgroup ids to cgroup paths and container ids"
```

---

### Task 8: 문서 갱신

**Files:**
- Modify: `README.md`, `PROGRESS.md`, `docs/DEV_SETUP.md`

- [ ] **Step 1: README 현재 상태를 Phase 1로 갱신**

출력 예시를 네 종류 전부로 바꾸고, 실행/검증 명령을 `tests/verify_probes.sh`로 고친다.

- [ ] **Step 2: PROGRESS 갱신**

Phase 1 행 전부 ✅, "완료한 일"에 한 줄, "해야 할 일"의 맨 위를 "Phase 2 plan 작성"으로 교체, 현재 plan 링크를 Phase 2 plan으로 바꿀 준비.

- [ ] **Step 3: 커밋**

```bash
git add -A && git commit -m "docs: update README and PROGRESS for Phase 1"
```

---

## Phase 1 완료 기준

- [ ] `sudo ./tests/verify_probes.sh`가 `ALL PASS` — exec/setuid/connect/openat 네 종류 전부 캡처되고, 읽기 전용 openat은 필터링됨
- [ ] 모든 이벤트에 `ppid`와 cgroup 정보(경로 또는 컨테이너 ID)가 들어 있음
- [ ] `cargo test --config 'target."cfg(all())".runner="env"'` 전부 통과 (Event ABI, 출력 포맷, 컨테이너 ID 파싱)
- [ ] 이벤트 유실이 `[metric] dropped_events=<n>`으로 노출됨
- [ ] `cargo build` 경고 없음
- [ ] PROGRESS.md의 Phase 1 행이 전부 ✅, 다음 할 일이 "Phase 2 plan 작성"
