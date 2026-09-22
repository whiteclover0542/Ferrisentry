# Phase 0: Foundation (Rust + Aya eBPF Hello World) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up a working Rust + Aya development toolchain and prove the eBPF pipeline end-to-end: a kernel-side tracepoint program captures process-execution events and a userspace agent reads and prints them via a ring buffer.

**Architecture:** A three-crate Aya workspace (common / ebpf / userspace) generated via `aya-template`. The eBPF crate attaches a tracepoint to `sched:sched_process_exec`, packs a `ExecEvent { pid, ppid, comm }` struct, and pushes it into a `RingBuf` map. The userspace crate loads the compiled eBPF bytes, attaches the tracepoint, and polls the ring buffer in a loop, printing each event.

**Tech Stack:** Rust (stable + nightly), Aya / aya-ebpf / aya-log, bpf-linker, cargo-generate (aya-template), tokio, WSL2 (Ubuntu) as the Linux kernel host since the dev machine is Windows.

**Spec:** [docs/superpowers/specs/2026-09-22-ferrisentry-design.md](../specs/2026-09-22-ferrisentry-design.md) — this plan implements the "0단계" row of the roadmap in section 7 (Rust 기초 + Aya로 eBPF hello-world).

## Global Constraints

- eBPF requires a real Linux kernel — all build/run/test commands in this plan run **inside WSL2 (Ubuntu)**, never in native Windows PowerShell.
- Language is Rust end-to-end (kernel + userspace), per spec section "언어: Rust (via Aya)".
- Running eBPF programs requires elevated privileges (`CAP_BPF`/root) — every run/test command uses `sudo`.
- This is Phase 0 only. Do not implement the rule engine, K8s integration, or additional probes (`connect`, `openat`, `setuid`) here — those are separate future plans per the spec's phased roadmap.

---

### Task 1: WSL2 + Rust/eBPF 툴체인 설치

**Files:**
- Create: `docs/DEV_SETUP.md`

**Interfaces:**
- Produces: a working `wsl` shell with `cargo`, `rustc +nightly`, `bpf-linker`, `cargo-generate`, `bpftool` all on `PATH` — every later task's commands assume this shell.

- [ ] **Step 1: WSL2 + Ubuntu 설치 (Windows PowerShell에서, 관리자 권한)**

```powershell
wsl --install -d Ubuntu
```

설치 후 재부팅이 필요할 수 있습니다. 재부팅 후 Ubuntu 앱을 실행해 Linux 사용자 계정을 만드세요.

- [ ] **Step 2: WSL2 커널이 eBPF를 지원하는지 확인 (WSL Ubuntu 셸 안에서)**

```bash
uname -r
zcat /proc/config.gz 2>/dev/null | grep CONFIG_BPF || echo "config.gz 없음 - 아래 bpftool로 재확인"
```

Expected: 커널 버전이 출력되고(예: `5.15.x-microsoft-standard-WSL2`), WSL2는 기본적으로 BPF를 지원하는 커널을 사용합니다.

- [ ] **Step 3: Rust 설치 (stable + nightly, rust-src 포함)**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup install stable
rustup toolchain install nightly --component rust-src
```

- [ ] **Step 4: bpf-linker 설치**

```bash
cargo install bpf-linker
```

[불확실] `bpf-linker`는 LLVM 버전 요구사항이 자주 바뀌므로, 설치 실패 시 https://github.com/aya-rs/bpf-linker#installation 의 최신 안내를 따르세요 (예: `sudo apt install llvm-19-dev` 류의 LLVM 패키지가 선행 설치로 필요할 수 있습니다).

- [ ] **Step 5: cargo-generate, bpftool 설치**

```bash
cargo install cargo-generate
sudo apt update && sudo apt install -y bpftool
```

- [ ] **Step 6: 전체 검증**

```bash
rustc +nightly --version
bpf-linker --version
cargo generate --version
bpftool version
```

Expected: 4개 명령 모두 버전 문자열 출력, 에러 없음.

- [ ] **Step 7: 문서화 + 커밋**

`docs/DEV_SETUP.md` 파일에 아래 내용을 기록합니다 (다음에 새 머신에서 셋업할 때 재사용):

```markdown
# 개발 환경 셋업 (WSL2)

eBPF는 Linux 커널 기능이라 Windows 네이티브에서 빌드/실행 불가. 모든 명령은 WSL2 Ubuntu 셸 안에서 실행.

## 설치
1. `wsl --install -d Ubuntu` (Windows PowerShell, 관리자 권한)
2. `rustup install stable && rustup toolchain install nightly --component rust-src`
3. `cargo install bpf-linker` (LLVM 요구사항: https://github.com/aya-rs/bpf-linker#installation)
4. `cargo install cargo-generate`
5. `sudo apt install -y bpftool`

## 검증
`rustc +nightly --version && bpf-linker --version && cargo generate --version && bpftool version`
```

```bash
git add docs/DEV_SETUP.md
git commit -m "docs: add WSL2 dev environment setup guide"
```

---

### Task 2: aya-template으로 워크스페이스 스캐폴딩

**Files:**
- Create: `ferrisentry-common/` (Cargo 크레이트, template이 생성)
- Create: `ferrisentry-ebpf/` (Cargo 크레이트, template이 생성)
- Create: `ferrisentry/` (Cargo 크레이트, template이 생성)
- Create: `xtask/` (빌드 헬퍼, template이 생성)
- Create: `Cargo.toml` (워크스페이스 루트, template이 생성)

**Interfaces:**
- Consumes: Task 1의 툴체인
- Produces: `cargo run` 가능한 빈 tracepoint 프로그램 스캐폴드 — Task 3~5가 이 파일들의 내용을 채웁니다.

- [ ] **Step 1: 템플릿으로 프로젝트 생성**

리포지토리 루트(`D:\IT\git\PERSONAL\Ferrisentry`, WSL 경로로는 `/mnt/d/IT/git/PERSONAL/Ferrisentry`)에서:

```bash
cd /mnt/d/IT/git/PERSONAL/Ferrisentry
cargo generate -d program_type=tracepoint --name ferrisentry --init https://github.com/aya-rs/aya-template
```

`--init`은 새 하위 폴더를 만들지 않고 현재 디렉터리에 바로 생성합니다. 추가로 tracepoint category/name을 묻는 프롬프트가 나오면 아무 값이나 입력해도 됩니다 (Task 4에서 tracepoint 핸들러 코드를 전부 새로 작성하므로 템플릿 기본값은 버려집니다).

- [ ] **Step 2: 기본 스캐폴드가 빌드/실행되는지 확인**

```bash
cd /mnt/d/IT/git/PERSONAL/Ferrisentry
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"'
```

Expected: 컴파일 성공 + 템플릿 기본 eBPF 프로그램이 로드/부착되었다는 로그 출력. `Ctrl+C`로 종료.

- [ ] **Step 3: 커밋**

```bash
git add ferrisentry-common ferrisentry-ebpf ferrisentry xtask Cargo.toml Cargo.lock .cargo 2>/dev/null
git commit -m "chore: scaffold aya workspace via aya-template"
```

---

### Task 3: 공용 ExecEvent 구조체 정의

**Files:**
- Modify: `ferrisentry-common/src/lib.rs`

**Interfaces:**
- Produces: `ExecEvent { pid: u32, ppid: u32, comm: [u8; 16] }` — Task 4(eBPF)와 Task 5(userspace)가 이 타입을 그대로 가져다 씁니다.

- [ ] **Step 1: `ferrisentry-common/src/lib.rs`를 아래 내용으로 교체**

```rust
#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub comm: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}
```

- [ ] **Step 2: `ferrisentry-common/Cargo.toml`에 `user` feature와 선택적 `aya` 의존성이 있는지 확인, 없으면 추가**

```toml
[dependencies]
aya = { version = "0.13", optional = true }

[features]
user = ["dep:aya"]
```

- [ ] **Step 3: 양쪽 타겟으로 컴파일 확인**

```bash
cargo check -p ferrisentry-common
cargo check -p ferrisentry-common --features user
```

Expected: 둘 다 에러 없이 통과 (no_std 빌드와 std+Pod 빌드 모두 성공).

- [ ] **Step 4: 커밋**

```bash
git add ferrisentry-common
git commit -m "feat: define shared ExecEvent struct"
```

---

### Task 4: eBPF tracepoint 프로그램 — execve 캡처

**Files:**
- Modify: `ferrisentry-ebpf/src/main.rs`

**Interfaces:**
- Consumes: `ferrisentry_common::ExecEvent` (Task 3)
- Produces: `EXEC_EVENTS` RingBuf map, `trace_exec` tracepoint 함수 — Task 5가 이 맵 이름과 프로그램 이름으로 attach합니다.

- [ ] **Step 1: `ferrisentry-ebpf/src/main.rs`를 아래 내용으로 교체**

```rust
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
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let comm = bpf_get_current_comm()?;

    if let Some(mut entry) = EXEC_EVENTS.reserve::<ExecEvent>(0) {
        entry.write(ExecEvent {
            pid,
            ppid: 0,
            comm,
        });
        entry.submit(0);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

`ppid`는 Phase 0에서는 0으로 고정합니다 (`task_struct` 워크을 통한 부모 PID 조회는 별도 probe 확장 단계에서 추가 — 스펙 범위 밖).

- [ ] **Step 2: eBPF 크레이트 빌드 확인**

```bash
cargo build -p ferrisentry-ebpf --release
```

Expected: BPF 타겟(`bpfel-unknown-none`)으로 컴파일 성공, verifier 관련 에러 없음.

- [ ] **Step 3: 커밋**

```bash
git add ferrisentry-ebpf
git commit -m "feat: implement execve tracepoint probe"
```

---

### Task 5: 유저스페이스 에이전트 — 이벤트 로드/출력

**Files:**
- Modify: `ferrisentry/src/main.rs`

**Interfaces:**
- Consumes: `ferrisentry_common::ExecEvent` (Task 3), `EXEC_EVENTS` map + `trace_exec` program (Task 4)
- Produces: 실행 시 stdout으로 `PID: <n> COMM: <name>` 라인을 출력하는 바이너리 — Task 6의 통합 검증 스크립트가 이 출력 포맷을 grep합니다.

- [ ] **Step 1: `ferrisentry/src/main.rs`를 아래 내용으로 교체**

```rust
use anyhow::{Context, Result};
use aya::{include_bytes_aligned, maps::RingBuf, programs::TracePoint, Ebpf};
use ferrisentry_common::ExecEvent;
use log::info;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ferrisentry"
    )))?;

    let program: &mut TracePoint = ebpf.program_mut("trace_exec").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    let mut ring_buf = RingBuf::try_from(
        ebpf.take_map("EXEC_EVENTS")
            .context("EXEC_EVENTS map not found")?,
    )?;

    info!("Monitoring process execution... (Ctrl+C to stop)");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => break,
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(50)) => {
                while let Some(data) = ring_buf.next() {
                    if data.len() >= std::mem::size_of::<ExecEvent>() {
                        let event: ExecEvent = unsafe {
                            std::ptr::read_unaligned(data.as_ptr() as *const ExecEvent)
                        };
                        let comm = String::from_utf8_lossy(&event.comm);
                        let comm = comm.trim_end_matches('\0');
                        println!("PID: {} COMM: {}", event.pid, comm);
                    }
                }
            }
        }
    }

    Ok(())
}
```

- [ ] **Step 2: 필요한 의존성 확인/추가 (`ferrisentry/Cargo.toml`)**

```bash
cd ferrisentry
cargo add tokio --features rt-multi-thread,macros,signal,time
cargo add anyhow log env_logger
cd ..
```

- [ ] **Step 3: 빌드 확인**

```bash
cargo build
```

Expected: 워크스페이스 전체 빌드 성공.

- [ ] **Step 4: 커밋**

```bash
git add ferrisentry
git commit -m "feat: implement userspace loader and ring buffer reader"
```

---

### Task 6: 통합 검증 — 실제 프로세스 실행 캡처 확인

**Files:**
- Create: `tests/verify_execve_capture.sh`

**Interfaces:**
- Consumes: `ferrisentry` 바이너리 (Task 5)의 stdout 포맷 `PID: <n> COMM: <name>`

- [ ] **Step 1: 검증 스크립트 작성 (먼저 실패하는 걸 확인할 목적 없이 바로 통과 조건을 정의 — 커널 연동 코드는 순수 단위테스트가 불가능하므로, "빌드된 바이너리가 실제 프로세스 실행을 캡처하는가"를 유일한 통합 테스트로 둡니다)**

`tests/verify_execve_capture.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --release

LOG_FILE=$(mktemp)
sudo ./target/release/ferrisentry > "$LOG_FILE" 2>&1 &
AGENT_PID=$!

# 에이전트가 tracepoint를 attach할 시간을 줌
sleep 2

# 캡처 대상 프로세스 실행
/bin/echo "hello-ferrisentry-test" > /dev/null

# 링버퍼 poll 주기(50ms)보다 넉넉히 대기
sleep 1

sudo kill "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true

if grep -q "COMM: echo" "$LOG_FILE"; then
    echo "PASS: execve event captured for 'echo'"
    rm -f "$LOG_FILE"
    exit 0
else
    echo "FAIL: no execve event for 'echo' found in agent output:"
    cat "$LOG_FILE"
    rm -f "$LOG_FILE"
    exit 1
fi
```

- [ ] **Step 2: 실행 권한 부여 및 최초 실행 (통과해야 함 — Task 4/5 구현이 맞았는지 검증)**

```bash
chmod +x tests/verify_execve_capture.sh
./tests/verify_execve_capture.sh
```

Expected: `PASS: execve event captured for 'echo'` 출력. FAIL이 나오면 Task 4의 tracepoint 이름(`sched`/`sched_process_exec`)과 Task 5의 `program_mut("trace_exec")` 이름이 서로 일치하는지, `EXEC_EVENTS` 맵 이름이 양쪽에서 동일한지 확인.

- [ ] **Step 3: 커밋**

```bash
git add tests/verify_execve_capture.sh
git commit -m "test: add execve capture integration check"
```

---

### Task 7: README 작성

**Files:**
- Create: `README.md`

- [ ] **Step 1: 프로젝트 개요, 실행 방법, 현재 범위를 기록**

```markdown
# Ferrisentry

eBPF 기반 Kubernetes 런타임 보안 모니터링 도구 (Rust, via Aya). Falco/Tetragon과 같은
카테고리의 학습/포트폴리오 프로젝트입니다.

설계 문서: [docs/superpowers/specs/2026-09-22-ferrisentry-design.md](docs/superpowers/specs/2026-09-22-ferrisentry-design.md)

## 현재 상태: Phase 0 (Foundation)

`execve` 계열 syscall(`sched_process_exec` tracepoint)을 캡처해 PID/프로세스명을
콘솔에 출력하는 hello-world 단계입니다. 룰 엔진, K8s 연동, 대시보드는 아직 없습니다.

## 개발 환경

eBPF는 Linux 커널 기능이라 WSL2(Ubuntu) 안에서 빌드/실행합니다.
셋업: [docs/DEV_SETUP.md](docs/DEV_SETUP.md)

## 실행

\`\`\`bash
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"'
\`\`\`

## 검증

\`\`\`bash
./tests/verify_execve_capture.sh
\`\`\`
```

- [ ] **Step 2: 커밋**

```bash
git add README.md
git commit -m "docs: add project README"
```
