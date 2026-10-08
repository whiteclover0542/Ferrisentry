# Phase 0: Foundation (Rust + Aya eBPF Hello World) Implementation Plan

> **상태: 완료 (2026-09-25 구현, 2026-10-08 복구/병합).** Task 1~7 전부 구현·검증했습니다.
> 아래 체크박스는 작성 당시 그대로 남겨둔 기록이며, 실제 진행 상태는 [PROGRESS.md](../../../PROGRESS.md)를 보세요.
> 구현 중 plan과 달라진 점: `bpf-linker`는 `cargo-binstall`로 설치, aya-template 0.25는 `xtask/`를 만들지 않음,
> `cargo build`의 경고 grep은 aya build.rs가 진행 로그를 warning 채널로 흘려서 쓰지 않음.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up a working Rust + Aya development toolchain and prove the eBPF pipeline end-to-end: a kernel-side tracepoint program captures process-execution events and a userspace agent reads and prints them via a ring buffer.

**Architecture:** A three-crate Aya workspace (common / ebpf / userspace) generated via `aya-template`. The eBPF crate attaches a tracepoint to `sched:sched_process_exec`, packs an `ExecEvent { pid, comm }` struct, and pushes it into a `RingBuf` map. The userspace crate loads the compiled eBPF bytes, attaches the tracepoint, and polls the ring buffer in a loop, printing each event.

**Tech Stack:** Rust (stable + nightly), Aya / aya-ebpf, bpf-linker, cargo-generate (aya-template), tokio, WSL2 (Ubuntu) as the Linux kernel host since the dev machine is Windows.

**Docs:**
- Spec: [docs/superpowers/specs/2026-09-22-ferrisentry-design.md](../specs/2026-09-22-ferrisentry-design.md) — 로드맵 7장 "0단계" 구현
- 기획서: [PLANNING.md](../../../PLANNING.md) — Phase 0은 MVP 범위에 포함
- 진행 현황: [PROGRESS.md](../../../PROGRESS.md)

## Global Constraints

- eBPF requires a real Linux kernel — all build/run/test commands run **inside WSL2 (Ubuntu)**, never in native Windows PowerShell (Task 1 Step 1 제외).
- `RingBuf` map은 커널 5.8 이상 필요. Task 1 Step 2에서 확인.
- Language is Rust end-to-end (kernel + userspace).
- Running eBPF programs requires elevated privileges (`CAP_BPF`/root) — every run/test command uses `sudo`.
- **리포지토리 위치:** 이 plan은 Windows 경로(`/mnt/d/IT/git/PERSONAL/Ferrisentry`)에서 작업한다고 가정합니다. `/mnt/d`(DrvFs)는 cargo 빌드가 눈에 띄게 느립니다. Task 2 빌드가 너무 느리면 WSL 홈(`~/Ferrisentry`)으로 clone해서 VS Code "WSL" 원격 모드로 여는 방식으로 바꾸세요. 그 경우 아래 명령의 경로만 바꾸면 됩니다.
- **git은 한쪽에서만:** 같은 리포지토리를 Windows git과 WSL git으로 번갈아 커밋하면 줄바꿈/권한 비트 diff가 생깁니다. 커밋은 WSL 안에서만 하세요.
- This is Phase 0 only. Do not implement the rule engine, K8s integration, `ppid`/cgroup 조회, or additional probes (`connect`, `openat`, `setuid`) here — Phase 1 이후 plan에서 다룹니다.
- **각 Task를 끝낼 때마다 [PROGRESS.md](../../../PROGRESS.md)의 해당 행을 ✅로 바꾸고 "완료한 일"에 한 줄 추가한 뒤 같은 커밋에 포함합니다.**

---

### Task 1: WSL2 + Rust/eBPF 툴체인 설치

**Files:**
- Create: `docs/DEV_SETUP.md`

**Interfaces:**
- Produces: a working `wsl` shell with `cargo`, `rustc +nightly`, `bpf-linker`, `cargo-generate` on `PATH` — every later task's commands assume this shell.

- [ ] **Step 1: WSL2 + Ubuntu 설치 (Windows PowerShell에서, 관리자 권한)**

```powershell
wsl --install -d Ubuntu
wsl --update
```

재부팅이 필요할 수 있습니다. 재부팅 후 Ubuntu 앱을 실행해 Linux 사용자 계정을 만드세요. `wsl --update`는 WSL 커널을 최신으로 올립니다.

- [ ] **Step 2: 커널 버전 확인 (WSL Ubuntu 셸 안에서)**

```bash
uname -r
```

Expected: `5.15.x-microsoft-standard-WSL2` 이상 (최신 WSL은 `6.x`). **5.8 미만이면 RingBuf를 쓸 수 없으니 Step 1의 `wsl --update`부터 다시 하세요.** BPF 기능이 실제로 동작하는지는 Task 2 Step 2(템플릿 프로그램 로드)에서 최종 확인됩니다.

- [ ] **Step 3: 빌드 기본 도구 설치**

```bash
sudo apt update
sudo apt install -y build-essential pkg-config curl git
```

새로 설치한 Ubuntu에는 C 링커(`cc`)가 없어서, 이걸 빼먹으면 이후 모든 `cargo install`이 `linker 'cc' not found`로 실패합니다.

- [ ] **Step 4: Rust 설치 (stable + nightly, rust-src 포함)**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup toolchain install nightly --component rust-src
```

rustup 설치 스크립트가 stable을 기본으로 설치하므로 `rustup install stable`은 따로 필요 없습니다.

- [ ] **Step 5: bpf-linker, cargo-generate 설치**

```bash
cargo install bpf-linker
cargo install cargo-generate
```

`bpf-linker`는 LLVM 요구사항이 자주 바뀝니다. 설치가 실패하면 https://github.com/aya-rs/bpf-linker#installation 의 최신 안내를 따르세요 (LLVM 개발 패키지 선행 설치가 필요할 수 있음).

`bpftool`은 Phase 0에 필요 없으므로 설치하지 않습니다. 로드된 프로그램/맵을 들여다볼 필요가 생기면 그때 설치하세요.

- [ ] **Step 6: 전체 검증**

```bash
rustc +nightly --version
bpf-linker --version
cargo generate --version
```

Expected: 3개 명령 모두 버전 문자열 출력, 에러 없음.

- [ ] **Step 7: 문서화 + 커밋**

`docs/DEV_SETUP.md`:

```markdown
# 개발 환경 셋업 (WSL2)

eBPF는 Linux 커널 기능이라 Windows 네이티브에서 빌드/실행 불가. 모든 명령은 WSL2 Ubuntu 셸 안에서 실행.
커밋도 WSL 안에서만 한다 (Windows git과 섞지 않기).

## 설치
1. `wsl --install -d Ubuntu && wsl --update` (Windows PowerShell, 관리자 권한)
2. `uname -r` → 5.8 이상인지 확인 (RingBuf 요구사항)
3. `sudo apt install -y build-essential pkg-config curl git`
4. rustup 설치 후 `rustup toolchain install nightly --component rust-src`
5. `cargo install bpf-linker` (LLVM 요구사항: https://github.com/aya-rs/bpf-linker#installation)
6. `cargo install cargo-generate`

## 검증
`rustc +nightly --version && bpf-linker --version && cargo generate --version`
```

```bash
git add docs/DEV_SETUP.md PROGRESS.md
git commit -m "docs: add WSL2 dev environment setup guide"
```

---

### Task 2: aya-template으로 워크스페이스 스캐폴딩

**Files (template이 생성):**
- `ferrisentry-common/`, `ferrisentry-ebpf/`, `ferrisentry/` (Cargo 크레이트)
- `xtask/` (빌드 헬퍼, 템플릿 버전에 따라 없을 수 있음)
- `Cargo.toml` (워크스페이스 루트), `.gitignore` 등

**Interfaces:**
- Consumes: Task 1의 툴체인
- Produces: `cargo run` 가능한 tracepoint 프로그램 스캐폴드 — Task 3~5가 이 파일들의 내용을 채웁니다.

- [ ] **Step 1: 템플릿으로 프로젝트 생성**

```bash
cd /mnt/d/IT/git/PERSONAL/Ferrisentry
cargo generate --init --name ferrisentry \
  -d program_type=tracepoint \
  -d tracepoint_category=sched \
  -d tracepoint_name=sched_process_exec \
  https://github.com/aya-rs/aya-template
```

`--init`은 하위 폴더를 만들지 않고 현재 디렉터리에 바로 생성합니다. tracepoint category/name을 미리 넘기면 템플릿 기본 프로그램이 처음부터 우리가 쓸 tracepoint에 붙습니다. 그래도 프롬프트가 뜨면 같은 값(`sched`, `sched_process_exec`)을 입력하세요.

- [ ] **Step 2: 기본 스캐폴드가 빌드/실행되는지 확인**

```bash
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"'
```

Expected: 컴파일 성공 + 템플릿 기본 eBPF 프로그램이 로드/부착되고, 다른 셸에서 `ls` 등을 실행하면 로그가 출력됨. `Ctrl+C`로 종료.

**이 단계가 WSL2 커널의 BPF 지원을 실제로 검증하는 곳입니다.** 여기서 `Operation not permitted`/verifier 에러로 막히면 에러 메시지를 PROGRESS.md 보류/메모에 기록하고, Linux VM(Multipass 등)으로 바꾸는 것을 검토하세요.

- [ ] **Step 3: 템플릿 구조 기록**

Task 3~5는 템플릿 파일을 수정합니다. 수정 전에 아래를 확인하고 다르면 이후 Task의 경로/코드를 맞춰 고치세요:

```bash
ls
cat ferrisentry-ebpf/src/main.rs    # LICENSE 섹션, panic_handler 형태 확인
cat ferrisentry/src/main.rs         # Ebpf::load 경로(OUT_DIR 등), rlimit 처리 확인
cat ferrisentry-common/Cargo.toml   # user feature 존재 여부
```

- [ ] **Step 4: 커밋**

```bash
git status            # 생성된 파일 목록 확인. target/ 이 안 보이는지 확인 (.gitignore)
git add -A
git commit -m "chore: scaffold aya workspace via aya-template"
```

---

### Task 3: 공용 ExecEvent 구조체 정의

**Files:**
- Modify: `ferrisentry-common/src/lib.rs`
- Modify (필요 시): `ferrisentry-common/Cargo.toml`

**Interfaces:**
- Produces: `ExecEvent { pid: u32, comm: [u8; 16] }` — Task 4(eBPF)와 Task 5(userspace)가 이 타입을 그대로 가져다 씁니다.

`ppid`는 넣지 않습니다. `sched_process_exec` tracepoint 인자에 부모 PID가 없어서 `task_struct`를 따라가야 하는데, 그건 Phase 1(cgroup_id 추가할 때 같이) 작업입니다. 항상 0인 필드는 두지 않습니다.

- [ ] **Step 1: `ferrisentry-common/src/lib.rs`를 아래 내용으로 교체**

```rust
#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExecEvent {
    pub pid: u32,
    pub comm: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}
```

- [ ] **Step 2: `ferrisentry-common/Cargo.toml`에 `user` feature와 선택적 `aya` 의존성 확인**

템플릿에 이미 있으면 그대로 둡니다. 없으면 추가 (aya 버전은 워크스페이스 다른 크레이트와 맞출 것):

```toml
[dependencies]
aya = { workspace = true, optional = true }

[features]
user = ["dep:aya"]
```

루트 `Cargo.toml`에 `[workspace.dependencies] aya`가 없으면 `workspace = true` 대신 `ferrisentry/Cargo.toml`에 적힌 것과 같은 버전을 직접 적으세요.

- [ ] **Step 3: 양쪽 설정으로 컴파일 확인**

```bash
cargo check -p ferrisentry-common
cargo check -p ferrisentry-common --features user
```

Expected: 둘 다 에러 없이 통과 (no_std 빌드와 std+Pod 빌드 모두 성공).

- [ ] **Step 4: 커밋**

```bash
git add ferrisentry-common PROGRESS.md
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
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = bpf_get_current_comm()?;

    // ponytail: 버퍼가 가득 차면 이벤트를 조용히 버림. Phase 1에서 drop 카운터 맵 추가.
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

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
```

**`LICENSE` 섹션은 지우면 안 됩니다.** 커널은 GPL 호환 라이선스가 선언되지 않은 프로그램에 GPL 전용 helper 사용을 거부합니다. Task 2 Step 3에서 본 템플릿의 LICENSE/panic_handler 형태가 위와 다르면(예: `#[unsafe(link_section = ...)]` 문법) 템플릿 쪽 형태를 따르세요.

- [ ] **Step 2: 빌드 확인**

eBPF 크레이트는 유저스페이스 크레이트의 `build.rs`가 빌드합니다. 템플릿 방식을 그대로 따릅니다:

```bash
cargo build
```

Expected: 에러 없음. 템플릿에 `xtask`가 있고 README가 `cargo xtask build-ebpf`를 안내하면 그 명령을 쓰세요.

- [ ] **Step 3: 커밋**

```bash
git add ferrisentry-ebpf PROGRESS.md
git commit -m "feat: implement execve tracepoint probe"
```

---

### Task 5: 유저스페이스 에이전트 — 이벤트 로드/출력

**Files:**
- Modify: `ferrisentry/src/main.rs`
- Modify (필요 시): `ferrisentry/Cargo.toml`

**Interfaces:**
- Consumes: `ferrisentry_common::ExecEvent` (Task 3), `EXEC_EVENTS` map + `trace_exec` program (Task 4)
- Produces: 실행 시 stdout으로 `PID: <n> COMM: <name>` 라인을 출력하는 바이너리 — Task 6 검증 스크립트가 이 포맷을 grep합니다.

- [ ] **Step 1: `ferrisentry/src/main.rs`를 아래 내용으로 교체**

`Ebpf::load` 경로는 Task 2 Step 3에서 본 템플릿의 값을 그대로 쓰세요 (아래는 최근 템플릿 기준).

```rust
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

    // ponytail: 50ms 주기 polling. 이벤트량이 늘면 tokio AsyncFd로 ring buffer fd를 기다리는 방식으로 교체.
    let mut tick = time::interval(time::Duration::from_millis(50));
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => break,
            _ = tick.tick() => {
                while let Some(data) = ring_buf.next() {
                    if data.len() < std::mem::size_of::<ExecEvent>() {
                        continue;
                    }
                    let event: ExecEvent =
                        unsafe { std::ptr::read_unaligned(data.as_ptr() as *const ExecEvent) };
                    let comm = String::from_utf8_lossy(&event.comm);
                    println!("PID: {} COMM: {}", event.pid, comm.trim_end_matches('\0'));
                }
            }
        }
    }

    Ok(())
}
```

템플릿의 `aya_log` 초기화 코드는 빼도 됩니다 (Task 4에서 eBPF 쪽 로그 호출을 없앴으므로). 템플릿의 memlock rlimit 코드는 커널 5.11+에서는 필요 없지만, 있으면 그대로 둬도 무방합니다.

- [ ] **Step 2: 의존성 확인/추가**

템플릿에 이미 있는 것은 건너뜁니다:

```bash
cargo add -p ferrisentry tokio --features rt-multi-thread,macros,signal,time
cargo add -p ferrisentry anyhow log env_logger
```

- [ ] **Step 3: 빌드 + 경고 확인**

```bash
cargo build 2>&1 | tee /tmp/build.log
grep -E "^(warning|error)" /tmp/build.log || echo "clean"
```

Expected: 빌드 성공. 사용 안 하는 import(`aya_log` 등) 경고가 나오면 지우세요.

- [ ] **Step 4: 커밋**

```bash
git add ferrisentry Cargo.lock PROGRESS.md
git commit -m "feat: implement userspace loader and ring buffer reader"
```

---

### Task 6: 통합 검증 — 실제 프로세스 실행 캡처 확인

**Files:**
- Create: `tests/verify_execve_capture.sh`

**Interfaces:**
- Consumes: `ferrisentry` 바이너리 (Task 5)의 stdout 포맷 `PID: <n> COMM: <name>`

커널 연동 코드는 순수 단위 테스트가 불가능하므로, "빌드된 바이너리가 실제 프로세스 실행을 캡처하는가"를 Phase 0의 유일한 테스트로 둡니다.

- [ ] **Step 1: 검증 스크립트 작성**

`tests/verify_execve_capture.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --release

# 백그라운드 sudo는 비밀번호를 물을 수 없으므로 먼저 인증을 캐시해 둠
sudo -v

LOG_FILE=$(mktemp)
sudo ./target/release/ferrisentry > "$LOG_FILE" 2>&1 &
AGENT_PID=$!
trap 'sudo kill "$AGENT_PID" 2>/dev/null || true; rm -f "$LOG_FILE"' EXIT

# 에이전트가 tracepoint를 attach할 시간
sleep 2

# 캡처 대상 프로세스 실행 (절대경로 → 셸 builtin이 아닌 실제 exec)
/bin/echo "hello-ferrisentry-test" > /dev/null

# polling 주기(50ms)보다 넉넉히 대기
sleep 1

if grep -q "COMM: echo" "$LOG_FILE"; then
    echo "PASS: execve event captured for 'echo'"
else
    echo "FAIL: no execve event for 'echo' found in agent output:"
    cat "$LOG_FILE"
    exit 1
fi
```

- [ ] **Step 2: 실행**

```bash
chmod +x tests/verify_execve_capture.sh
./tests/verify_execve_capture.sh
```

Expected: `PASS: execve event captured for 'echo'`.

FAIL이면 확인할 것:
1. 출력에 로드/attach 에러가 있는지 (권한, verifier)
2. Task 4의 `trace_exec` / `EXEC_EVENTS` 이름과 Task 5의 `program_mut` / `take_map` 인자가 같은지
3. `attach("sched", "sched_process_exec")` 카테고리/이름 오타

- [ ] **Step 3: 커밋**

`/mnt/d`에서는 실행 권한 비트가 git에 안 잡힐 수 있으므로 명시적으로 기록합니다:

```bash
git add tests/verify_execve_capture.sh PROGRESS.md
git update-index --chmod=+x tests/verify_execve_capture.sh
git commit -m "test: add execve capture integration check"
```

---

### Task 7: README 작성

**Files:**
- Create: `README.md`

- [ ] **Step 1: 프로젝트 개요, 실행 방법, 현재 범위를 기록**

````markdown
# Ferrisentry

eBPF 기반 Kubernetes 런타임 보안 모니터링 도구 (Rust, via Aya). Falco/Tetragon과 같은
카테고리의 학습/포트폴리오 프로젝트입니다.

- 기획서: [PLANNING.md](PLANNING.md)
- 설계 문서: [docs/superpowers/specs/2026-09-22-ferrisentry-design.md](docs/superpowers/specs/2026-09-22-ferrisentry-design.md)
- 진행 현황: [PROGRESS.md](PROGRESS.md)

## 현재 상태: Phase 0 (Foundation)

`sched_process_exec` tracepoint로 프로세스 실행을 캡처해 PID/프로세스명을
콘솔에 출력하는 hello-world 단계입니다. 룰 엔진, K8s 연동, 대시보드는 아직 없습니다.

## 개발 환경

eBPF는 Linux 커널 기능이라 WSL2(Ubuntu) 안에서 빌드/실행합니다.
셋업: [docs/DEV_SETUP.md](docs/DEV_SETUP.md)

## 실행

```bash
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"'
```

## 검증

```bash
./tests/verify_execve_capture.sh
```
````

- [ ] **Step 2: 커밋**

```bash
git add README.md PROGRESS.md
git commit -m "docs: add project README"
```

---

## Phase 0 완료 기준

- [ ] `./tests/verify_execve_capture.sh`가 PASS
- [ ] `cargo build` 경고 없음
- [ ] `docs/DEV_SETUP.md`만 보고 새 WSL 환경에서 재현 가능
- [ ] PROGRESS.md의 Phase 0 행이 전부 ✅, 다음 할 일에 "Phase 1 plan 작성"이 올라가 있음
