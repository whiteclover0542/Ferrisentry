# Ferrisentry

eBPF 기반 Kubernetes 런타임 보안 모니터링 도구 (Rust, via Aya). 컨테이너 안에서 일어나는
syscall을 커널 레벨에서 관찰해 위험 행동을 탐지하는 것이 목표입니다.
Falco/Tetragon과 같은 카테고리의 학습/포트폴리오 프로젝트입니다.

- 기획서: [PLANNING.md](PLANNING.md)
- 설계 문서: [docs/superpowers/specs/2026-09-22-ferrisentry-design.md](docs/superpowers/specs/2026-09-22-ferrisentry-design.md)
- 진행 현황: [PROGRESS.md](PROGRESS.md)
- 용어집: [docs/GLOSSARY.md](docs/GLOSSARY.md) — 문서에 나오는 eBPF/Kubernetes/보안 용어 설명

## 현재 상태: Phase 0 (Foundation) 완료

`sched:sched_process_exec` tracepoint에 붙어서 프로세스 실행을 캡처하고, PID와 프로세스명을
ring buffer로 유저스페이스에 전달해 출력합니다.

```text
PID: 1234 COMM: bash
```

룰 엔진, 추가 probe(`connect`/`openat`/`setuid`), Kubernetes 메타데이터 연동, 알림은
Phase 1 이후 범위입니다.

## 개발 환경

eBPF는 Linux 커널 기능이라 Ubuntu WSL2(또는 다른 Linux 호스트) 안에서 빌드/실행합니다.
Windows PowerShell에서는 빌드되지 않습니다.

셋업 방법: [docs/DEV_SETUP.md](docs/DEV_SETUP.md)

## 실행

WSL Ubuntu 셸에서:

```bash
cargo build --release
sudo ./target/release/ferrisentry
```

`Ctrl+C`를 누를 때까지 계속 실행됩니다. 다른 셸에서 `/bin/echo hello` 같은 외부 프로그램을
실행하면 이벤트가 출력됩니다.

## 검증

```bash
./tests/verify_execve_capture.sh
```

릴리스 바이너리를 빌드하고, 권한을 올려 실행한 뒤 `/bin/echo`를 띄워서 아래 출력을 확인합니다.

```text
PASS: execve event captured for 'echo'
```

유닛 테스트는 eBPF 로더를 거치지 않으므로 sudo 없이 돌립니다.

```bash
cargo test --config 'target."cfg(all())".runner="env"'
```

## 라이선스

eBPF 코드를 제외한 부분은 [MIT 라이선스](LICENSE-MIT) 또는
[Apache 라이선스](LICENSE-APACHE) 중 선택해 사용할 수 있습니다.
eBPF 코드는 [GNU GPL v2](LICENSE-GPL2) 또는 MIT 라이선스를 따릅니다.
