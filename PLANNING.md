# Ferrisentry 기획서

- 작성일: 2026-09-22
- 상세 설계: [docs/superpowers/specs/2026-09-22-ferrisentry-design.md](docs/superpowers/specs/2026-09-22-ferrisentry-design.md)
- 진행 현황: [PROGRESS.md](PROGRESS.md)

## 1. 한 줄 소개

eBPF로 컨테이너 안에서 일어나는 syscall을 커널 레벨에서 관찰해, 리버스쉘·권한 상승·민감 파일 쓰기·비정상 아웃바운드 연결을 실시간으로 탐지하는 Kubernetes 런타임 보안 도구. Rust로 커널/유저스페이스 전부 작성 (Aya).

## 2. 배경 & 목적

| 구분 | 내용 |
|---|---|
| 목적 | 보안 포트폴리오 + eBPF/Rust 학습 |
| 카테고리 | 런타임 보안 (Falco, Tetragon과 같은 영역) |
| 차별점 | 100% Rust(eBPF 포함, Aya), 위협 모델 문서화, 공격 시뮬레이션 기반 탐지율 검증, n8n 연동 SOAR 데모 |
| 투입 | 주 30시간, 총 12~14주 |

상용 수준의 대체재를 만드는 게 아니라, **"커널 이벤트 → 탐지 → 대응"을 처음부터 끝까지 직접 구현해 봤다**는 걸 보여주는 게 핵심입니다.

## 3. 핵심 기능

1. **syscall 관찰**: `execve`, `connect`, `openat`, `setuid`를 tracepoint/kprobe로 후킹하고 ring buffer로 전달
2. **컨테이너 컨텍스트 붙이기**: cgroup ID → 컨테이너 → Pod/네임스페이스/이미지 (CRI API)
3. **룰 엔진**: Falco 스타일 YAML 규칙
4. **알림**: Webhook/Slack → 중앙 Collector (gRPC)
5. **대시보드**: 실시간 이벤트 타임라인, 정책 관리
6. **자동 대응 (선택)**: n8n 웹훅으로 Pod 격리, 티켓 생성, IP 평판 조회

## 4. MVP

### 4.1 MVP 정의

> **kind 클러스터에 DaemonSet으로 배포한 에이전트가, 공격 시뮬레이션 Pod의 위험 행동 3종을 탐지해서 Pod 이름이 담긴 알림을 Slack/Webhook으로 보낸다.**

"탐지가 실제로 된다"는 걸 증명하는 가장 작은 범위입니다. 중앙 Collector와 대시보드 없이 에이전트 하나로 완결됩니다.

### 4.2 MVP 포함 범위

| 영역 | MVP에 포함 | 로드맵 단계 |
|---|---|---|
| eBPF probe | `execve`, `openat`, `setuid` (+ 가능하면 `connect`) | Phase 0~1 |
| 이벤트 파이프라인 | ring buffer → 유저스페이스, 이벤트 유실 수 카운트 | Phase 1 |
| 컨테이너 매핑 | cgroup ID → 컨테이너 ID → Pod/네임스페이스 | Phase 1, 3 |
| 룰 엔진 | YAML 로드 + 매칭, 규칙 3개 | Phase 2 |
| 초기 규칙 | ① 컨테이너 내부 인터랙티브 쉘 실행 ② `/etc`, `/root/.ssh` 쓰기 ③ `setuid(0)` | Phase 2 |
| 알림 | stdout JSON + Webhook 1개 (Slack incoming webhook) | Phase 2~3 |
| 배포 | DaemonSet 매니페스트 (최소 권한 capability) | Phase 3 |
| 검증 | 공격 시뮬레이션 Pod 3종 + 탐지 확인 스크립트 | Phase 3 |

### 4.3 MVP 제외 (MVP 이후 진행)

- 중앙 Collector, gRPC, 저장소 (SQLite/Postgres)
- 정책 CRD, Helm 차트 (MVP는 plain YAML 매니페스트로 충분)
- 웹 대시보드
- n8n 연동
- 아웃바운드 IP 허용목록 규칙, 크립토마이너 패턴 규칙
- 성능 벤치마크

### 4.4 MVP 완료 기준

- [ ] `kubectl apply` 한 번으로 kind 클러스터에 에이전트 배포
- [ ] 공격 시뮬레이션 Pod 3종 각각에 대해 알림 1건 이상 발생 (탐지율 3/3)
- [ ] 알림에 Pod 이름, 네임스페이스, 프로세스명, 매칭된 규칙 이름이 들어 있음
- [ ] 평상시 시스템 Pod(kube-system)에서는 오탐 알림이 나오지 않음
- [ ] README에 데모 GIF + 실행 방법

### 4.5 MVP 일정

Phase 0~3 + 알림 최소 구현 → **약 7~9주** (주 30시간 기준).

## 5. 아키텍처 요약

```
[노드] eBPF probe ──ring buf──▶ Rust agent (enrich + 룰 엔진) ──▶ 알림
                                        │  (MVP 이후)
                                        ▼ gRPC
                               중앙 Collector ──▶ 대시보드 / n8n
```

자세한 구조, 데이터 흐름, 에러 처리는 [설계 문서](docs/superpowers/specs/2026-09-22-ferrisentry-design.md) 2~5장 참고.

## 6. 기술 스택

| 영역 | 선택 |
|---|---|
| 언어 | Rust (stable + nightly, eBPF 빌드에 nightly 필요) |
| eBPF | Aya / aya-ebpf, bpf-linker |
| 비동기 런타임 | tokio |
| 규칙 포맷 | YAML (serde) |
| 배포 | Kubernetes DaemonSet (MVP) → Helm (MVP 이후) |
| 개발 환경 | Windows + WSL2 Ubuntu (eBPF가 Linux 커널 기능이라서) |
| 테스트 클러스터 | kind |

## 7. 로드맵

| 단계 | 기간 | 내용 | MVP |
|---|---|---|---|
| 0 | 1~2주 | 툴체인 + Aya로 execve hello-world | ✔ |
| 1 | 2~3주 | 핵심 probe 4종 + ring buffer 파이프라인 + cgroup→컨테이너 매핑 | ✔ |
| 2 | 2주 | 룰 엔진 + 초기 규칙셋 + stdout/Webhook 알림 | ✔ |
| 3 | 2주 | K8s 연동 (DaemonSet, CRI 메타데이터) + 공격 시뮬레이션 | ✔ (Helm 제외) |
| 4 | 2주 | 중앙 Collector + gRPC + Slack 라우팅 + n8n(선택) | |
| 5 | 2주 | 웹 대시보드 | |
| 6 | 1~2주 | 벤치마크, 위협 모델 문서, 데모 영상, 블로그 글 | |

## 8. 리스크 & 대응

| 리스크 | 영향 | 대응 |
|---|---|---|
| WSL2 커널의 eBPF 기능 제약 | Phase 0 막힘 | Task 1에서 가장 먼저 확인. 안 되면 Linux VM(Multipass/Hyper-V)으로 전환 |
| Aya/bpf-linker 버전 변화 | 빌드 실패 | aya-template 최신 버전 기준으로 진행, 버전 고정 |
| verifier 거부 | probe 로드 실패 | probe 비활성화 + 헬스체크 실패로 degrade (크래시 대신) |
| kind 노드 안에서 eBPF 동작 | Phase 3 막힘 | kind 노드는 호스트 커널을 공유하므로 privileged DaemonSet으로 확인. 안 되면 minikube(VM driver)로 전환 |
| 일정 초과 | 포트폴리오 완성 지연 | MVP를 먼저 끝내고, Phase 4~6은 줄여도 되는 범위로 둠 |
| 에이전트 자체가 공격 표면 | 보안 도구가 취약점이 됨 | 필요한 capability만, 읽기 전용 rootfs, seccomp. 위협 모델 문서화 |

## 9. 성공 지표

- MVP 완료 기준 5개 전부 충족
- 공격 시뮬레이션 탐지율 100% (정의한 시나리오 기준)
- 에이전트 오버헤드: CPU < 5%, 메모리 < 100MB (Phase 6 벤치마크로 측정, 목표치)
- 포트폴리오 결과물: README + 데모 GIF, 위협 모델 문서, 블로그 글 1편

## 10. 범위 밖 (v1)

- ML 기반 이상탐지 (규칙 기반만)
- 멀티클러스터
- 자체 SOAR 엔진 (n8n으로 대체)
