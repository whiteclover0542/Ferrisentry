# Ferrisentry — eBPF 기반 K8s 런타임 보안 모니터링 도구

- 날짜: 2026-09-22
- 목적: 보안 포트폴리오 + eBPF/Rust 학습
- 투입 시간: 주 30시간
- 언어: Rust (userspace + eBPF, via Aya)
- 배포 대상: Kubernetes 클러스터

## 1. 개요

컨테이너 내부에서 실행되는 프로세스의 syscall을 커널 레벨(eBPF)에서 실시간 관찰하여,
리버스쉘 실행, 권한 상승, 민감 파일 쓰기, 비정상 아웃바운드 연결 같은 위험 행동을
탐지하고 알림을 보내는 런타임 보안 도구. Falco/Tetragon과 같은 카테고리.

## 2. 아키텍처

```
[K8s 노드1]              [K8s 노드2]           ...
┌─────────────┐         ┌─────────────┐
│ DaemonSet    │         │ DaemonSet    │
│ ┌─────────┐  │         │ ┌─────────┐  │
│ │eBPF probe│ │  syscall │ │eBPF probe│ │
│ │(커널)    │◄─┼─ hook    │ │(커널)    │ │
│ └────┬────┘  │         │ └────┬────┘  │
│      │ring buf│         │      │       │
│ ┌────▼────┐  │         │ ┌────▼────┐  │
│ │Rust agent│  │         │ │Rust agent│  │
│ │+ 룰엔진  │  │         │ │+ 룰엔진  │  │
│ └────┬────┘  │         │ └────┬────┘  │
└──────┼────────┘         └──────┼────────┘
       │ gRPC (알림/이벤트)       │
       └───────────┬─────────────┘
                    ▼
          ┌─────────────────┐
          │ 중앙 Collector    │
          │ (Deployment)      │
          │ - 이벤트 집계      │
          │ - 정책(CRD) 관리   │
          │ - 저장소(sqlite/pg)│
          └────────┬──────────┘
                    ├──────────────┐
                    ▼              ▼
          ┌─────────────────┐  ┌─────────────────┐
          │  웹 대시보드       │  │ n8n 웹훅 (선택)    │
          └─────────────────┘  │ → 자동 대응 워크플로우│
                                └─────────────────┘
```

## 3. 핵심 컴포넌트

1. **eBPF probe (커널)**: tracepoint/kprobe로 `execve`, `connect`, `openat`, `setuid` 등
   후킹 → ring buffer로 이벤트 전달. Aya로 작성 (Rust → BPF 바이트코드 컴파일).
2. **노드 에이전트 (Rust, DaemonSet)**: Aya userspace API로 probe 로드/관리,
   ring buffer polling, cgroup ID → 컨테이너/Pod 메타데이터 매핑 (containerd/CRI API 조회),
   룰 엔진 실행.
3. **룰 엔진**: YAML 기반 규칙 정의 (Falco 스타일). 초기 규칙셋:
   - 컨테이너 내부에서 인터랙티브 쉘 실행
   - `/etc`, `/root/.ssh` 등 민감 경로 쓰기
   - 허용되지 않은 아웃바운드 IP/포트 연결
   - `setuid(0)` 등 권한 상승 시도
   - 알려진 크립토마이너 프로세스 패턴
4. **중앙 Collector (Deployment)**: 클러스터 전체 이벤트 집계, 정책을 K8s CRD로 관리,
   이벤트 저장(SQLite/Postgres), 알림 라우팅.
5. **대시보드**: 실시간 이벤트 타임라인, 정책 관리 UI (WebSocket/SSE로 실시간 push).
6. **n8n 연동 (확장, 선택)**: Collector가 탐지 이벤트를 n8n 웹훅으로 전달 →
   n8n 워크플로우에서 자동 대응 (예: 해당 Pod 격리 API 호출, 티켓 생성, Slack 알림,
   위협 인텔리전스 API로 IP 평판 조회). 탐지(Ferrisentry)와 대응 자동화(n8n)를
   분리해 SOAR 스타일 엔드투엔드 데모를 구성. **Phase 4에서 옵션 기능으로 구현.**

## 4. 데이터 흐름

1. 컨테이너 프로세스가 syscall 실행 (예: `execve("/bin/sh")`)
2. eBPF probe가 커널 내에서 이벤트 캡처 → ring buffer에 push (lock-free)
3. Rust 에이전트가 유저스페이스에서 ring buffer poll → raw 이벤트(pid, syscall, cgroup_id, 인자) 수신
4. cgroup_id로 컨테이너 ID 조회 → CRI API로 Pod/네임스페이스/이미지 메타데이터 enrich
5. 룰 엔진이 enrich된 이벤트를 YAML 규칙과 매칭
6. 매칭되면 Alert 객체 생성 → gRPC로 중앙 Collector에 전송 (배치/디바운스로 노이즈 억제)
7. Collector가 저장 + 대시보드에 실시간 push + (옵션) n8n 웹훅 트리거

## 5. 에러 처리 & 위협 모델

- **Ring buffer 오버플로우**: 이벤트 유실 시 drop 카운트를 메트릭으로 노출 (조용히 삼키지 않음)
- **커널 버전 비호환**: eBPF verifier가 프로그램 로드를 거부하면 에이전트는 크래시 대신
  "probe 비활성화 + 헬스체크 실패" 상태로 degrade
- **K8s API 레이트리밋**: CRI/K8s API 조회는 캐시 + 지수 백오프
- **에이전트 자체가 공격 표면**: DaemonSet은 `CAP_BPF`/`CAP_SYS_ADMIN` 등 높은 권한으로 실행됨.
  최소 권한 원칙(필요한 capability만 부여), 읽기 전용 루트파일시스템, seccomp 프로파일 적용.
  이 위협 모델 자체를 문서화하는 것이 포트폴리오 어필 포인트.

## 6. 테스트 전략

- 룰 엔진: 유닛 테스트 (입력 이벤트 → 예상 알림 매칭 여부)
- eBPF probe: kind/minikube 클러스터에서 통합 테스트
- **공격 시뮬레이션 스위트**: 리버스쉘, 권한 상승, 크립토마이닝 패턴을 의도적으로
  재현하는 테스트 Pod 세트로 탐지율 검증. 포트폴리오 데모 자료(README GIF, 블로그 글)로 활용.
- 성능: 에이전트 오버헤드(CPU/메모리, syscall 레이턴시 증가분) 벤치마크

## 7. 로드맵 (주 30시간 기준, 총 12~14주)

| 단계 | 기간 | 내용 |
|---|---|---|
| 0 | 1~2주 | Rust 기초 + Aya로 eBPF hello-world (execve 추적, 콘솔 출력) |
| 1 | 2~3주 | 핵심 probe (execve/connect/openat/setuid) + ring buffer 파이프라인 + cgroup→컨테이너 매핑 |
| 2 | 2주 | 룰 엔진 (YAML 파싱, 매칭 로직) + 초기 규칙셋 |
| 3 | 2주 | K8s 연동 (DaemonSet, CRI 메타데이터, Helm 차트) |
| 4 | 2주 | 중앙 Collector + 알림 (Slack/Webhook) + n8n 웹훅 연동(선택) |
| 5 | 2주 | 웹 대시보드 (이벤트 타임라인, 정책 관리) |
| 6 | 1~2주 | 공격 시뮬레이션 테스트, 벤치마크, 문서화, 데모 영상 |

## 8. 범위 밖 (v1 기준)

- ML 기반 이상탐지 (초기엔 규칙 기반만; 추후 확장 가능)
- 멀티클러스터 연합 (단일 클러스터 기준)
- 자체 SOAR 엔진 구현 (n8n으로 대체)
