# Ferrisentry 진행 현황

- 마지막 업데이트: 2026-10-08
- 기획서: [PLANNING.md](PLANNING.md) · 설계: [spec](docs/superpowers/specs/2026-09-22-ferrisentry-design.md) · 현재 plan: [Phase 0](docs/superpowers/plans/2026-09-22-phase0-foundation.md)

범례: ✅ 완료 · 🔄 진행 중 · ⬜ 미완료

진행 규칙: Phase를 시작할 때마다 `docs/superpowers/plans/YYYY-MM-DD-phaseN-<이름>.md` plan을 먼저 작성하고, 그 plan을 따라 진행한다. 위의 "현재 plan" 링크를 새 plan으로 바꾼다.

---

## 1. 해야 할 일

지금 바로 해야 할 일 (위에서부터 순서대로):

- [ ] Phase 1 plan 작성 (`docs/superpowers/plans/`)
- [ ] Phase 1: `connect` / `openat` / `setuid` probe 추가
- [ ] Phase 1: 이벤트 공통 포맷으로 통합 (+ ppid, cgroup_id)
- [ ] Phase 1: ring buffer drop 카운터
- [ ] Phase 1: cgroup ID → 컨테이너 ID 매핑

보류/메모:

- `/mnt/d`(DrvFs)에서 빌드가 느리면 리포지토리를 WSL 홈(`~/`)으로 옮기는 것 검토
- WSL 개발 계정은 `ferris`이고 비밀번호가 설정되어 있지 않다. 그래서 `sudo` 비밀번호 프롬프트 경로는 검증되지 않았다 (root로 실행해 테스트함)
- Phase 0 코드는 한 번 전체가 revert(`b65ddf8`)된 뒤 다시 복구(`3e0dc54`)되었다. revert 사유는 기록이 남아 있지 않다

---

## 2. 작업 순서

### 기획
| 상태 | 작업 |
|---|---|
| ✅ | 설계 문서 (spec) |
| ✅ | Phase 0 plan |
| ✅ | 기획서 (MVP 정의 포함) + PROGRESS |

### Phase 0 — Foundation (1~2주) · MVP
| 상태 | Task | 결과물 |
|---|---|---|
| ✅ | 1. WSL2 + 툴체인 설치 | `docs/DEV_SETUP.md` |
| ✅ | 2. aya-template 스캐폴딩 | 워크스페이스 3크레이트 (aya-template 0.25, xtask 없음) |
| ✅ | 3. 공용 `ExecEvent` 구조체 | `ferrisentry-common/src/lib.rs` + ABI 테스트 |
| ✅ | 4. execve tracepoint probe | `ferrisentry-ebpf/src/main.rs` |
| ✅ | 5. 유저스페이스 로더 + ring buffer 읽기 | `ferrisentry/src/main.rs` |
| ✅ | 6. 통합 검증 | `tests/verify_execve_capture.sh` |
| ✅ | 7. README | `README.md` |

### Phase 1 — 핵심 probe (2~3주) · MVP
| 상태 | 작업 |
|---|---|
| ⬜ | plan 작성 |
| ⬜ | `connect` / `openat` / `setuid` probe |
| ⬜ | 이벤트 공통 포맷 + ppid, cgroup_id 추가 |
| ⬜ | ring buffer drop 카운트 |
| ⬜ | cgroup ID → 컨테이너 ID 매핑 |

### Phase 2 — 룰 엔진 (2주) · MVP
| 상태 | 작업 |
|---|---|
| ⬜ | plan 작성 |
| ⬜ | YAML 규칙 파싱 + 매칭 로직 (유닛 테스트) |
| ⬜ | 초기 규칙 3종 (쉘 실행 / 민감 경로 쓰기 / setuid(0)) |
| ⬜ | 알림 출력: stdout JSON + Webhook |

### Phase 3 — K8s 연동 (2주) · MVP
| 상태 | 작업 |
|---|---|
| ⬜ | plan 작성 |
| ⬜ | CRI API로 Pod/네임스페이스/이미지 메타데이터 붙이기 |
| ⬜ | DaemonSet 매니페스트 (최소 권한) |
| ⬜ | kind 클러스터 배포 |
| ⬜ | 공격 시뮬레이션 Pod 3종 + 탐지 확인 |
| ⬜ | **🎯 MVP 완료 기준 점검** ([PLANNING.md 4.4](PLANNING.md#44-mvp-완료-기준)) |

### Phase 4 — 중앙 Collector (2주)
| 상태 | 작업 |
|---|---|
| ⬜ | plan 작성 |
| ⬜ | Collector Deployment + gRPC |
| ⬜ | 이벤트 저장 (SQLite/Postgres) |
| ⬜ | 정책 CRD, Helm 차트 |
| ⬜ | Slack 알림 라우팅, n8n 웹훅 (선택) |

### Phase 5 — 대시보드 (2주)
| 상태 | 작업 |
|---|---|
| ⬜ | plan 작성 |
| ⬜ | 실시간 이벤트 타임라인 (WebSocket/SSE) |
| ⬜ | 정책 관리 UI |

### Phase 6 — 마무리 (1~2주)
| 상태 | 작업 |
|---|---|
| ⬜ | plan 작성 |
| ⬜ | 성능 벤치마크 |
| ⬜ | 위협 모델 문서 |
| ⬜ | 데모 영상/GIF, 블로그 글 |

---

## 3. 완료한 일

| 날짜 | 내용 | 관련 |
|---|---|---|
| 2026-09-22 | 설계 문서 작성 | `3696f1f` |
| 2026-09-22 | Phase 0 plan 작성 | `4c9feac` |
| 2026-09-22 | 기획서(MVP 포함), PROGRESS 작성, Phase 0 plan 수정 | — |
| 2026-09-25 | Phase 0 Task 1~7 구현 완료 (툴체인 → 워크스페이스 → probe → 로더 → 통합 테스트 → README) | `9da66ed`..`ca27c80` |
| 2026-10-08 | revert된 Phase 0 구현 복구 + 문서 한국어 정리 후 main 병합 | `3e0dc54`, `a60a567` |

### Phase 0 검증 기록

- 환경: Ubuntu WSL2, 커널 `6.6.87.2-microsoft-standard-WSL2`, 사용자 `ferris`
- `cargo build` / `cargo test --config 'target."cfg(all())".runner="env"'` 통과
- `./tests/verify_execve_capture.sh` (root 실행) → `PASS: execve event captured for 'echo'`
- `bpf-linker`는 소스 빌드에 LLVM이 필요해서 `cargo-binstall`로 설치함
- 2026-10-08 main 병합 후 재검증: 유닛 테스트 2개 통과, 통합 테스트 PASS
- 원격(`origin`)의 `main`은 GitHub가 만든 `Initial commit`(README만)이라서 로컬 히스토리와 분기되어 있다. 아직 푸시하지 않았다
