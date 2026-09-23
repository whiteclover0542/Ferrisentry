# Ferrisentry Progress

- Last updated: 2026-09-23
- Plan: [Phase 0](docs/superpowers/plans/2026-09-22-phase0-foundation.md)

Legend: `[x]` complete, `[~]` in progress, `[ ]` not started.

## Phase 0 — Foundation

- [x] Task 1: WSL2 and Rust/eBPF toolchain; see [development setup](docs/DEV_SETUP.md).
- [x] Task 2: Scaffold the Aya workspace.
- [x] Task 3: Define the shared `ExecEvent` structure.
- [x] Task 4: Implement the execve tracepoint probe.
- [x] Task 5: Implement the userspace loader and ring-buffer reader.
- [~] Task 6: Add the execve capture integration test.
- [ ] Task 7: Write the project README.

## Notes

- Ubuntu WSL2 kernel: `6.6.87.2-microsoft-standard-WSL2`.
- `bpf-linker` was installed through Aya's recommended `cargo-binstall` route
  because a source install requires a local LLVM setup.
