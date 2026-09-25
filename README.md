# Ferrisentry

Ferrisentry is a Rust eBPF learning project for Kubernetes runtime security.
It uses Aya to collect Linux process-execution events and deliver them to a
userspace agent through a ring buffer.

- [Design specification](docs/superpowers/specs/2026-09-22-ferrisentry-design.md)
- [Progress](PROGRESS.md)

## Current status: Phase 0 — Foundation

The current agent attaches to `sched:sched_process_exec`, captures a process
PID and command name, and prints events in this form:

```text
PID: 1234 COMM: bash
```

Rule evaluation, Kubernetes metadata enrichment, additional probes, and
alerting are deliberately outside Phase 0.

## Development environment

eBPF requires a Linux kernel. Build and run this project in Ubuntu WSL2 (or
another Linux host), not native Windows PowerShell.

See [docs/DEV_SETUP.md](docs/DEV_SETUP.md) for the required Rust, Aya, and
WSL2 setup.

## Run

In an Ubuntu WSL shell:

```bash
cargo build --release
sudo ./target/release/ferrisentry
```

The process stays active until `Ctrl+C`. In a separate shell, run an external
program such as `/bin/echo hello` to produce an event.

## Verify

```bash
./tests/verify_execve_capture.sh
```

The script builds the release binary, starts it with elevated privileges, runs
`/bin/echo`, and expects:

```text
PASS: execve event captured for 'echo'
```

## License

With the exception of eBPF code, Ferrisentry is distributed under either the
[MIT license] or the [Apache License], at your option. eBPF code is distributed
under either the [GNU General Public License, Version 2] or the MIT license.

[Apache License]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
