# Development Environment Setup (WSL2)

Ferrisentry uses eBPF, which requires a Linux kernel. Build and run the project
from an Ubuntu WSL2 shell, not native Windows PowerShell. Use Git from that
same WSL shell to avoid Windows/WSL file-mode differences.

## Prerequisites

Run the following in an elevated Windows PowerShell if Ubuntu WSL2 is not
already installed:

```powershell
wsl --install -d Ubuntu
wsl --update
```

Restart if Windows requests it. Open Ubuntu once to create a Linux user, then
run the remaining commands from its shell.

## Verify the kernel

```bash
uname -r
```

The kernel must be version 5.8 or later because this project uses eBPF ring
buffer maps.

## Install the toolchain

```bash
sudo apt update
sudo apt install -y build-essential pkg-config curl git

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup toolchain install nightly --component rust-src

# Aya recommends installing bpf-linker as a prebuilt binary.
cargo install cargo-binstall --locked
cargo binstall bpf-linker --no-confirm
cargo install cargo-generate
```

The `cargo-binstall` route avoids compiling `bpf-linker` against a local LLVM
installation. See the current [bpf-linker installation guide](https://github.com/aya-rs/bpf-linker#installation)
if the binary installation is unavailable for your platform.

## Verify the installation

```bash
rustc +nightly --version
bpf-linker --version
cargo generate --version
```

All commands must print a version without an error.

## Repository location

This repository is available in WSL at:

```bash
/mnt/d/IT/git/PERSONAL/Ferrisentry
```

If builds are slow from the mounted Windows drive, clone the repository in the
Linux filesystem (for example, `~/Ferrisentry`) and open it through VS Code's
WSL integration.

## Running eBPF programs

Loading eBPF code needs elevated Linux privileges. Run the project and its
integration test through `sudo` as shown in the project README.
