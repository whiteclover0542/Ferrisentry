# 개발 환경 셋업 (WSL2)

eBPF는 Linux 커널 기능이라 Windows 네이티브에서는 빌드/실행이 안 됩니다. 모든 빌드/실행/테스트
명령은 Ubuntu WSL2 셸 안에서 돌립니다. 커밋도 같은 WSL 셸에서 하세요 (Windows git과 섞으면
줄바꿈/실행권한 비트 diff가 생깁니다).

## 1. WSL2 설치

Ubuntu WSL2가 없으면 관리자 권한 Windows PowerShell에서:

```powershell
wsl --install -d Ubuntu
wsl --update
```

Windows가 재부팅을 요구하면 재부팅하고, **Ubuntu**를 한 번 실행해 Linux 사용자 계정을 만듭니다.

## 2. 커널 확인

Ubuntu 셸에서:

```bash
uname -r
```

이 프로젝트는 eBPF ring buffer 맵을 쓰므로 **커널 5.8 이상**이어야 합니다.
(검증 환경: `6.6.87.2-microsoft-standard-WSL2`)

## 3. 툴체인 설치

```bash
sudo apt update
sudo apt install -y build-essential pkg-config curl git

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup toolchain install nightly --component rust-src

cargo install cargo-binstall
cargo binstall -y bpf-linker
cargo install cargo-generate
```

`bpf-linker`는 `cargo install`로 소스 빌드하면 로컬 LLVM 설치를 요구합니다. 그래서 Aya가 권장하는
`cargo-binstall`로 미리 빌드된 바이너리를 받습니다. 실패하면
[bpf-linker 설치 안내](https://github.com/aya-rs/bpf-linker#installation)를 확인하세요.

## 4. 설치 검증

```bash
rustc +nightly --version
bpf-linker --version
cargo generate --version
```

세 명령 모두 에러 없이 버전을 출력해야 합니다.

## 5. 리포지토리 위치

현재 위치:

```bash
/mnt/d/IT/git/PERSONAL/Ferrisentry
```

`/mnt/d`(DrvFs)에서는 cargo 빌드가 느립니다. 느려서 불편하면 Linux 파일시스템 안으로
(예: `~/Ferrisentry`) clone하고 VS Code의 WSL 원격 모드로 여세요.

## 6. eBPF 실행 권한

eBPF 프로그램 로드에는 상위 권한이 필요합니다. 실행과 통합 테스트는 `sudo`로 돌립니다
([README](../README.md) 참고). 워크스페이스의 `.cargo/config.toml`에 `runner = "sudo -E"`가
설정되어 있어서 `cargo run`도 sudo를 거칩니다.

sudo가 필요 없는 유닛 테스트는 runner를 덮어써서 돌립니다.

```bash
cargo test --config 'target."cfg(all())".runner="env"'
```
