#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH=$(realpath "$0")
cd "$(dirname "$SCRIPT_PATH")/.."
cargo build --release

if [[ $(id -u) -ne 0 ]]; then
    exec sudo -E env PATH="$PATH" bash "$SCRIPT_PATH" "$@"
fi
LOG_FILE=$(mktemp)
COMM_FILE=$(mktemp)
AGENT_PID=
cleanup() {
    if [[ -n "$AGENT_PID" ]]; then
        kill "$AGENT_PID" 2>/dev/null || true
        wait "$AGENT_PID" 2>/dev/null || true
    fi
    rm -f "$LOG_FILE" "$COMM_FILE"
}
trap cleanup EXIT
./target/release/ferrisentry > "$LOG_FILE" 2>&1 &
AGENT_PID=$!
sleep 2
if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    echo "FAIL: agent exited before triggers"
    cat "$LOG_FILE"
    exit 1
fi
/bin/echo "hello-ferrisentry-test" > /dev/null
# BPF PIDs use the initial namespace; a unique comm works in WSL namespaces.
python3 -c 'import ctypes, os, sys; name = ("fsuid_" + os.urandom(4).hex()).encode(); libc = ctypes.CDLL(None, use_errno=True); assert libc.prctl(15, name, 0, 0, 0) == 0; open(sys.argv[1], "w").write(name.decode()); os.setuid(0)' "$COMM_FILE"
TARGET_COMM=$(cat "$COMM_FILE")
sleep 1
if grep -q '\[exec\].*comm=echo' "$LOG_FILE"; then
    echo "PASS: execve event captured for 'echo'"
else
    echo "FAIL: no execve event for 'echo' found"
    cat "$LOG_FILE"
    exit 1
fi
if grep -Eq "\[setuid\] .*comm=${TARGET_COMM} .*target_uid=0$" "$LOG_FILE"; then
    echo "PASS: setuid(0) event captured for trigger comm=$TARGET_COMM"
else
    echo "FAIL: no setuid(0) event for trigger comm=$TARGET_COMM found"
    cat "$LOG_FILE"
    exit 1
fi
echo "ALL PASS"
