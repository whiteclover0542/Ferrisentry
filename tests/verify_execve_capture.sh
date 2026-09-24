#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --release

LOG_FILE=$(mktemp)
sudo ./target/release/ferrisentry > "$LOG_FILE" 2>&1 &
AGENT_PID=$!
trap 'sudo kill "$AGENT_PID" 2>/dev/null || true; rm -f "$LOG_FILE"' EXIT

sleep 2
/bin/echo "hello-ferrisentry-test" > /dev/null
sleep 1

if grep -q "COMM: echo" "$LOG_FILE"; then
    echo "PASS: execve event captured for 'echo'"
else
    echo "FAIL: no execve event for 'echo' found in agent output:"
    cat "$LOG_FILE"
    exit 1
fi
