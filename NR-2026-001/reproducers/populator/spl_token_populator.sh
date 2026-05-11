#!/bin/bash
# spl_token_populator_xargs.sh — parallel populator using
# `spl-token create-account` via xargs -P. Inlined the worker
# (no exported function; bash -c starts fresh shells that
# don't inherit exported functions reliably).

set -euo pipefail

COUNT="${1:-2000}"
JOBS="${2:-32}"
WORK_DIR="${WORK_DIR:-/data/claude-wd/solana-localnet}"
RPC_URL="${RPC_URL:-http://127.0.0.1:8899}"

export PATH="/data/solana/release/bin:$PATH"

cd "$WORK_DIR"

solana config set --url "$RPC_URL" >/dev/null 2>&1
solana config set --keypair "$WORK_DIR/keypair.json" >/dev/null 2>&1

echo "[populator-xargs] Creating mint..."
MINT_LINE=$(spl-token create-token --decimals 9 2>&1 | grep '^Address:')
MINT=$(echo "$MINT_LINE" | awk '{print $2}')
[ -z "$MINT" ] && { echo "[populator-xargs] mint creation failed" >&2; exit 1; }
echo "$MINT" > "$WORK_DIR/mint.txt"
echo "[populator-xargs] Mint: $MINT"

RCPTS="$WORK_DIR/rcpt-keypairs"
rm -rf "$RCPTS"
mkdir -p "$RCPTS"

echo "[populator-xargs] Generating $COUNT recipient keypairs..."
for i in $(seq 1 "$COUNT"); do
    solana-keygen new --no-bip39-passphrase --silent --outfile "$RCPTS/r-$i.json" --force >/dev/null 2>&1
done
echo "[populator-xargs] Keypairs ready."

echo "[populator-xargs] Creating $COUNT token accounts via xargs -P $JOBS..."
START=$(date +%s)

# Inline worker — passes mint, payer keypair, recipient keypair to spl-token CLI.
# Logs a "." per success, "X" per failure. tee-counts go to a log file we
# tail for progress, NOT through xargs's pipe (which serialises and bottlenecks).
LOG="$WORK_DIR/populator-progress.log"
: > "$LOG"

ls "$RCPTS" | head -n "$COUNT" | \
    xargs -I{} -P "$JOBS" bash -c '
        kp="'"$RCPTS"'/{}"
        owner=$(/data/solana/release/bin/solana-keygen pubkey "$kp")
        if /data/solana/release/bin/spl-token create-account "'"$MINT"'" \
            --owner "$owner" \
            --fee-payer "'"$WORK_DIR"'/keypair.json" \
            --url "'"$RPC_URL"'" \
            >/dev/null 2>&1
        then
            echo "ok" >> "'"$LOG"'"
        else
            echo "err" >> "'"$LOG"'"
        fi
    ' &

XARGS_PID=$!

# Progress watcher
while kill -0 "$XARGS_PID" 2>/dev/null; do
    sleep 5
    OK=$(grep -c '^ok$' "$LOG" 2>/dev/null || echo 0)
    ERR=$(grep -c '^err$' "$LOG" 2>/dev/null || echo 0)
    DONE=$((OK + ERR))
    ELAPSED=$(($(date +%s) - START))
    if [ "$DONE" -gt 0 ] && [ "$ELAPSED" -gt 0 ]; then
        RATE=$(awk -v d="$DONE" -v e="$ELAPSED" 'BEGIN{printf "%.1f", d/e}')
        REMAINING=$((COUNT - DONE))
        ETA=$(awk -v r="$REMAINING" -v rate="$RATE" 'BEGIN{if(rate>0) printf "%d", r/rate; else print "?"}')
        echo "[populator-xargs]   $DONE/$COUNT (ok=$OK err=$ERR) ${RATE}/s eta=${ETA}s"
    fi
done

wait "$XARGS_PID" || true
ELAPSED=$(($(date +%s) - START))

OK=$(grep -c '^ok$' "$LOG" 2>/dev/null || echo 0)
ERR=$(grep -c '^err$' "$LOG" 2>/dev/null || echo 0)
echo "[populator-xargs] Send phase done: ok=$OK err=$ERR in ${ELAPSED}s"

sleep 10

echo "[populator-xargs] Verifying account count..."
N=$(curl -sS "$RPC_URL" -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getProgramAccounts","params":["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",{"encoding":"base64","filters":[{"dataSize":165}]}]}' \
    | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("result", [])))')

echo "[populator-xargs] On-chain token accounts (size=165): $N"
echo "[populator-xargs] Mint: $MINT"
