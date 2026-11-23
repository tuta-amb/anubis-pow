#!/bin/sh
# anubis-fetch.sh - fetch an Anubis-protected page by solving its PoW natively.
#
# Usage: anubis-fetch.sh URL [OUTFILE]
#   Prints the final (unprotected) page body to stdout, or to OUTFILE.
#   If the page has no Anubis challenge, the body is passed through as-is.
#
# Protocol verified against Anubis v1.28.2:
#   challenge: GET URL, parse <script id="anubis_challenge"> JSON
#   solve:     first nonce (decimal, from 0) whose SHA-256(randomData + nonce)
#              hex digest has `difficulty` leading zero nibbles
#   pass:      GET ORIGIN/.within.website/x/cmd/anubis/api/pass-challenge
#              ?id=CHALLENGE_ID&response=HEX&nonce=N&elapsedTime=MS&redir=URL
#              with the verification cookie from the challenge response,
#              following the redirect to redir with the issued auth cookie.
#
# Only the "fast" (SHA-256) algorithm is supported; the script bails on
# others ("slow", "metarefresh", "wasm").

set -eu

URL=${1:?usage: anubis-fetch.sh URL [OUTFILE]}
OUT=${2:-}
UA="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
BIN="$HERE/anubis-solve"

DIR=$(mktemp -d)
trap 'rm -rf "$DIR"' EXIT
JAR="$DIR/cookies.txt"
PAGE="$DIR/page.html"

curl -sS -c "$JAR" -b "$JAR" -A "$UA" -o "$PAGE" "$URL"

# No challenge -> pass through.
if ! grep -q 'id="anubis_challenge"' "$PAGE"; then
    if [ -n "$OUT" ]; then cp "$PAGE" "$OUT"; else cat "$PAGE"; fi
    exit 0
fi

CH_JSON=$(sed -n 's|.*<script id="anubis_challenge" type="application/json">||p' "$PAGE" | sed 's|</script>.*||')
PREFIX=$(sed -n 's:.*<script id="anubis_base_prefix" type="application/json">"\([^"]*\)"</script>.*:\1:p' "$PAGE")

field() { printf '%s' "$CH_JSON" | grep -o "\"$1\":*\"[^\"]*\"" | head -1 | cut -d'"' -f4; }

ALGO=$(field algorithm)
RANDOM_DATA=$(field randomData)
CH_ID=$(field id)
DIFFICULTY=$(printf '%s' "$CH_JSON" | grep -o '"difficulty":[0-9]*' | tail -1 | cut -d: -f2)

[ "$ALGO" = "fast" ] || { echo "anubis-fetch: unsupported algorithm '$ALGO'" >&2; exit 2; }
[ -n "$RANDOM_DATA" ] && [ -n "$CH_ID" ] && [ -n "$DIFFICULTY" ] || {
    echo "anubis-fetch: could not parse challenge JSON" >&2; exit 2; }

# Build the native solver on first use; fall back to python3 if no compiler.
if [ ! -x "$BIN" ]; then
    if command -v cc >/dev/null 2>&1; then
        cc -O3 -pthread -o "$BIN" "$HERE/anubis-solve.c"
    elif command -v python3 >/dev/null 2>&1; then
        BIN="$HERE/anubis-solve.py"
    else
        echo "anubis-fetch: need cc or python3" >&2; exit 2
    fi
fi

T0=$(date +%s%3N 2>/dev/null || echo 0)
RESULT=$("$BIN" "$RANDOM_DATA" "$DIFFICULTY")
T1=$(date +%s%3N 2>/dev/null || echo 0)
ELAPSED=$((T1 - T0)); [ "$ELAPSED" -ge 0 ] || ELAPSED=1

NONCE=$(printf '%s' "$RESULT" | cut -d' ' -f1)
RESPONSE=$(printf '%s' "$RESULT" | cut -d' ' -f2)

ORIGIN=$(printf '%s' "$URL" | sed -n 's|^\([a-zA-Z][a-zA-Z0-9+.-]*://[^/]*\).*|\1|p')

curl -sSL -c "$JAR" -b "$JAR" -A "$UA" \
    -G "$ORIGIN$PREFIX/.within.website/x/cmd/anubis/api/pass-challenge" \
    --data-urlencode "id=$CH_ID" \
    --data-urlencode "response=$RESPONSE" \
    --data-urlencode "nonce=$NONCE" \
    --data-urlencode "elapsedTime=$ELAPSED" \
    --data-urlencode "redir=$URL" \
    ${OUT:+-o "$OUT"}
