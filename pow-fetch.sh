#!/bin/sh
# pow-fetch.sh - fetch pages protected by Anubis or go-away by solving their
# proof-of-work / refresh challenges natively, without a browser.
#
# Usage: pow-fetch.sh URL [OUTFILE]
#   Prints the final (unprotected) page body to stdout, or to OUTFILE.
#   If the page has no supported challenge, the body is passed through as-is.
#
# Supported:
#   Anubis: fast, slow (SHA-256 PoW, nibble difficulty),
#           sha256 (wasm flavor: binary nonce, bit difficulty),
#           metarefresh (timed refresh), preact (single SHA-256)
#   go-away: js-pow-sha256 (wasm-backed sha256 PoW),
#            refresh / resource-load (self-redirect token flows)
#
# Not supported (need a real browser / device):
#   Anubis argon2id and hashx wasm flavors, soteria (hardware attestation),
#   go-away captcha-style custom runtimes.
#
# Protocol references:
#   Anubis v1.28.2: lib/challenge/proofofwork/proofofwork.go,
#     lib/challenge/metarefresh/metarefresh.go, lib/challenge/preact/preact.go,
#     lib/challenge/wasm/wasm.go, wasm/pow/sha256/src/lib.rs
#   go-away master: embed/challenge/js-pow-sha256/*, lib/challenge/refresh,
#     lib/challenge/resource-load, lib/challenge/helper.go

set -eu

URL=${1:?usage: pow-fetch.sh URL [OUTFILE]}
OUT=${2:-}
UA="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

# POW_FETCH_EXTRA_HEADER adds one extra header to every request; only needed
# when testing against an origin that demands it (e.g. a local Anubis wanting
# X-Real-IP).
EXTRA=${POW_FETCH_EXTRA_HEADER:-}

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

DIR=$(mktemp -d)
trap 'rm -rf "$DIR"' EXIT
JAR="$DIR/cookies.txt"
PAGE="$DIR/page.html"
HDRS="$DIR/headers.txt"

ORIGIN=$(printf '%s' "$URL" | sed -n 's|^\([a-zA-Z][a-zA-Z0-9+.-]*://[^/]*\).*|\1|p')
[ -n "$ORIGIN" ] || { echo "pow-fetch: bad URL" >&2; exit 2; }

# --- pick a solver: prebuilt binary, release asset, compile, or python ----
SOLVER=""
for cand in "$HERE/pow-solve" "$HERE/pow-solve-linux-$(uname -m 2>/dev/null || echo x86_64)"; do
    if [ -x "$cand" ]; then SOLVER=$cand; break; fi
done
if [ -z "$SOLVER" ]; then
    if command -v cc >/dev/null 2>&1 && [ -f "$HERE/pow-solve.c" ]; then
        cc -O3 -pthread -o "$HERE/pow-solve" "$HERE/pow-solve.c"
        SOLVER="$HERE/pow-solve"
    elif command -v python3 >/dev/null 2>&1 && [ -f "$HERE/pow-solve.py" ]; then
        SOLVER="$HERE/pow-solve.py"
    fi
fi

hcurl() { # hcurl CURL_ARGS... - always with jar, UA and optional extra header
    if [ -n "$EXTRA" ]; then
        curl -sS -c "$JAR" -b "$JAR" -A "$UA" -H "$EXTRA" "$@"
    else
        curl -sS -c "$JAR" -b "$JAR" -A "$UA" "$@"
    fi
}

fetch() { # fetch URL [OUT]
    if [ -n "${2:-}" ]; then
        hcurl -L -D "$HDRS" -o "$2" "$1"
    else
        hcurl -L -D "$HDRS" "$1"
    fi
}

jfield() { # jfield NAME < json  (flat string fields only)
    grep -o "\"$1\" *: *\"[^\"]*\"" | head -1 | sed 's/.*: *"//; s/"$//'
}

emit() { # emit FILE
    if [ -n "$OUT" ]; then cp "$1" "$OUT"; else cat "$1"; fi
}

now_ms() { date +%s%3N 2>/dev/null || echo 0; }

fetch "$URL" "$PAGE"

# ============================ Anubis ============================
if grep -q 'id="anubis_challenge"' "$PAGE"; then
    CH_JSON=$(sed -n 's|.*<script id="anubis_challenge" type="application/json">||p' "$PAGE" | sed 's|</script>.*||')
    PREFIX=$(sed -n 's:.*<script id="anubis_base_prefix" type="application/json">"\([^"]*\)"</script>.*:\1:p' "$PAGE")

    ALGO=$(printf '%s' "$CH_JSON" | jfield algorithm)
    RANDOM_DATA=$(printf '%s' "$CH_JSON" | jfield randomData)
    CH_ID=$(printf '%s' "$CH_JSON" | jfield id)
    DIFFICULTY=$(printf '%s' "$CH_JSON" | grep -o '"difficulty":[0-9]*' | tail -1 | cut -d: -f2)
    [ -n "$CH_ID" ] || { echo "pow-fetch: could not parse anubis challenge JSON" >&2; exit 2; }

    PASS="$ORIGIN$PREFIX/.within.website/x/cmd/anubis/api/pass-challenge"

    case "$ALGO" in
    fast|slow)
        [ -n "$SOLVER" ] || { echo "pow-fetch: need a solver (cc or python3)" >&2; exit 2; }
        T0=$(now_ms)
        RESULT=$("$SOLVER" fast "$RANDOM_DATA" "$DIFFICULTY")
        ELAPSED=$(( $(now_ms) - T0 )); [ "$ELAPSED" -ge 1 ] || ELAPSED=1
        NONCE=${RESULT%% *}
        RESPONSE=${RESULT##* }
        hcurl -L \
            -G "$PASS" \
            --data-urlencode "id=$CH_ID" \
            --data-urlencode "response=$RESPONSE" \
            --data-urlencode "nonce=$NONCE" \
            --data-urlencode "elapsedTime=$ELAPSED" \
            --data-urlencode "redir=$URL" \
            ${OUT:+-o "$OUT"}
        ;;
    sha256)
        # wasm sha256 flavor: randomData is hex, nonce is a binary u32
        [ -n "$SOLVER" ] || { echo "pow-fetch: need a solver (cc or python3)" >&2; exit 2; }
        T0=$(now_ms)
        RESULT=$("$SOLVER" wasm-sha256 "$RANDOM_DATA" "$DIFFICULTY")
        ELAPSED=$(( $(now_ms) - T0 )); [ "$ELAPSED" -ge 1 ] || ELAPSED=1
        NONCE=${RESULT%% *}
        RESPONSE=${RESULT##* }
        hcurl -L \
            -G "$PASS" \
            --data-urlencode "id=$CH_ID" \
            --data-urlencode "response=$RESPONSE" \
            --data-urlencode "nonce=$NONCE" \
            --data-urlencode "elapsedTime=$ELAPSED" \
            --data-urlencode "redir=$URL" \
            ${OUT:+-o "$OUT"}
        ;;
    metarefresh)
        # server requires difficulty*800ms to have passed since issuance
        SLEEP=$((DIFFICULTY + 1))
        sleep "$SLEEP"
        hcurl -L \
            -G "$PASS" \
            --data-urlencode "id=$CH_ID" \
            --data-urlencode "challenge=$RANDOM_DATA" \
            --data-urlencode "redir=$URL" \
            ${OUT:+-o "$OUT"}
        ;;
    preact)
        # result = hex sha256 of the randomData string; difficulty*80ms wait
        RESPONSE=$(printf '%s' "$RANDOM_DATA" | sha256sum | cut -d' ' -f1)
        sleep 1
        hcurl -L \
            -G "$PASS" \
            --data-urlencode "id=$CH_ID" \
            --data-urlencode "result=$RESPONSE" \
            --data-urlencode "redir=$URL" \
            ${OUT:+-o "$OUT"}
        ;;
    argon2id|hashx)
        echo "pow-fetch: anubis '$ALGO' wasm challenge not supported (needs browser wasm)" >&2
        exit 2
        ;;
    *)
        echo "pow-fetch: unsupported anubis algorithm '$ALGO'" >&2
        exit 2
        ;;
    esac
    exit 0
fi

# ============================ go-away ============================
GOAWAY_SCRIPT=$(sed -n 's/.*<script[^>]*src="\([^"]*\/challenge\/[^/"]*\/script\.mjs\)[?"][^"]*".*/\1/p' "$PAGE" | head -1)
# refresh / resource-load / js-refresh runtimes: a ready-made verify URL with
# the token appears in a Refresh header, a meta refresh, a stylesheet link, or
# a window.location assignment (HTML attributes amp-escape the query string)
GOAWAY_TOKEN_URL=$( { grep -ioE '(url=)?[^"'"'"' <>]*__goaway_token=[^"'"'"' <>]*' "$HDRS" || :
                      grep -oE '(url=)?[^"'"'"' <>]*__goaway_token=[^"'"'"' <>]*' "$PAGE" || :
                    } | head -1 | tr -d '\r' | sed 's/^url=//; s/&amp;/\&/g; s/\\u0026/\&/g' )

if [ -n "$GOAWAY_TOKEN_URL" ] || [ -n "$GOAWAY_SCRIPT" ]; then
    if [ -n "$GOAWAY_TOKEN_URL" ]; then
        case "$GOAWAY_TOKEN_URL" in
            http*) : ;;
            *) GOAWAY_TOKEN_URL="$ORIGIN$GOAWAY_TOKEN_URL" ;;
        esac
        # no time gate on the key verifier; follow immediately
        hcurl -L "$GOAWAY_TOKEN_URL" -o "$DIR/step2.html"
        # the verify endpoint may 307 to the target, or (resource-load) return
        # empty CSS; refetch the original URL with the issued cookie
        fetch "$URL" "$PAGE"
        if grep -q '__goaway_token=' "$PAGE" || grep -q 'script\.mjs' "$PAGE"; then
            echo "pow-fetch: go-away refresh flow did not clear the challenge" >&2
            exit 2
        fi
        emit "$PAGE"
        exit 0
    fi

    # js runtime (js-pow-sha256)
    [ -n "$SOLVER" ] || { echo "pow-fetch: need a solver (cc or python3)" >&2; exit 2; }
    case "$GOAWAY_SCRIPT" in
        http*) SCRIPT_URL="$GOAWAY_SCRIPT" ;;
        *) SCRIPT_URL="$ORIGIN$GOAWAY_SCRIPT" ;;
    esac
    fetch "$SCRIPT_URL" "$DIR/script.mjs"

    G_PATH=$(sed -n 's/.*Path: *"\([^"]*\)".*/\1/p' "$DIR/script.mjs" | head -1)
    G_NAME=$(sed -n 's/.*__goaway_challenge: *"\([^"]*\)".*/\1/p' "$DIR/script.mjs" | head -1)
    G_ID=$(sed -n 's/.*__goaway_id: *"\([^"]*\)".*/\1/p' "$DIR/script.mjs" | head -1)
    [ -n "$G_PATH" ] && [ -n "$G_NAME" ] && [ -n "$G_ID" ] || {
        echo "pow-fetch: could not parse go-away challenge script" >&2; exit 2; }

    # key headers must match between make-challenge and verify-challenge:
    # same UA, same (absent) Accept-Language/Sec-Ch-Ua, same jar, same IP
    MC=$(hcurl -X POST "$ORIGIN$G_PATH/make-challenge")
    G_CHAL=$(printf '%s' "$MC" | jfield challenge)
    G_TARGET=$(printf '%s' "$MC" | jfield target)
    [ -n "$G_CHAL" ] && [ -n "$G_TARGET" ] || {
        echo "pow-fetch: go-away make-challenge failed (runtime may not be js-pow-sha256)" >&2; exit 2; }

    T0=$(now_ms)
    TOKEN=$("$SOLVER" goaway "$G_CHAL" "$G_TARGET")
    ELAPSED=$(( $(now_ms) - T0 )); [ "$ELAPSED" -ge 1 ] || ELAPSED=1

    hcurl -L \
        -G "$ORIGIN$G_PATH/verify-challenge" \
        --data-urlencode "__goaway_token=$TOKEN" \
        --data-urlencode "__goaway_challenge=$G_NAME" \
        --data-urlencode "__goaway_redirect=$URL" \
        --data-urlencode "__goaway_id=$G_ID" \
        --data-urlencode "__goaway_elapsedTime=$ELAPSED" \
        ${OUT:+-o "$OUT"}
    exit 0
fi

# ============================ passthrough ============================
emit "$PAGE"
