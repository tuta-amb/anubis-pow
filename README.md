# anubis-pow

Native-code solvers + a fetch wrapper for [Anubis](https://anubis.techaro.lol/)
and [go-away](https://git.gammaspectra.live/git/go-away) anti-bot challenges,
so protected pages can be fetched without a browser.

## Usage

```sh
./pow-fetch.sh URL [OUTFILE]
```

Prints the unprotected page body to stdout (or OUTFILE). If the page has no
supported challenge, the body passes through unchanged.

The wrapper uses, in order: a prebuilt `pow-solve` next to the script, a
downloaded release binary (`pow-solve-linux-x86_64`), a fresh compile from
`pow-solve.c`, or the `pow-solve.py` fallback.

## Supported challenges

Anubis (verified against v1.28.2 source and a live v1.28.2 server):

| Algorithm | How it passes |
| --- | --- |
| `fast` / `slow` | SHA-256(randomData + decimal nonce), `difficulty` leading zero hex nibbles |
| `sha256` (wasm) | SHA-256(challenge bytes + u32 nonce, LE/BE by last challenge byte), `difficulty` leading zero bits |
| `metarefresh` | wait `difficulty` x 800ms, then pass-challenge with the randomData echoed back |
| `preact` | pass-challenge with hex SHA-256(randomData) |

go-away (verified against master source and a live go-away server):

| Runtime | How it passes |
| --- | --- |
| `js-pow-sha256` | POST make-challenge, find 8-byte LE nonce with SHA-256(challenge \|\| nonce) < target, GET verify-challenge with the token |
| `refresh` (header/meta/javascript) | follow the verify URL carrying `__goaway_token` |
| `resource-load` | fetch the "stylesheet" verify URL, then refetch |
| `cookie` | just follow the redirect; the token cookie is set on the first response |

Not supported (bails with exit 2): Anubis `argon2id` and `hashx` wasm flavors
(memory-/program-hard PoW, need a real wasm engine or a big porting effort),
`soteria` (hardware attestation), and go-away custom/captcha runtimes.

## Solver alone

```sh
cc -O3 -pthread -o pow-solve pow-solve.c
./pow-solve fast <randomData> <difficulty> [threads]        # -> "<nonce> <hexdigest>"
./pow-solve wasm-sha256 <randomDataHex> <bits> [threads]    # -> "<nonce> <hexdigest>"
./pow-solve goaway <challengeHex> <targetHex> [threads]     # -> "<hex(challenge||nonce8)>"
```

`pow-solve.py` is the same thing in Python for hosts without a C compiler
(single-threaded, so keep difficulties modest).

Difficulty 4 (fast) solves in tens of milliseconds in C. go-away difficulty 16
is instant, 20 takes a second or two. Anything above that gets exponentially
pricier.

## Releases

The GitHub release carries a statically linked `pow-solve-linux-x86_64`
(x86-64 only; other platforms compile from source or use the Python fallback).

## How it works

1. GET the URL with a cookie jar and a consistent User-Agent (the UA feeds
   into challenge keys on both WAFs).
2. Anubis: parse the `<script id="anubis_challenge">` JSON (`randomData`,
   `id`, `rules.algorithm`, `rules.difficulty`), solve, then GET
   `/.within.website/x/cmd/anubis/api/pass-challenge` with the proof and
   follow the redirect.
3. go-away: find either a ready-made verify URL with `__goaway_token`
   (refresh/resource-load runtimes) or the challenge `script.mjs`; for
   js-pow-sha256, POST `<path>/make-challenge`, solve, GET
   `<path>/verify-challenge` with `__goaway_token` and friends.

Protocol references: Anubis `lib/challenge/{proof-of-work,metarefresh,preact,wasm}`
+ `wasm/pow/sha256/src/lib.rs`; go-away `embed/challenge/js-pow-sha256/*`,
`lib/challenge/{refresh,resource-load,cookie,helper.go}`.

Tested end to end against:
- https://lists.ffmpeg.org/mailman3/lists/ (live, Anubis v1.28.2, fast,
  difficulty 4)
- a local Anubis v1.28.2: fast, slow, metarefresh, preact, wasm sha256
- a local go-away master: js-pow-sha256, cookie, header/meta/js refresh,
  resource-load

## Files

- `pow-solve.c` — multithreaded solver, self-contained, no deps
- `pow-solve.py` — single-threaded Python fallback
- `pow-fetch.sh` — end-to-end fetch: detect challenge, solve, pass, follow
