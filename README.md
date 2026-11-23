# anubis-pow

Native-code solver + fetch wrapper for [Anubis](https://anubis.techaro.lol/) "fast"
proof-of-work challenges, so Anubis-protected pages can be fetched without a
browser.

## Usage

```sh
./anubis-fetch.sh URL [OUTFILE]
```

Prints the unprotected page body to stdout (or OUTFILE). If the page has no
Anubis challenge, the body passes through unchanged.

Solver alone:

```sh
cc -O3 -pthread -o anubis-solve anubis-solve.c
./anubis-solve <randomData> <difficulty> [threads]
# -> "<nonce> <hexdigest>"
```

`anubis-solve.py` is the same thing in Python for hosts without a C compiler.

## How it works

Verified against Anubis v1.28.2 source (`TecharoHQ/anubis`):

1. GET the URL with a cookie jar. Anubis replies with a challenge page carrying
   a verification cookie and a `<script id="anubis_challenge">` JSON blob
   (`randomData`, `id`, `rules.algorithm`, `rules.difficulty`).
2. Solve the "fast" PoW: the first nonce (decimal string, from 0) whose
   `SHA-256(randomData + nonce)` hex digest has `difficulty` leading zero
   nibbles. Native C, one thread per core (`web/js/worker/sha256.ts`,
   `lib/challenge/proofofwork/proofofwork.go`).
3. GET `/.within.website/x/cmd/anubis/api/pass-challenge?id=...&response=HEX&nonce=N&elapsedTime=MS&redir=URL`
   with the verification cookie, then follow the redirect with the issued
   auth cookie. Same User-Agent across all requests (the UA is recorded in
   challenge metadata).

Difficulty 4 solves in tens of milliseconds in C. Only the "fast" (SHA-256)
algorithm is supported; the wrapper exits 2 on "slow"/"metarefresh"/"wasm".

## Files

- `anubis-solve.c` — multithreaded SHA-256 PoW solver, self-contained, no deps
- `anubis-solve.py` — single-threaded Python fallback
- `anubis-fetch.sh` — end-to-end fetch: detect challenge, solve, pass, follow

Tested end to end against https://lists.ffmpeg.org/mailman3/lists/
(Anubis v1.28.2, fast, difficulty 4): real Mailman list index returned in ~1.5s.
