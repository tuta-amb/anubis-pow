#!/usr/bin/env python3
"""Fallback PoW solver for hosts without a C compiler.

Same wire formats as pow-solve.c, single-threaded. Fine at typical
difficulties (fast <= 5, wasm-sha256 <= 16 bits, go-away <= 20 bits).

Usage:
  pow-solve.py fast <randomData> <difficulty>        -> "<nonce> <hexdigest>"
  pow-solve.py wasm-sha256 <randomDataHex> <bits>    -> "<nonce> <hexdigest>"
  pow-solve.py goaway <challengeHex> <targetHex>     -> "<hex(challenge||nonce8)>"
"""
import hashlib
import sys


def lead_zero_nibbles(hexdigest: str, difficulty: int) -> bool:
    return hexdigest.startswith("0" * difficulty)


def lead_zero_bits(digest: bytes, difficulty: int) -> bool:
    remaining = difficulty
    for byte in digest:
        if remaining == 0:
            break
        if remaining >= 8:
            if byte != 0:
                return False
            remaining -= 8
        else:
            if byte & (0xFF << (8 - remaining)):
                return False
            remaining = 0
    return True


def mode_fast(data: str, difficulty: int) -> None:
    payload = data.encode()
    prefix = "0" * difficulty
    nonce = 0
    while True:
        digest = hashlib.sha256(payload + str(nonce).encode()).hexdigest()
        if digest.startswith(prefix):
            print(nonce, digest)
            return
        nonce += 1


def mode_wasm_sha256(data_hex: str, difficulty: int) -> None:
    data = bytes.fromhex(data_hex)
    use_le = data[-1] >= 128
    nonce = 0
    while nonce < 2**32:
        nb = nonce.to_bytes(4, "little" if use_le else "big")
        digest = hashlib.sha256(data + nb).digest()
        if lead_zero_bits(digest, difficulty):
            print(nonce, digest.hex())
            return
        nonce += 1
    raise SystemExit("no solution in u32 space")


def mode_goaway(challenge_hex: str, target_hex: str) -> None:
    data = bytes.fromhex(challenge_hex)
    target = bytes.fromhex(target_hex)
    ctr = 0
    while ctr < 2**64:
        buf = data + ctr.to_bytes(8, "little")
        if hashlib.sha256(buf).digest() < target:
            print(buf.hex())
            return
        ctr += 1
    raise SystemExit("no solution")


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        return 1
    mode = sys.argv[1]
    if mode in ("fast", "slow"):
        mode_fast(sys.argv[2], int(sys.argv[3]))
    elif mode in ("wasm-sha256", "sha256"):
        mode_wasm_sha256(sys.argv[2], int(sys.argv[3]))
    elif mode == "goaway":
        mode_goaway(sys.argv[2], sys.argv[3])
    else:
        print(f"unknown mode {mode!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
