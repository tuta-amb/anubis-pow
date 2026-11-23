#!/usr/bin/env python3
"""Fallback Anubis "fast" PoW solver for hosts without a C compiler.

Same wire format as anubis-solve.c: prints "<nonce> <hexdigest>".
Slower (single process, hashlib) but fine at typical difficulties (<=5).
"""
import hashlib
import sys


def main() -> int:
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <randomData> <difficulty>", file=sys.stderr)
        return 1
    data = sys.argv[1].encode()
    difficulty = int(sys.argv[2])
    prefix = "0" * difficulty

    nonce = 0
    while True:
        digest = hashlib.sha256(data + str(nonce).encode()).hexdigest()
        if digest.startswith(prefix):
            print(nonce, digest)
            return 0
        nonce += 1


if __name__ == "__main__":
    sys.exit(main())
