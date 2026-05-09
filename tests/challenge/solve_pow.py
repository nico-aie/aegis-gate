#!/usr/bin/env python3
"""
Reference PoW solver for the v2.3 challenge contract.

NEW-2 (2026-05-08) — when the WAF returns a 429 challenge response,
the body carries:

    {
      "challenge":     true,
      "challenge_type": "proof_of_work",
      "nonce":          "<32 hex chars>",
      "difficulty":     16,
      "expires_at_ms":  <unix ms>,
      "mac":            "<64 hex chars>",
      "submit_to":      "/__waf_control/challenge_verify",
      "reason":         "..."
    }

The client finds a `counter` (any string) such that

    blake3(nonce || ":" || counter)

has at least `difficulty` leading zero bits, then POSTs

    { nonce, difficulty, expires_at_ms, mac, counter }

to `submit_to`. On success the WAF returns 204 and the client
retries the original request.

Usage (called by the OC harness or a benchmark script):

    python3 solve_pow.py <nonce> <difficulty>

Prints the discovered counter to stdout.

Dependency: `pip install blake3` — the WAF uses keyed-blake3 for
the MAC and unkeyed-blake3 for the PoW solution check; both must
match what `aegis_security::challenge::pow::pow_solution_valid`
computes.
"""

import sys

try:
    from blake3 import blake3
except ImportError:
    print(
        "error: this script requires the 'blake3' package.\n"
        "install with: pip install blake3",
        file=sys.stderr,
    )
    sys.exit(2)


def leading_zero_bits(b: bytes) -> int:
    """Count leading zero bits across a byte string. Mirrors
    `aegis_security::challenge::pow::leading_zero_bits`."""
    n = 0
    for byte in b:
        if byte == 0:
            n += 8
            continue
        # int.bit_length() returns the index of the highest bit;
        # 8 - bit_length is the count of leading zeros in the byte.
        n += 8 - byte.bit_length()
        break
    return n


def pow_solution_valid(nonce: str, counter: str, difficulty: int) -> bool:
    """Match `aegis_security::challenge::pow::pow_solution_valid`."""
    h = blake3()
    h.update(nonce.encode("ascii"))
    h.update(b":")
    h.update(counter.encode("ascii"))
    digest = h.digest()
    return leading_zero_bits(digest) >= difficulty


def solve(nonce: str, difficulty: int) -> str:
    """Iterate counters until pow_solution_valid returns True.

    With difficulty=16 the average is ~65 K iterations — milliseconds
    on a laptop. Higher difficulties scale exponentially."""
    counter = 0
    while True:
        s = str(counter)
        if pow_solution_valid(nonce, s, difficulty):
            return s
        counter += 1


def main():
    if len(sys.argv) != 3:
        print("usage: solve_pow.py <nonce> <difficulty>", file=sys.stderr)
        sys.exit(2)
    nonce = sys.argv[1]
    try:
        difficulty = int(sys.argv[2])
    except ValueError:
        print(f"error: difficulty must be an integer, got {sys.argv[2]!r}",
              file=sys.stderr)
        sys.exit(2)
    if difficulty < 0 or difficulty > 64:
        print(f"error: difficulty out of range [0, 64], got {difficulty}",
              file=sys.stderr)
        sys.exit(2)
    counter = solve(nonce, difficulty)
    print(counter)


if __name__ == "__main__":
    main()
