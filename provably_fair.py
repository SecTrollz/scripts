#!/usr/bin/env python3
"""
provably_fair.py — Local provably-fair round verifier
--------------------------------------------------------------
Many crypto casinos (Stake, BitStarz-style originals, etc.) use a
"provably fair" scheme: before a round, they show you a HASH of a
server seed (commitment). After the round (or after you rotate
seeds), they reveal the actual server seed. You can then verify
locally that hash(revealed_seed) == the commitment you were shown
earlier, and re-derive the round's random outcome from
(server_seed, client_seed, nonce) to confirm it matches what you
were dealt.

This is entirely local cryptographic verification of data you
already have from your own account — no scraping, no network
calls, no automation of the site.

You'll need, per round, from your account's "fairness"/"seeds" page:
  - server_seed_hash   (shown BEFORE the round — the commitment)
  - server_seed        (revealed AFTER — the preimage)
  - client_seed        (yours, chosen or shown by the site)
  - nonce               (round counter)

Usage:
  python3 provably_fair.py verify-hash \
      --server-seed <hex> --claimed-hash <hex>

  python3 provably_fair.py derive \
      --server-seed <hex> --client-seed <str> --nonce <int> \
      [--cursor <int>] [--count <int>]

Notes:
  - The exact HMAC/hash construction differs slightly by provider.
    The default here implements the common Stake-style scheme
    (HMAC-SHA256(server_seed, client_seed:nonce:cursor), taken in
    4-byte float chunks). If your casino documents a different
    construction, pass --scheme to select it, or adjust
    SCHEMES below to match their published algorithm exactly —
    verification is only meaningful if the math matches theirs.
"""

import argparse
import hashlib
import hmac
import sys


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_hash(server_seed_hex: str, claimed_hash_hex: str) -> bool:
    """Confirms the revealed server seed actually hashes to the
    commitment you were shown before the round started."""
    computed = sha256_hex(bytes.fromhex(server_seed_hex))
    return computed.lower() == claimed_hash_hex.lower()


def hmac_sha256_floats(server_seed: str, client_seed: str, nonce: int,
                        cursor: int = 0, count: int = 5):
    """Common 'Stake-style' provably fair derivation:
    HMAC-SHA256(key=server_seed, msg=f"{client_seed}:{nonce}:{cursor}")
    consumed in 4-byte chunks, each mapped to a float in [0,1).
    Returns a list of floats you can map to card ranks/outcomes
    the same way the site documents.
    """
    floats = []
    cur = cursor
    while len(floats) < count:
        msg = f"{client_seed}:{nonce}:{cur}".encode()
        digest = hmac.new(server_seed.encode(), msg, hashlib.sha256).digest()
        for i in range(0, len(digest), 4):
            if len(floats) >= count:
                break
            chunk = digest[i:i + 4]
            if len(chunk) < 4:
                continue
            value = int.from_bytes(chunk, "big") / 2**32
            floats.append(value)
        cur += 1
    return floats


def floats_to_ranks(floats, num_decks=6):
    """Example mapping of provably-fair floats onto a 1-10 rank
    (blackjack card value) using a standard rank distribution
    (four 10-value cards per 13-rank deck). Casinos document their
    OWN exact shuffle algorithm — this is illustrative only and
    must be adjusted to match the specific site's published spec
    before you treat a mismatch as meaningful evidence."""
    ranks = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 10, 10, 10]
    out = []
    for f in floats:
        idx = int(f * len(ranks))
        idx = min(idx, len(ranks) - 1)
        out.append(ranks[idx])
    return out


SCHEMES = {
    "stake": hmac_sha256_floats,
}


def cmd_verify_hash(args):
    result = verify_hash(args.server_seed, args.claimed_hash)
    if result:
        print("MATCH — the revealed server seed hashes to the commitment you were shown.")
        print("This confirms the server seed wasn't swapped after the fact.")
    else:
        print("MISMATCH — the revealed seed does NOT hash to the commitment shown before the round.")
        print("This is a real red flag worth raising directly with the casino/regulator —")
        print("it means the commitment scheme's core guarantee was violated.")
    sys.exit(0 if result else 1)


def cmd_derive(args):
    scheme_fn = SCHEMES.get(args.scheme, hmac_sha256_floats)
    floats = scheme_fn(args.server_seed, args.client_seed, args.nonce,
                        cursor=args.cursor, count=args.count)
    ranks = floats_to_ranks(floats)
    print("Raw floats (0-1):")
    for f in floats:
        print(f"  {f:.6f}")
    print("\nIllustrative rank mapping (VERIFY against the site's documented")
    print("shuffle algorithm before drawing conclusions — this default mapping")
    print("is a generic example, not necessarily this casino's exact spec):")
    labels = {1: "A", 10: "10/J/Q/K"}
    print("  " + ", ".join(labels.get(r, str(r)) for r in ranks))
    print("\nCompare this sequence against what you were actually dealt for this")
    print("nonce. A mismatch only means something if your rank-mapping code above")
    print("exactly matches the casino's published algorithm — check their fairness")
    print("docs page for the precise spec before treating a mismatch as proof of anything.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    p1 = sub.add_parser("verify-hash", help="Check revealed server seed against its pre-round commitment hash")
    p1.add_argument("--server-seed", required=True, help="hex-encoded revealed server seed")
    p1.add_argument("--claimed-hash", required=True, help="hex-encoded hash shown BEFORE the round")
    p1.set_defaults(func=cmd_verify_hash)

    p2 = sub.add_parser("derive", help="Re-derive round outcome floats from seeds/nonce")
    p2.add_argument("--server-seed", required=True)
    p2.add_argument("--client-seed", required=True)
    p2.add_argument("--nonce", type=int, required=True)
    p2.add_argument("--cursor", type=int, default=0)
    p2.add_argument("--count", type=int, default=10)
    p2.add_argument("--scheme", default="stake", choices=list(SCHEMES.keys()))
    p2.set_defaults(func=cmd_derive)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
