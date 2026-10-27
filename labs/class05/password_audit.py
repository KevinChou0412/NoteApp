#!/usr/bin/env python3
"""Offline password-hash exercise over synthetic, in-memory accounts only."""
import argparse
import hashlib
import json
import platform
import statistics
import sys
import time
from datetime import date
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


ACCOUNTS = {
    "demo_user_a": "autumn2026",
    "demo_user_b": "sable-moon-42",
    "demo_user_c": "6f3a9d2c8b1e",
}
WORDLIST = ("welcome1", "autumn2026", "letmein", "password123", "sablemoon")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("labs/class05/results.json"))
    args = parser.parse_args()

    md5_hashes = {name: hashlib.md5(password.encode(), usedforsecurity=False).hexdigest()
                  for name, password in ACCOUNTS.items()}
    matched = set()
    for candidate in WORDLIST:
        digest = hashlib.md5(candidate.encode(), usedforsecurity=False).hexdigest()
        matched.update(name for name, value in md5_hashes.items()
                       if name not in matched and value == digest)

    checks = 100_000
    targets = set(md5_hashes.values())
    benchmark_matches = 0
    started = time.perf_counter()
    for index in range(checks):
        candidate = WORDLIST[index % len(WORDLIST)]
        digest = hashlib.md5(candidate.encode(), usedforsecurity=False).hexdigest()
        benchmark_matches += digest in targets
    elapsed = time.perf_counter() - started
    print(f"Synthetic accounts matched by tiny wordlist: {len(matched)}/{len(ACCOUNTS)}")
    print(f"MD5 checks: {checks}; {checks / elapsed:,.0f} checks/second (local CPU run)")

    hasher = PasswordHasher(time_cost=2, memory_cost=32768, parallelism=1)
    target_hash = hasher.hash(ACCOUNTS["demo_user_a"])
    samples = []
    for _ in range(5):
        started = time.perf_counter()
        try:
            hasher.verify(target_hash, "incorrect-demo-candidate")
        except VerifyMismatchError:
            pass
        samples.append(time.perf_counter() - started)
    median_seconds = statistics.median(samples)
    print(f"Argon2id failed verification median: {median_seconds * 1000:.3f} ms "
          "(memory=32 MiB, time=2, parallelism=1; local CPU run)")
    print("Only synthetic in-memory accounts were used; no external dump or service was accessed.")

    result = {
        "recorded_on": date.today().isoformat(),
        "runtime": sys.version.split()[0],
        "platform": platform.platform(),
        "synthetic_account_count": len(ACCOUNTS),
        "wordlist_candidate_count": len(WORDLIST),
        "wordlist_matches": len(matched),
        "md5_checks": checks,
        "md5_checks_per_second": round(checks / elapsed, 2),
        "benchmark_matches": benchmark_matches,
        "argon2id": {
            "memory_kib": 32768,
            "time_cost": 2,
            "parallelism": 1,
            "failed_verification_samples": len(samples),
            "median_ms": round(median_seconds * 1000, 3),
        },
        "scope": "synthetic in-memory accounts only",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Recorded this run in {args.output}")


if __name__ == "__main__":
    main()
