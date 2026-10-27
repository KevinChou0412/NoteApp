#!/usr/bin/env python3
import argparse
import os
from pathlib import Path

from security_utils import decode_key, verify_export_bytes


def main():
    parser = argparse.ArgumentParser(description="Verify a NotesApp CSV HMAC footer.")
    parser.add_argument("csv_file", type=Path)
    args = parser.parse_args()
    key = decode_key(os.environ.get("EXPORT_HMAC_KEY_B64"), "EXPORT_HMAC_KEY_B64")
    if not verify_export_bytes(args.csv_file.read_bytes(), key):
        print("INVALID: CSV contents or HMAC footer do not match")
        return 1
    print("VALID: HMAC-SHA256 verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
