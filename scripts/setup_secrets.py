#!/usr/bin/env python3
import base64
import os
import secrets
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env"


def main():
    if ENV_FILE.exists():
        raise SystemExit(f"{ENV_FILE} already exists; preserve its keys for existing data")
    values = {
        "COMMENT_ENCRYPTION_KEY_B64": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        "EXPORT_HMAC_KEY_B64": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
    }
    content = "# Local application secrets. Back up securely; do not commit this file.\n"
    content += "".join(f"{name}={value}\n" for name, value in values.items())
    fd = os.open(ENV_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as env_file:
        env_file.write(content)
    print(f"Created {ENV_FILE}; keep a secure backup of these keys.")


if __name__ == "__main__":
    main()
