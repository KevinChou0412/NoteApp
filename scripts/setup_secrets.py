#!/usr/bin/env python3
import base64
import os
import secrets
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env"
SECRET_NAMES = (
    "COMMENT_ENCRYPTION_KEY_B64",
    "EXPORT_HMAC_KEY_B64",
    "JWT_SECRET",
)


def generate_secret(name):
    if name == "JWT_SECRET":
        return secrets.token_urlsafe(32)
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def main():
    if ENV_FILE.exists():
        existing = ENV_FILE.read_text(encoding="utf-8")
        lines = existing.splitlines()
        populated = set()
        empty_lines = {}
        for index, line in enumerate(lines):
            name, separator, value = line.partition("=")
            name = name.strip()
            if not separator or name not in SECRET_NAMES:
                continue
            if value.strip().strip("\"'"):
                populated.add(name)
            else:
                empty_lines[name] = index

        missing = set(SECRET_NAMES) - populated
        if not missing:
            raise SystemExit(f"{ENV_FILE} already contains all required secrets")

        additions = []
        for name in SECRET_NAMES:
            if name not in missing:
                continue
            assignment = f"{name}={generate_secret(name)}"
            if name in empty_lines:
                lines[empty_lines[name]] = assignment
            else:
                additions.append(assignment)
        lines.extend(additions)
        ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.chmod(ENV_FILE, 0o600)
        print(f"Added missing secrets to {ENV_FILE}; existing keys were preserved.")
        return

    content = "# Local application secrets. Back up securely; do not commit this file.\n"
    content += "".join(f"{name}={generate_secret(name)}\n" for name in SECRET_NAMES)
    fd = os.open(ENV_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as env_file:
        env_file.write(content)
    print(f"Created {ENV_FILE}; keep a secure backup of these keys.")


if __name__ == "__main__":
    main()
