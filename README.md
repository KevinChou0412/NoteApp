# NotesApp
Author: ZHOUYI 周毅
Student ID: 2023900903

A small grades application used throughout the Computer Security course. Teachers
record grades and comments for their classes, students read their own grades, and an
admin manages users and classes.

Coursework exercises are organized under `labs/` and `tests/`.

## Run locally

Requirements: Docker with the Compose plugin.

```sh
python3 scripts/setup_secrets.py
docker compose up --build
```

The first run migrates the seed comments to AES-GCM ciphertext. Keep the ignored
`.env` file and a secure backup of its keys; do not generate replacement keys for an
existing database. The default teaching stack is available at http://localhost:8080.

For local HTTPS, run `sh scripts/generate_cert.sh` and start Compose with
`-f docker-compose.https.yml`. The certificate is self-signed and intended only for
local testing. The default stack deliberately contains security flaws for coursework
and must not be exposed to untrusted networks.

## Test accounts

| Role    | Username      | Password   |
|---------|---------------|------------|
| Student | `alice`       | `alicepw`  |
| Teacher | `prof.turing` | `teach123` |
| Admin   | `admin`       | `admin123` |

These are synthetic course accounts, not production credentials.
