# NotesApp
Author: ZHOUYI 周毅
Student ID: 2023900903

A small grades application used throughout the Computer Security course. Teachers
record grades and comments for their classes, students read their own grades, and an
admin manages users and classes.

Coursework exercises are organized under `labs/` and `tests/`:

- [Session 03: symmetric encryption](labs/session03/README.md)
- [Class 04: integrity and export verification](labs/class04/README.md)
- [Class 05: password audit](labs/class05/README.md)
- [Project 1: threat model](labs/project1/README.md)

## Run locally

Requirements: Docker with the Compose plugin.

```sh
python3 scripts/setup_secrets.py
docker compose up --build
```

The first run migrates the seed comments to AES-GCM ciphertext. Keep the ignored
`.env` file and a secure backup of its keys; do not generate replacement keys for an
existing database. The default teaching stack is available at http://localhost:8080.

For local HTTPS, run `sh scripts/generate_cert.sh` and start both Compose files:

```sh
docker compose -f docker-compose.yml -f docker-compose.https.yml up --build
```

Browse to https://localhost. The certificate is self-signed and intended only for
local testing; a browser trust warning is expected. Stop the HTTPS stack without
deleting its database volume with:

```sh
docker compose -f docker-compose.yml -f docker-compose.https.yml down
```

The default stack deliberately contains security flaws for coursework and must not
be exposed to untrusted networks.

With the stack running, run the utility tests in the same Python 3.11 container
used by the app:

```sh
docker compose exec -T -w /host web python -m unittest discover -s tests -v
```

The app intentionally retains vulnerabilities for coursework. The security labs
demonstrate selected protections; they do not make the entire app production-safe.
See the Project 1 threat model for the assessed scope, risks, and limitations.

## Test accounts

| Role    | Username      | Password   |
|---------|---------------|------------|
| Student | `alice`       | `alicepw`  |
| Teacher | `prof.turing` | `teach123` |
| Admin   | `admin`       | `admin123` |

These are synthetic course accounts, not production credentials.
