# Project 1 — NotesApp threat model

## Purpose and scope

This threat model covers the local NotesApp teaching stack: a browser, the Flask
application, PostgreSQL, and the optional nginx HTTPS reverse proxy. It focuses on
the confidentiality and integrity of student grades, comments, account credentials,
and application secrets. The app is deliberately vulnerable; this is a coursework
analysis, not a claim that the system is safe to deploy.

Included: login and sessions, student and teacher pages, grade changes, CSV export,
the notes API, administration features, database storage, application logs, and the
optional local TLS setup.

Excluded: public cloud hosting, institution identity providers, real student data,
external email services, and production operations. The supplied accounts and data
are synthetic. Keep the stack bound to localhost and do not expose it to untrusted
networks.

## System overview and trust boundaries

```text
 Student / Teacher / Admin browser
              |
       TB1: client connection
        HTTP (base) or HTTPS (overlay)
              |
       [nginx TLS proxy] (HTTPS overlay only)
              |
       TB2: Compose private network
              |
       [Flask / web application] --------> [application log]
              |
       TB3: database credentials/network
              |
       [PostgreSQL: users, grades, comments]

 [local .env keys] ---> Flask (comment AES-GCM key, export HMAC key)
 [local TLS key]   ---> nginx (HTTPS overlay)
```

- **TB1** separates user-controlled browsers from the service. In the base Compose
  setup traffic is plain HTTP. In the HTTPS overlay, nginx serves TLS locally and
  redirects HTTP to HTTPS; the self-signed certificate is not a public trust chain.
- **TB2** separates the reverse proxy and application containers. Compose networking
  is not a substitute for application authorization.
- **TB3** separates the application from the database. Database credentials are
  supplied to the application, which can read and modify all application records.
- The `.env` file and nginx private key are local secrets. Their host filesystem
  permissions and backups are part of the trust boundary.

## Assets and security goals

| Asset | Security goal | Impact if compromised |
|---|---|---|
| Student grades and teacher comments | Confidentiality and integrity | Privacy harm, incorrect academic outcomes |
| Usernames, passwords, and account roles | Confidentiality and authenticity | Account takeover and privilege abuse |
| Session cookies and bearer tokens | Authenticity and authorization | Impersonation and unauthorized record access |
| Comment encryption key | Confidentiality of encrypted comments | Stored ciphertext can be exposed |
| Export HMAC key | Integrity/authenticity of exported CSVs | Forged exports may validate |
| Database contents and availability | Integrity and availability | Data loss, tampering, or service outage |
| Application logs | Appropriate accountability and confidentiality | Investigation gaps or exposure of sensitive values |
| TLS private key | Confidentiality and server authenticity | Local TLS impersonation |

## Actors and assumptions

| Actor | Intended access | Relevant trust assumption |
|---|---|---|
| Student | Own grades and comments | Authenticated account does not imply access to other students' records |
| Teacher | Classes and grades they are responsible for | Teacher role must be scoped to assigned classes |
| Administrator | User and class management | Administrative actions are especially sensitive |
| Unauthenticated visitor | Login and public endpoints | May submit arbitrary requests and input |
| Host operator | Local containers, volumes, and secret files | Controls the machine running the lab |
| Malicious or curious course user | May interact with the intentionally vulnerable app | Must remain within the local, synthetic lab environment |

Assume the host and Docker daemon are trusted for this local exercise. Do not put
real credentials or student records in the test database. A compromised Flask
process can use its database credentials and encryption keys; encryption at rest
does not protect data from a running, authorized application process.

## STRIDE analysis

| STRIDE category | Threat scenario | Existing exposure in this teaching app | Impact | Recommended control |
|---|---|---|---|---|
| **Spoofing** | A caller impersonates a user or forges a higher-privilege identity | The app accepts weakly protected bearer-token claims; default seeded passwords are predictable | Unauthorized account/role use | Replace custom token handling with a maintained library, enforce signature and claim validation, use strong unique secrets, rotate sessions after login, and replace seeded credentials |
| **Tampering** | A caller changes grades, comments, accounts, or exported data without authority | Login SQL is constructed from input; grade/admin forms lack CSRF protection; the admin ping path invokes a shell with user input | Unauthorized data changes or command execution in the lab container | Use parameterized SQL, CSRF defenses, strict validation, safe process APIs, least-privilege containers, and audited changes |
| **Repudiation** | A user denies making a sensitive change | Logs are minimal, local, and not protected against alteration; some log writes are silently ignored | Weak incident reconstruction | Use structured audit events with actor, action, target, and time; protect and rotate logs; report logging failures |
| **Information disclosure** | A user reads another user's grades/comments or credentials | Notes API lacks record ownership checks; bearer identity can be forged; base setup uses HTTP; comments/passwords have legacy storage states | Student privacy breach and account compromise | Enforce per-record authorization on every request, use HTTPS, use adaptive password hashing, encrypt sensitive stored fields, and avoid returning raw errors |
| **Denial of service** | Repeated or costly requests exhaust app/database resources | No rate limiting or request-size policy is visible; database queries and authentication are reachable through the web process | Service degradation or outage | Add request limits and rate limits, bound query work, set database/app timeouts, monitor resource usage, and apply graceful overload controls |
| **Elevation of privilege** | A student or teacher obtains admin-level capabilities | Role claims can be trusted from a weak token; authorization is inconsistent between routes; admin command handling is unsafe | Full application and data compromise | Derive identity from a validated session, centralize role checks, enforce least privilege in each route and query, and isolate admin functions |

## Risk prioritization

Priorities are qualitative for the local coursework system (likelihood and impact
are both considered).

1. **Critical — broken authentication/authorization and SQL injection:** can expose
   or alter records across roles. Fix identity validation, parameterize queries,
   and enforce ownership/role checks before any deployment.
2. **High — unsafe admin command handling and missing CSRF defenses:** could turn
   an authenticated browser action into unauthorized server-side effects. Remove
   shell interpretation, add CSRF protection, and restrict administrative actions.
3. **High — plaintext HTTP, weak/default credentials, and legacy password storage:**
   risk credential interception or reuse. Use HTTPS end-to-end where possible,
   unique credentials, and adaptive password hashing.
4. **Medium — comment storage, export integrity, and weak auditability:** AES-GCM
   comment-at-rest encryption and CSV HMAC reduce selected risks when keys are
   protected, but do not compensate for application compromise or authorization
   flaws. Protect keys and improve audit logging.
5. **Medium — resource exhaustion:** add limits and monitoring before any shared
   or externally reachable deployment.

## Coursework controls and limitations

- **AES-GCM comments:** comments are encrypted with a per-record nonce and record
  ID as authenticated additional data; startup migrates plaintext comments and
  validates already-encrypted values. Losing or replacing the key makes comments
  unreadable. The database and application process still need access to plaintext
  when displaying or exporting comments.
- **CSV HMAC:** a verifier detects changes to a CSV body when the correct secret key
  is available. HMAC does not provide non-repudiation, and a party holding the key
  can generate another valid MAC.
- **HTTPS overlay:** local TLS protects browser traffic in transit to nginx. The
  self-signed certificate is for local testing only, and the base HTTP setup remains
  available for coursework comparison.
- **Argon2id:** new accounts use Argon2id; a legacy password is upgraded after a
  successful login. Seeded accounts are still initialized with weak plaintext
  passwords, and accounts that never log in are not upgraded automatically.
- These controls are partial lab exercises. The deliberately planted authentication,
  authorization, input-handling, and operational flaws remain and must be fixed
  before a real deployment.

## Verification and evidence record

Run the applicable tests and scripts locally, then record the actual output and
date for your submission. Do not invent screenshots, packet captures, or classroom
observations.

| Check | Command / action | Evidence |
|---|---|---|
| Compose configuration | `docker compose config -q` with the base and HTTPS files | Both configurations validated successfully |
| Utility tests | `docker compose exec -T -w /host web python -m unittest discover -s tests -v` | 9 tests passed on 2026-10-27 using Python 3.11.18 |
| Comment encryption behavior | Start the app and check the seeded rows; teacher page displays decrypted comments | Startup migrated all non-null comments; database count for remaining plaintext comments was 0 |
| Export integrity | Sign in as the synthetic teacher and request `/export.csv` | Original export verified; a locally modified export was rejected |
| HTTPS behavior | `scripts/smoke_https.py` after starting the HTTPS Compose overlay | HTTPS `/login` returned 200; HTTP `/login` returned 301 to `https://localhost/login` |
| Password migration | Sign in once with the seeded teacher account; inspect only whether its stored value has the Argon2 prefix | Successful login upgraded that legacy password to Argon2id |
| Password audit | `docker compose exec -T -w /host web python -m labs.class05.password_audit` | Local synthetic measurements recorded in [results.json](../class05/results.json) on 2026-10-27 using Python 3.11.18 |
| Threat-model review | Compare this analysis with the routes and data flows | Add course-specific instructor feedback if required |

The local Docker HTTPS stack was started and these checks passed on 2026-10-27.
It is bound to localhost. The database uses a local Compose volume and the existing
ignored `.env` keys; preserve both if you want to keep using this database.
