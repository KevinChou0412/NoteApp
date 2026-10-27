# Class 4 — Integrity demonstrations

With the Compose stack running, run the SHA-256, HMAC-SHA256, and RSA-PSS
comparison in the app container:

```sh
docker compose exec -T -w /host web python -m labs.class04.integrity_demo
```

The demonstration uses synthetic data and temporary keys. SHA-256 alone is not
authentication; HMAC uses a shared secret; RSA-PSS allows verification with a
public key. The app's CSV export uses HMAC. Verify a saved original export with
[`web/verify_export.py`](../../web/verify_export.py). See the
[Project 1 threat model](../project1/README.md) for the application context and
the limitations of this coursework protection.
