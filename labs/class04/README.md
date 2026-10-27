# Class 4 — Integrity demonstrations

Run the local SHA-256, HMAC-SHA256, and RSA-PSS comparison:

```sh
python3 labs/class04/integrity_demo.py
```

The demonstration uses synthetic data and temporary keys. SHA-256 alone is not
authentication; HMAC uses a shared secret; RSA-PSS allows verification with a
public key. The app's CSV export uses HMAC. Verify a saved original export with
[`web/verify_export.py`](../../web/verify_export.py), as described in
[`docs/export-integrity.md`](../../docs/export-integrity.md).
