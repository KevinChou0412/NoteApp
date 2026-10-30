import json
import os
import secrets
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


WEB_DIR = Path(__file__).resolve().parents[1] / "web"
sys.path.insert(0, str(WEB_DIR))
os.environ.setdefault("JWT_SECRET", secrets.token_urlsafe(32))

import app as notes_app


class JwtVerificationTests(unittest.TestCase):
    def setUp(self):
        self.secret = "test-only-random-secret"
        secret_patch = patch.object(notes_app, "JWT_SECRET", self.secret)
        secret_patch.start()
        self.addCleanup(secret_patch.stop)

    def make_token(self, header, payload, secret):
        header_b64 = notes_app._b64url(json.dumps(header).encode())
        payload_b64 = notes_app._b64url(json.dumps(payload).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = notes_app._b64url(
            notes_app.hmac.new(
                secret.encode(), signing_input, notes_app.hashlib.sha256
            ).digest()
        )
        return f"{header_b64}.{payload_b64}.{signature}"

    def test_rejects_unsigned_none_token(self):
        header = notes_app._b64url(json.dumps({"alg": "none"}).encode())
        payload = notes_app._b64url(json.dumps({"role": "teacher"}).encode())

        self.assertIsNone(notes_app.verify_jwt(f"{header}.{payload}."))

    def test_api_rejects_unsigned_none_token(self):
        header = notes_app._b64url(json.dumps({"alg": "none"}).encode())
        payload = notes_app._b64url(json.dumps({"role": "teacher"}).encode())
        response = notes_app.app.test_client().get(
            "/api/notes/3",
            headers={"Authorization": f"Bearer {header}.{payload}."},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json(), {"error": "unauthorized"})

    def test_rejects_algorithm_other_than_exact_hs256(self):
        token = self.make_token({"alg": "hs256"}, {"user_id": 1}, self.secret)

        self.assertIsNone(notes_app.verify_jwt(token))

    def test_rejects_token_signed_with_old_weak_secret(self):
        token = self.make_token(
            {"alg": "HS256"}, {"role": "teacher"}, "s3cr3t"
        )

        self.assertIsNone(notes_app.verify_jwt(token))

    def test_api_rejects_token_signed_with_old_weak_secret(self):
        token = self.make_token(
            {"alg": "HS256"}, {"role": "teacher"}, "s3cr3t"
        )
        response = notes_app.app.test_client().get(
            "/api/notes/3",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json(), {"error": "unauthorized"})

    def test_accepts_valid_hs256_token(self):
        payload = {"user_id": 1, "username": "alice", "role": "student"}
        token = notes_app.make_jwt(payload)

        self.assertEqual(notes_app.verify_jwt(token), payload)


if __name__ == "__main__":
    unittest.main()
