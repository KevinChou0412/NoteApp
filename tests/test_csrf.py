import os
import secrets
import sys
import unittest
from pathlib import Path

from werkzeug.exceptions import BadRequest


WEB_DIR = Path(__file__).resolve().parents[1] / "web"
sys.path.insert(0, str(WEB_DIR))
os.environ.setdefault("JWT_SECRET", secrets.token_urlsafe(32))

import app as notes_app


class CsrfProtectionTests(unittest.TestCase):
    def test_post_without_session_token_is_rejected(self):
        with notes_app.app.test_request_context("/grades", method="POST"):
            with self.assertRaises(BadRequest):
                notes_app.app.preprocess_request()

    def test_post_with_wrong_token_is_rejected(self):
        with notes_app.app.test_request_context(
            "/grades", method="POST", data={"csrf_token": "wrong"}
        ):
            notes_app.session["csrf"] = "expected"
            with self.assertRaises(BadRequest):
                notes_app.app.preprocess_request()

    def test_post_with_matching_token_passes_csrf_check(self):
        with notes_app.app.test_request_context(
            "/grades", method="POST", data={"csrf_token": "expected"}
        ):
            notes_app.session["csrf"] = "expected"
            self.assertIsNone(notes_app.app.preprocess_request())

    def test_token_is_stable_within_a_session(self):
        with notes_app.app.test_request_context("/teacher"):
            first = notes_app.csrf_token()
            self.assertEqual(notes_app.csrf_token(), first)


if __name__ == "__main__":
    unittest.main()
