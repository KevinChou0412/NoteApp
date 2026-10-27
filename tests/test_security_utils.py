import base64
import os
import unittest

from web.security_utils import (
    decode_key, decrypt_comment, encrypt_comment, export_hmac, hash_password,
    verify_export_bytes, verify_password,
)
from argon2 import PasswordHasher


class CommentEncryptionTests(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(32)

    def test_round_trip_unicode_empty_and_null(self):
        self.assertEqual(decrypt_comment(12, encrypt_comment(12, "评语 ✓", self.key), self.key), "评语 ✓")
        self.assertEqual(decrypt_comment(12, encrypt_comment(12, "", self.key), self.key), "")
        self.assertIsNone(encrypt_comment(12, None, self.key))
        self.assertIsNone(decrypt_comment(12, None, self.key))

    def test_nonce_varies_and_record_id_is_authenticated(self):
        first = encrypt_comment(12, "same text", self.key)
        second = encrypt_comment(12, "same text", self.key)
        self.assertNotEqual(first, second)
        with self.assertRaises(ValueError):
            decrypt_comment(13, first, self.key)

    def test_tampering_and_wrong_key_fail(self):
        value = encrypt_comment(12, "private comment", self.key)
        changed = value[:-2] + ("AA" if value[-2:] != "AA" else "BB")
        with self.assertRaises(ValueError):
            decrypt_comment(12, changed, self.key)
        with self.assertRaises(ValueError):
            decrypt_comment(12, value, os.urandom(32))

    def test_plaintext_is_rejected_by_normal_decrypt(self):
        with self.assertRaises(ValueError):
            decrypt_comment(12, "legacy plaintext", self.key)


class PasswordTests(unittest.TestCase):
    def test_legacy_password_upgrades_only_after_valid_login(self):
        matched, replacement = verify_password("legacy-value", "legacy-value")
        self.assertTrue(matched)
        self.assertTrue(replacement.startswith("$argon2"))
        self.assertEqual(verify_password("wrong", "legacy-value"), (False, None))

    def test_argon_hash_verifies_and_bad_hash_fails_closed(self):
        encoded = hash_password("example")
        self.assertEqual(verify_password("example", encoded), (True, None))
        self.assertEqual(verify_password("wrong", encoded), (False, None))
        self.assertEqual(verify_password("example", "$argon2id$broken"), (False, None))

    def test_outdated_argon_parameters_are_rehashed_after_success(self):
        old_hasher = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)
        outdated_hash = old_hasher.hash("example")
        matched, replacement = verify_password("example", outdated_hash)
        self.assertTrue(matched)
        self.assertTrue(replacement.startswith("$argon2"))
        self.assertNotEqual(replacement, outdated_hash)


class ExportIntegrityTests(unittest.TestCase):
    def test_export_authentication_detects_changes(self):
        key = os.urandom(32)
        csv_body = b"student,class,grade,comment\r\nalice,Math,15,Good\r\n"
        signature = export_hmac(csv_body, key).encode("ascii")
        data = csv_body + b"# HMAC-SHA256: " + signature + b"\r\n"
        self.assertTrue(verify_export_bytes(data, key))
        self.assertFalse(verify_export_bytes(data.replace(b"15", b"05", 1), key))
        self.assertFalse(verify_export_bytes(data + b"extra\r\n", key))

    def test_keys_are_validated(self):
        key = base64.b64encode(b"k" * 32).decode("ascii")
        self.assertEqual(decode_key(key, "test"), b"k" * 32)
        with self.assertRaises(ValueError):
            decode_key("not base64", "test")
        with self.assertRaises(ValueError):
            decode_key(base64.b64encode(b"short").decode("ascii"), "test")


if __name__ == "__main__":
    unittest.main()
