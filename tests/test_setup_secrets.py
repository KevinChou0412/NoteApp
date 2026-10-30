import base64
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import setup_secrets


class SetupSecretsTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.env_file = Path(self.temp_dir.name) / ".env"
        self.env_patch = patch.object(setup_secrets, "ENV_FILE", self.env_file)
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def read_values(self):
        return {
            name: value
            for line in self.env_file.read_text(encoding="utf-8").splitlines()
            if (name := line.partition("=")[0]) in setup_secrets.SECRET_NAMES
            for value in [line.partition("=")[2]]
        }

    def test_creates_all_secrets_for_a_new_env_file(self):
        setup_secrets.main()
        values = self.read_values()

        self.assertEqual(set(values), set(setup_secrets.SECRET_NAMES))
        self.assertEqual(len(base64.b64decode(values["COMMENT_ENCRYPTION_KEY_B64"])), 32)
        self.assertEqual(len(base64.b64decode(values["EXPORT_HMAC_KEY_B64"])), 32)
        self.assertGreaterEqual(len(values["JWT_SECRET"]), 32)
        self.assertEqual(self.env_file.stat().st_mode & 0o777, 0o600)

    def test_adds_missing_keys_without_replacing_existing_keys(self):
        self.env_file.write_text(
            "COMMENT_ENCRYPTION_KEY_B64=existing-comment-key\n"
            "EXPORT_HMAC_KEY_B64=\n"
            "JWT_SECRET=\n",
            encoding="utf-8",
        )

        setup_secrets.main()
        values = self.read_values()

        self.assertEqual(values["COMMENT_ENCRYPTION_KEY_B64"], "existing-comment-key")
        self.assertEqual(len(base64.b64decode(values["EXPORT_HMAC_KEY_B64"])), 32)
        self.assertGreaterEqual(len(values["JWT_SECRET"]), 32)
        self.assertEqual(len(values), 3)

    def test_refuses_to_replace_all_existing_keys(self):
        self.env_file.write_text(
            "COMMENT_ENCRYPTION_KEY_B64=comment\n"
            "EXPORT_HMAC_KEY_B64=export\n"
            "JWT_SECRET=jwt\n",
            encoding="utf-8",
        )

        with self.assertRaises(SystemExit):
            setup_secrets.main()

        self.assertEqual(
            self.env_file.read_text(encoding="utf-8"),
            "COMMENT_ENCRYPTION_KEY_B64=comment\n"
            "EXPORT_HMAC_KEY_B64=export\n"
            "JWT_SECRET=jwt\n",
        )


if __name__ == "__main__":
    unittest.main()
