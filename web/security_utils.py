import base64
import hashlib
import hmac
import re
from os import urandom

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_COMMENT_PREFIX = "aesgcm:v1:"
_PASSWORD_HASHER = PasswordHasher()


def decode_key(value, name, size=32):
    if not value:
        raise ValueError(f"{name} is required; run scripts/setup_secrets.py")
    try:
        key = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{name} must be valid base64") from exc
    if len(key) != size:
        raise ValueError(f"{name} must decode to exactly {size} bytes")
    return key


def _comment_aad(note_id):
    return f"notes:comment:v1:{note_id}".encode("utf-8")


def encrypt_comment(note_id, comment, key):
    if comment is None:
        return None
    nonce = urandom(12)
    encrypted = AESGCM(key).encrypt(nonce, comment.encode("utf-8"), _comment_aad(note_id))
    return _COMMENT_PREFIX + base64.b64encode(nonce + encrypted).decode("ascii")


def decrypt_comment(note_id, value, key):
    if value is None:
        return None
    if not value.startswith(_COMMENT_PREFIX):
        raise ValueError("comment is not encrypted")
    try:
        combined = base64.b64decode(value[len(_COMMENT_PREFIX):], validate=True)
        if len(combined) < 12 + 16:
            raise ValueError("ciphertext is too short")
        plaintext = AESGCM(key).decrypt(combined[:12], combined[12:], _comment_aad(note_id))
        return plaintext.decode("utf-8")
    except (InvalidTag, ValueError, UnicodeDecodeError) as exc:
        raise ValueError("comment ciphertext is invalid") from exc


def hash_password(password):
    return _PASSWORD_HASHER.hash(password)


def verify_password(password, stored):
    if stored.startswith("$argon2"):
        try:
            matched = _PASSWORD_HASHER.verify(stored, password)
        except (InvalidHashError, VerificationError, VerifyMismatchError):
            return False, None
        replacement = hash_password(password) if _PASSWORD_HASHER.check_needs_rehash(stored) else None
        return matched, replacement
    matched = hmac.compare_digest(stored.encode("utf-8"), password.encode("utf-8"))
    return matched, hash_password(password) if matched else None


def export_hmac(csv_bytes, key):
    return hmac.new(key, csv_bytes, hashlib.sha256).hexdigest()


def verify_export_bytes(data, key):
    match = re.search(rb"# HMAC-SHA256: ([0-9a-f]{64})\r?\n$", data)
    if not match:
        return False
    body = data[:match.start()]
    expected = export_hmac(body, key).encode("ascii")
    return hmac.compare_digest(expected, match.group(1))
