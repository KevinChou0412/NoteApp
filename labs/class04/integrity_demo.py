#!/usr/bin/env python3
import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def main():
    message = b"Synthetic grade export: student=demo, grade=15.0\n"
    changed = message.replace(b"15.0", b"05.0")
    print("SHA-256:", hashlib.sha256(message).hexdigest())

    shared_key = secrets.token_bytes(32)
    tag = hmac.new(shared_key, message, hashlib.sha256).hexdigest()
    print("HMAC-SHA256 valid:", hmac.compare_digest(
        tag, hmac.new(shared_key, message, hashlib.sha256).hexdigest()))
    print("HMAC-SHA256 detects edit:", not hmac.compare_digest(
        tag, hmac.new(shared_key, changed, hashlib.sha256).hexdigest()))

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    private_key.public_key().verify(
        signature,
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    print("RSA-PSS signature valid: True")
    try:
        private_key.public_key().verify(
            signature,
            changed,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature:
        print("RSA-PSS detects edit: True")


if __name__ == "__main__":
    main()
