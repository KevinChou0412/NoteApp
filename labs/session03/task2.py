#!/usr/bin/env python3
import argparse
import hashlib
import secrets
import struct
import zlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.padding import PKCS7


def create_pattern(size=128):
    rows = []
    pixels = bytearray()
    for y in range(size):
        row = bytearray()
        for x in range(size):
            tile = (24, 84, 150) if (x // 16 + y // 16) % 2 == 0 else (238, 190, 72)
            color = (210, 72, 65) if 40 <= x < 88 and 40 <= y < 88 else tile
            row.extend(color)
        rows.append(bytes(row))
        pixels.extend(row)
    return size, pixels, rows


def png_chunk(chunk_type, data):
    content = chunk_type + data
    return struct.pack(">I", len(data)) + content + struct.pack(">I", zlib.crc32(content) & 0xFFFFFFFF)


def save_png(path, size, rows):
    header = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
    image_data = b"".join(b"\x00" + row for row in rows)
    content = (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", header)
        + png_chunk(b"IDAT", zlib.compress(image_data))
        + png_chunk(b"IEND", b"")
    )
    path.write_bytes(content)


def png_rows(pixels, size):
    row_size = size * 3
    return [pixels[index:index + row_size] for index in range(0, len(pixels), row_size)]


def ecb_encrypt(plaintext, key):
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return padded, encryptor.update(padded) + encryptor.finalize()


def ecb_decrypt(ciphertext, key):
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def image_from_bytes(data, size):
    return Image.frombytes("RGB", size, data)


def main():
    parser = argparse.ArgumentParser(description="Compare AES-ECB and AES-GCM on synthetic image pixels.")
    parser.add_argument("--output", type=Path, default=Path("labs/session03/task2_output"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    size, plaintext, original_rows = create_pattern()
    key = secrets.token_bytes(32)
    padded, ecb = ecb_encrypt(plaintext, key)
    nonce = secrets.token_bytes(12)
    gcm = AESGCM(key).encrypt(nonce, plaintext, b"synthetic-image-v1")
    if ecb_decrypt(ecb, key) != plaintext:
        raise RuntimeError("ECB round-trip verification failed")
    if AESGCM(key).decrypt(nonce, gcm, b"synthetic-image-v1") != plaintext:
        raise RuntimeError("GCM round-trip verification failed")

    save_png(args.output / "original.png", size, original_rows)
    save_png(args.output / "ecb.png", size, png_rows(ecb[:len(plaintext)], size))
    save_png(args.output / "gcm.png", size, png_rows(gcm[:len(plaintext)], size))
    report = (
        f"synthetic pixels: {len(plaintext)} bytes\n"
        f"ECB padded input: {len(padded)} bytes\n"
        f"round-trip: ECB and GCM verified\n"
        f"ECB repeated 16-byte blocks: {len(ecb) // 16 - len(set(ecb[i:i+16] for i in range(0, len(ecb), 16)))}\n"
        f"plaintext SHA-256: {hashlib.sha256(plaintext).hexdigest()}\n"
        "Key and nonce are randomly generated and not saved.\n"
        "Ciphertext preview PNGs are lossy visualizations, not decryptable backups.\n"
    )
    (args.output / "results.txt").write_text(report, encoding="utf-8")
    print(report, end="")
    print(f"Images and results written to {args.output}")


if __name__ == "__main__":
    main()
