"""AES-GCM encryption for stored evidence files.

New files use an authenticated AES-GCM envelope. The legacy reader is retained
only so existing local evidence can be migrated without data loss.
"""

import hashlib
import hmac
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_FILE = "secret.key"
MAGIC = b"LG-AESGCM-1"
NONCE_SIZE = 12
LEGACY_NONCE_SIZE = 16
LEGACY_BLOCK_SIZE = 32


def generate_key():
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "wb") as file:
            file.write(secrets.token_bytes(32))


def load_key():
    with open(KEY_FILE, "rb") as file:
        key = file.read()
    if len(key) not in (16, 24, 32):
        raise ValueError("The encryption key must be 16, 24, or 32 bytes.")
    return key


generate_key()
_MASTER_KEY = load_key()


def _legacy_keystream(key, nonce, length):
    output = bytearray()
    counter = 0
    while len(output) < length:
        block = hmac.new(
            key,
            nonce + counter.to_bytes(8, "big"),
            hashlib.sha256,
        ).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:length])


def _legacy_decrypt(blob):
    nonce = blob[:LEGACY_NONCE_SIZE]
    tag = blob[LEGACY_NONCE_SIZE:LEGACY_NONCE_SIZE + LEGACY_BLOCK_SIZE]
    ciphertext = blob[LEGACY_NONCE_SIZE + LEGACY_BLOCK_SIZE:]
    enc_key = hmac.new(
        _MASTER_KEY, b"forensivault-encryption", hashlib.sha256
    ).digest()
    mac_key = hmac.new(
        _MASTER_KEY, b"forensivault-authentication", hashlib.sha256
    ).digest()
    expected_tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError(
            "Evidence file failed integrity verification during decryption "
            "-- the encrypted file may be corrupted or tampered with."
        )
    keystream = _legacy_keystream(enc_key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, keystream))


def encrypt_file(filepath):
    with open(filepath, "rb") as file:
        data = file.read()
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = AESGCM(_MASTER_KEY).encrypt(nonce, data, MAGIC)
    encrypted_path = filepath + ".enc"
    with open(encrypted_path, "wb") as file:
        file.write(MAGIC + nonce + ciphertext)
    return encrypted_path


def decrypt_file(filepath):
    with open(filepath, "rb") as file:
        blob = file.read()
    if blob.startswith(MAGIC):
        envelope = blob[len(MAGIC):]
        nonce = envelope[:NONCE_SIZE]
        ciphertext = envelope[NONCE_SIZE:]
        if len(nonce) != NONCE_SIZE or not ciphertext:
            raise ValueError("Evidence file has an invalid AES-GCM envelope.")
        try:
            return AESGCM(_MASTER_KEY).decrypt(nonce, ciphertext, MAGIC)
        except Exception as exc:
            raise ValueError(
                "Evidence file failed AES-GCM integrity verification."
            ) from exc
    return _legacy_decrypt(blob)
