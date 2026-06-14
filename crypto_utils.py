"""Encryption, hashing, and key management utilities."""

import os
import hashlib
import hmac
import json
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


def generate_key() -> bytes:
    """Generate a random 256-bit symmetric key."""
    return os.urandom(32)


def encrypt_blob(plaintext: bytes, key: bytes) -> bytes:
    """AES-256-CBC encrypt with random IV prepended."""
    iv = os.urandom(16)
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext


def decrypt_blob(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-CBC blob (IV is first 16 bytes)."""
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def compute_hash(data: bytes) -> str:
    """SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def hash_filename(name: str) -> str:
    """Hash a filename to a random-looking server-side name."""
    return hashlib.sha256(name.encode() + os.urandom(16)).hexdigest()


def compute_chain_hash(prev_hash: str, operation: str, inode_id: str,
                       merkle_root: str, timestamp: float) -> str:
    """Compute the next hash in the fork-consistency chain."""
    record = f"{prev_hash}|{operation}|{inode_id}|{merkle_root}|{timestamp}"
    return hashlib.sha256(record.encode()).hexdigest()


def bytes_to_b64(data: bytes) -> str:
    """Encode bytes as base64 string for JSON serialization."""
    return base64.b64encode(data).decode()


def b64_to_bytes(s: str) -> bytes:
    """Decode base64 string back to bytes."""
    return base64.b64decode(s)
