"""Tests for crypto primitives and data structures."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from crypto_utils import (
    generate_key, encrypt_blob, decrypt_blob, compute_hash,
    bytes_to_b64, b64_to_bytes,
)
from models import Inode, ChildEntry, Profile, new_inode_id
from merkle import compute_merkle_hash, compute_chain_entry, verify_chain


def test_encrypt_decrypt_roundtrip():
    key = generate_key()
    plaintext = b"hello world, this is a secret message!"
    ciphertext = encrypt_blob(plaintext, key)
    assert ciphertext != plaintext
    result = decrypt_blob(ciphertext, key)
    assert result == plaintext


def test_different_keys_different_ciphertext():
    k1 = generate_key()
    k2 = generate_key()
    plaintext = b"same message"
    c1 = encrypt_blob(plaintext, k1)
    c2 = encrypt_blob(plaintext, k2)
    assert c1 != c2


def test_empty_data():
    key = generate_key()
    plaintext = b""
    ciphertext = encrypt_blob(plaintext, key)
    result = decrypt_blob(ciphertext, key)
    assert result == plaintext


def test_large_data():
    key = generate_key()
    plaintext = os.urandom(1024 * 100)  # 100KB
    ciphertext = encrypt_blob(plaintext, key)
    result = decrypt_blob(ciphertext, key)
    assert result == plaintext


def test_b64_roundtrip():
    data = os.urandom(32)
    encoded = bytes_to_b64(data)
    assert isinstance(encoded, str)
    decoded = b64_to_bytes(encoded)
    assert decoded == data


def test_hash_deterministic():
    data = b"test data"
    h1 = compute_hash(data)
    h2 = compute_hash(data)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


def test_hash_different_data():
    h1 = compute_hash(b"data1")
    h2 = compute_hash(b"data2")
    assert h1 != h2


def test_inode_serialization():
    key = generate_key()
    child_key = generate_key()
    inode = Inode(
        inode_id=new_inode_id(),
        is_dir=True,
        children={"test.txt": ChildEntry(new_inode_id(), child_key)},
        data=b"",
        shared_with=["bob"],
        parent_id=new_inode_id(),
        parent_key=key,
    )
    serialized = inode.to_json()
    restored = Inode.from_json(serialized)
    assert restored.inode_id == inode.inode_id
    assert restored.is_dir == inode.is_dir
    assert "test.txt" in restored.children
    assert restored.children["test.txt"].key == child_key
    assert restored.shared_with == ["bob"]


def test_profile_serialization():
    key = generate_key()
    profile = Profile(
        username="alice",
        root_inode_id=new_inode_id(),
        root_key=key,
        chain_head="abc123",
        current_path=["docs"],
        current_inode_id=new_inode_id(),
        current_key=key,
    )
    serialized = profile.to_json()
    restored = Profile.from_json(serialized)
    assert restored.username == "alice"
    assert restored.root_key == key
    assert restored.chain_head == "abc123"
    assert restored.current_path == ["docs"]


def test_merkle_hash():
    data = b"inode content"
    h1 = compute_merkle_hash(data, [])
    h2 = compute_merkle_hash(data, ["child_hash_1"])
    h3 = compute_merkle_hash(data, ["child_hash_1", "child_hash_2"])
    assert h1 != h2
    assert h2 != h3
    # Deterministic
    assert compute_merkle_hash(data, ["child_hash_1"]) == h2


def test_chain_entry():
    h1, r1 = compute_chain_entry("", "init", "root-id", "merkle-root-1")
    assert len(h1) == 64
    assert r1["operation"] == "init"
    h2, r2 = compute_chain_entry(h1, "mkdir", "dir-id", "merkle-root-2")
    assert h2 != h1


def test_verify_chain():
    assert verify_chain("", "") is True
    assert verify_chain("abc", "abc") is True
    assert verify_chain("abc", "def") is False


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        try:
            t()
            print(f"  PASS: {t.__name__}")
        except AssertionError as e:
            print(f"  FAIL: {t.__name__}: {e}")
        except Exception as e:
            print(f"  ERROR: {t.__name__}: {e}")
    print("Done.")
