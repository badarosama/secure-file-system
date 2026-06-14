"""Merkle tree hash computation and fork-consistency chain."""

import hashlib
import time

from crypto_utils import compute_hash


def compute_merkle_hash(inode_data: bytes, child_hashes: list[str]) -> str:
    """Compute merkle hash for an inode.

    Hash = SHA-256(inode_content || child_hash_1 || child_hash_2 || ...)
    """
    h = hashlib.sha256()
    h.update(inode_data)
    for ch in sorted(child_hashes):
        h.update(ch.encode())
    return h.hexdigest()


def compute_chain_entry(prev_hash: str, operation: str, inode_id: str,
                        merkle_root: str) -> tuple[str, dict]:
    """Create a new chain entry for fork consistency.

    Returns (new_hash, record_dict).
    """
    ts = time.time()
    record = {
        "timestamp": ts,
        "operation": operation,
        "inode_id": inode_id,
        "merkle_root": merkle_root,
        "prev_hash": prev_hash,
    }
    data = f"{prev_hash}|{operation}|{inode_id}|{merkle_root}|{ts}"
    new_hash = hashlib.sha256(data.encode()).hexdigest()
    return new_hash, record


def verify_chain(local_head: str, server_head: str) -> bool:
    """Check if local and server chain heads match."""
    if not local_head and not server_head:
        return True
    return local_head == server_head
