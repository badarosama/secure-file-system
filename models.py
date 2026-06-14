"""Data structures for the encrypted file system."""

import json
import uuid
from dataclasses import dataclass, field
from typing import Optional

from crypto_utils import bytes_to_b64, b64_to_bytes, generate_key


@dataclass
class ChildEntry:
    """Reference to a child inode stored in parent's encrypted data."""
    inode_id: str
    key: bytes  # symmetric key to decrypt the child

    def to_dict(self) -> dict:
        return {"inode_id": self.inode_id, "key": bytes_to_b64(self.key)}

    @classmethod
    def from_dict(cls, d: dict) -> "ChildEntry":
        return cls(inode_id=d["inode_id"], key=b64_to_bytes(d["key"]))


@dataclass
class Inode:
    """Filesystem inode -- directories and files."""
    inode_id: str
    is_dir: bool
    children: dict = field(default_factory=dict)   # name -> ChildEntry (dirs only)
    data: bytes = b""                               # file content (files only)
    shared_with: list = field(default_factory=list) # usernames sharing this node
    parent_id: Optional[str] = None
    parent_key: Optional[bytes] = None              # key to decrypt parent

    def to_json(self) -> bytes:
        d = {
            "inode_id": self.inode_id,
            "is_dir": self.is_dir,
            "children": {name: ce.to_dict() for name, ce in self.children.items()},
            "data": bytes_to_b64(self.data),
            "shared_with": self.shared_with,
            "parent_id": self.parent_id,
            "parent_key": bytes_to_b64(self.parent_key) if self.parent_key else None,
        }
        return json.dumps(d).encode()

    @classmethod
    def from_json(cls, raw: bytes) -> "Inode":
        d = json.loads(raw.decode())
        children = {name: ChildEntry.from_dict(ce) for name, ce in d["children"].items()}
        return cls(
            inode_id=d["inode_id"],
            is_dir=d["is_dir"],
            children=children,
            data=b64_to_bytes(d["data"]),
            shared_with=d.get("shared_with", []),
            parent_id=d.get("parent_id"),
            parent_key=b64_to_bytes(d["parent_key"]) if d.get("parent_key") else None,
        )


@dataclass
class Profile:
    """Client-side profile stored locally. Contains root key -- never sent to server."""
    username: str
    root_inode_id: str
    root_key: bytes
    chain_head: str = ""                            # latest hash in consistency chain
    current_path: list = field(default_factory=list)
    current_inode_id: str = ""
    current_key: bytes = b""
    shared_roots: dict = field(default_factory=dict)  # name -> {inode_id, key}

    def to_json(self) -> str:
        return json.dumps({
            "username": self.username,
            "root_inode_id": self.root_inode_id,
            "root_key": bytes_to_b64(self.root_key),
            "chain_head": self.chain_head,
            "current_path": self.current_path,
            "current_inode_id": self.current_inode_id,
            "current_key": bytes_to_b64(self.current_key),
            "shared_roots": {
                name: {"inode_id": v["inode_id"], "key": bytes_to_b64(v["key"])}
                for name, v in self.shared_roots.items()
            },
        }, indent=2)

    @classmethod
    def from_json(cls, raw: str) -> "Profile":
        d = json.loads(raw)
        return cls(
            username=d["username"],
            root_inode_id=d["root_inode_id"],
            root_key=b64_to_bytes(d["root_key"]),
            chain_head=d.get("chain_head", ""),
            current_path=d.get("current_path", []),
            current_inode_id=d.get("current_inode_id", d["root_inode_id"]),
            current_key=b64_to_bytes(d.get("current_key", d["root_key"])),
            shared_roots={
                name: {"inode_id": v["inode_id"], "key": b64_to_bytes(v["key"])}
                for name, v in d.get("shared_roots", {}).items()
            },
        )


def new_inode_id() -> str:
    return str(uuid.uuid4())
