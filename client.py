"""Encrypted filesystem CLI client.

All cryptographic operations happen client-side. The server is untrusted
and only stores encrypted blobs.
"""

import os
import sys
import json
import cmd
import time

import requests

from crypto_utils import (
    generate_key, encrypt_blob, decrypt_blob, compute_hash,
    bytes_to_b64, b64_to_bytes,
)
from models import Inode, ChildEntry, Profile, new_inode_id
from merkle import compute_merkle_hash, compute_chain_entry, verify_chain


PROFILES_DIR = os.path.join(os.path.dirname(__file__), "profiles")
DEFAULT_SERVER = "http://127.0.0.1:5000"


class ConsistencyError(Exception):
    """Raised when fork consistency check fails."""
    pass


class SecureFS:
    """Client-side encrypted filesystem with Merkle tree integrity."""

    def __init__(self, profile_path: str, server_url: str = DEFAULT_SERVER):
        self.server_url = server_url
        self.profile_path = profile_path
        self.profile: Profile = None
        self._inode_cache: dict[str, tuple[Inode, bytes]] = {}  # id -> (inode, key)

    # ── Server Communication ──────────────────────────────────────────

    def _put_blob(self, blob_id: str, data: bytes):
        r = requests.put(f"{self.server_url}/blob/{blob_id}", data=data)
        r.raise_for_status()

    def _get_blob(self, blob_id: str) -> bytes:
        r = requests.get(f"{self.server_url}/blob/{blob_id}")
        if r.status_code == 404:
            raise FileNotFoundError(f"Blob {blob_id} not found on server")
        r.raise_for_status()
        return r.content

    def _delete_blob(self, blob_id: str):
        requests.delete(f"{self.server_url}/blob/{blob_id}")

    def _get_server_chain(self) -> str:
        r = requests.get(f"{self.server_url}/chain/{self.profile.username}")
        return r.json().get("chain_head", "")

    def _put_chain(self, chain_head: str, record: dict):
        requests.put(
            f"{self.server_url}/chain/{self.profile.username}",
            json={"chain_head": chain_head, "record": record},
        )

    # ── Inode Operations ──────────────────────────────────────────────

    def _store_inode(self, inode: Inode, key: bytes) -> str:
        """Encrypt and store inode on server. Returns the blob_id."""
        blob_id = inode.inode_id
        plaintext = inode.to_json()
        ciphertext = encrypt_blob(plaintext, key)
        self._put_blob(blob_id, ciphertext)
        self._inode_cache[blob_id] = (inode, key)
        return blob_id

    def _fetch_inode(self, inode_id: str, key: bytes) -> Inode:
        """Fetch and decrypt an inode from the server."""
        if inode_id in self._inode_cache:
            cached_inode, cached_key = self._inode_cache[inode_id]
            if cached_key == key:
                return cached_inode
        ciphertext = self._get_blob(inode_id)
        plaintext = decrypt_blob(ciphertext, key)
        inode = Inode.from_json(plaintext)
        self._inode_cache[inode_id] = (inode, key)
        return inode

    def _compute_inode_merkle(self, inode: Inode, key: bytes) -> str:
        """Recursively compute merkle hash for an inode."""
        child_hashes = []
        if inode.is_dir:
            for name, ce in inode.children.items():
                child = self._fetch_inode(ce.inode_id, ce.key)
                child_hashes.append(self._compute_inode_merkle(child, ce.key))
        return compute_merkle_hash(inode.to_json(), child_hashes)

    def _get_merkle_root(self) -> str:
        """Compute current merkle root hash."""
        root = self._fetch_inode(self.profile.root_inode_id, self.profile.root_key)
        return self._compute_inode_merkle(root, self.profile.root_key)

    # ── Consistency ───────────────────────────────────────────────────

    def _verify_consistency(self):
        """Check fork consistency on every operation."""
        server_head = self._get_server_chain()
        if not verify_chain(self.profile.chain_head, server_head):
            raise ConsistencyError(
                f"Fork detected! Local head: {self.profile.chain_head[:16]}... "
                f"Server head: {server_head[:16]}..."
            )

    def _record_operation(self, operation: str, inode_id: str):
        """Append operation to consistency chain."""
        merkle_root = self._get_merkle_root()
        new_hash, record = compute_chain_entry(
            self.profile.chain_head, operation, inode_id, merkle_root
        )
        self.profile.chain_head = new_hash
        self._put_chain(new_hash, record)
        self._save_profile()

    # ── Re-encryption ─────────────────────────────────────────────────

    def _reencrypt_to_root(self, inode_id: str, key: bytes):
        """Re-encrypt all parent inodes from inode_id up to root with new keys."""
        inode = self._fetch_inode(inode_id, key)
        if inode.parent_id is None:
            # This is the root -- update profile
            new_key = generate_key()
            old_id = inode.inode_id
            inode.inode_id = new_inode_id()
            self._store_inode(inode, new_key)
            self._delete_blob(old_id)
            self.profile.root_inode_id = inode.inode_id
            self.profile.root_key = new_key
            if self.profile.current_inode_id == old_id:
                self.profile.current_inode_id = inode.inode_id
                self.profile.current_key = new_key
            return

        parent = self._fetch_inode(inode.parent_id, inode.parent_key)
        # Update parent's reference to this child with new key
        new_child_key = generate_key()
        old_child_id = inode.inode_id
        inode.inode_id = new_inode_id()
        self._store_inode(inode, new_child_key)
        self._delete_blob(old_child_id)

        # Update current tracking if needed
        if self.profile.current_inode_id == old_child_id:
            self.profile.current_inode_id = inode.inode_id
            self.profile.current_key = new_child_key

        for name, ce in parent.children.items():
            if ce.inode_id == old_child_id:
                parent.children[name] = ChildEntry(inode.inode_id, new_child_key)
                # Update child's parent_key reference
                inode.parent_key = None  # will be set when parent re-encrypts
                break

        self._reencrypt_to_root(parent.inode_id, inode.parent_key or self._find_parent_key(parent))

    def _find_parent_key(self, inode: Inode) -> bytes:
        """Find the key for an inode by checking if it's root or cached."""
        if inode.inode_id == self.profile.root_inode_id:
            return self.profile.root_key
        # Check cache
        if inode.inode_id in self._inode_cache:
            return self._inode_cache[inode.inode_id][1]
        raise ValueError(f"Cannot find key for inode {inode.inode_id}")

    def _update_parents_to_root(self, child_name: str, child_entry: ChildEntry,
                                 parent_inode: Inode, parent_key: bytes):
        """Update parent chain after a child mutation. Re-encrypts each parent with a new key."""
        parent_inode.children[child_name] = child_entry
        new_parent_key = generate_key()
        old_parent_id = parent_inode.inode_id
        parent_inode.inode_id = new_inode_id()
        self._store_inode(parent_inode, new_parent_key)
        self._delete_blob(old_parent_id)

        if self.profile.current_inode_id == old_parent_id:
            self.profile.current_inode_id = parent_inode.inode_id
            self.profile.current_key = new_parent_key

        if parent_inode.parent_id is None:
            # Reached root
            self.profile.root_inode_id = parent_inode.inode_id
            self.profile.root_key = new_parent_key
            self._save_profile()
            return

        grandparent = self._fetch_inode(parent_inode.parent_id, parent_inode.parent_key)
        for name, ce in grandparent.children.items():
            if ce.inode_id == old_parent_id:
                new_ce = ChildEntry(parent_inode.inode_id, new_parent_key)
                self._update_parents_to_root(name, new_ce, grandparent, parent_inode.parent_key)
                return

    def _reencrypt_subtree_down(self, inode: Inode, key: bytes):
        """Re-encrypt all children downward, stopping at shared boundaries (fix #1)."""
        if not inode.is_dir:
            return
        for name, ce in list(inode.children.items()):
            child = self._fetch_inode(ce.inode_id, ce.key)
            if child.shared_with:
                # Stop at shared boundary -- don't re-encrypt independently shared subtrees
                continue
            new_key = generate_key()
            old_id = child.inode_id
            child.inode_id = new_inode_id()
            # Recurse before storing
            self._reencrypt_subtree_down(child, new_key)
            child.parent_id = inode.inode_id
            child.parent_key = key
            self._store_inode(child, new_key)
            self._delete_blob(old_id)
            inode.children[name] = ChildEntry(child.inode_id, new_key)

    # ── Profile Management ────────────────────────────────────────────

    def _save_profile(self):
        with open(self.profile_path, "w") as f:
            f.write(self.profile.to_json())

    def _load_profile(self):
        with open(self.profile_path, "r") as f:
            self.profile = Profile.from_json(f.read())

    def init_filesystem(self, username: str):
        """Create a new filesystem for a user."""
        os.makedirs(PROFILES_DIR, exist_ok=True)
        root_key = generate_key()
        root_id = new_inode_id()
        root_inode = Inode(
            inode_id=root_id,
            is_dir=True,
            children={},
            parent_id=None,
            parent_key=None,
        )
        self._store_inode(root_inode, root_key)
        self.profile = Profile(
            username=username,
            root_inode_id=root_id,
            root_key=root_key,
            chain_head="",
            current_path=[],
            current_inode_id=root_id,
            current_key=root_key,
        )
        self._save_profile()
        self._record_operation("init", root_id)
        print(f"Filesystem initialized for user '{username}'")

    def login(self, username: str):
        """Load existing profile."""
        path = os.path.join(PROFILES_DIR, f"{username}.json")
        if not os.path.exists(path):
            print(f"No profile found for '{username}'. Use 'init' to create one.")
            return False
        self.profile_path = path
        self._load_profile()
        self._inode_cache.clear()
        print(f"Logged in as '{username}'")
        return True

    # ── Filesystem Operations ─────────────────────────────────────────

    def pwd(self) -> str:
        path = "/" + "/".join(self.profile.current_path)
        return path

    def ls(self) -> list[str]:
        self._verify_consistency()
        cwd = self._fetch_inode(self.profile.current_inode_id, self.profile.current_key)
        if not cwd.is_dir:
            raise ValueError("Current inode is not a directory")
        entries = []
        for name, ce in cwd.children.items():
            child = self._fetch_inode(ce.inode_id, ce.key)
            suffix = "/" if child.is_dir else ""
            shared = " [shared]" if child.shared_with else ""
            entries.append(f"{name}{suffix}{shared}")
        self._record_operation("ls", cwd.inode_id)
        return entries

    def cd(self, dirname: str):
        self._verify_consistency()
        if dirname == "..":
            if not self.profile.current_path:
                return
            self.profile.current_path.pop()
            # Navigate from root
            inode = self._fetch_inode(self.profile.root_inode_id, self.profile.root_key)
            key = self.profile.root_key
            for part in self.profile.current_path:
                ce = inode.children.get(part)
                if not ce:
                    raise FileNotFoundError(f"Directory '{part}' not found")
                inode = self._fetch_inode(ce.inode_id, ce.key)
                key = ce.key
            self.profile.current_inode_id = inode.inode_id
            self.profile.current_key = key
            self._save_profile()
            return

        cwd = self._fetch_inode(self.profile.current_inode_id, self.profile.current_key)
        if dirname not in cwd.children:
            raise FileNotFoundError(f"Directory '{dirname}' not found")
        ce = cwd.children[dirname]
        child = self._fetch_inode(ce.inode_id, ce.key)
        if not child.is_dir:
            raise NotADirectoryError(f"'{dirname}' is not a directory")
        self.profile.current_path.append(dirname)
        self.profile.current_inode_id = child.inode_id
        self.profile.current_key = ce.key
        self._record_operation("cd", child.inode_id)
        self._save_profile()

    def mkdir(self, dirname: str):
        self._verify_consistency()
        cwd = self._fetch_inode(self.profile.current_inode_id, self.profile.current_key)
        if dirname in cwd.children:
            raise FileExistsError(f"'{dirname}' already exists")

        new_key = generate_key()
        new_id = new_inode_id()
        new_dir = Inode(
            inode_id=new_id,
            is_dir=True,
            children={},
            parent_id=cwd.inode_id,
            parent_key=self.profile.current_key,
        )
        self._store_inode(new_dir, new_key)

        ce = ChildEntry(new_id, new_key)
        old_cwd_id = cwd.inode_id
        cwd.children[dirname] = ce

        # Re-encrypt cwd and propagate up
        new_cwd_key = generate_key()
        cwd.inode_id = new_inode_id()
        # Update child's parent reference
        new_dir.parent_id = cwd.inode_id
        new_dir.parent_key = new_cwd_key
        self._store_inode(new_dir, new_key)
        self._store_inode(cwd, new_cwd_key)
        self._delete_blob(old_cwd_id)

        # Update all children's parent references
        for name, child_ce in cwd.children.items():
            if child_ce.inode_id == new_id:
                continue
            try:
                child = self._fetch_inode(child_ce.inode_id, child_ce.key)
                child.parent_id = cwd.inode_id
                child.parent_key = new_cwd_key
                self._store_inode(child, child_ce.key)
            except Exception:
                pass

        self.profile.current_inode_id = cwd.inode_id
        self.profile.current_key = new_cwd_key

        if cwd.parent_id is not None:
            parent = self._fetch_inode(cwd.parent_id, cwd.parent_key)
            for name, pce in parent.children.items():
                if pce.inode_id == old_cwd_id:
                    new_ce = ChildEntry(cwd.inode_id, new_cwd_key)
                    self._update_parents_to_root(name, new_ce, parent, cwd.parent_key)
                    break
        else:
            self.profile.root_inode_id = cwd.inode_id
            self.profile.root_key = new_cwd_key

        self._record_operation("mkdir", new_id)
        self._save_profile()

    def put(self, local_path: str, remote_name: str = None):
        """Upload a local file to the encrypted filesystem."""
        self._verify_consistency()
        if not os.path.isfile(local_path):
            raise FileNotFoundError(f"Local file '{local_path}' not found")

        if remote_name is None:
            remote_name = os.path.basename(local_path)

        with open(local_path, "rb") as f:
            file_data = f.read()

        cwd = self._fetch_inode(self.profile.current_inode_id, self.profile.current_key)

        # Delete old version if exists
        if remote_name in cwd.children:
            old_ce = cwd.children[remote_name]
            self._delete_blob(old_ce.inode_id)

        new_key = generate_key()
        new_id = new_inode_id()
        file_inode = Inode(
            inode_id=new_id,
            is_dir=False,
            data=file_data,
            parent_id=cwd.inode_id,
            parent_key=self.profile.current_key,
        )
        self._store_inode(file_inode, new_key)

        ce = ChildEntry(new_id, new_key)
        old_cwd_id = cwd.inode_id
        cwd.children[remote_name] = ce

        new_cwd_key = generate_key()
        cwd.inode_id = new_inode_id()
        file_inode.parent_id = cwd.inode_id
        file_inode.parent_key = new_cwd_key
        self._store_inode(file_inode, new_key)
        self._store_inode(cwd, new_cwd_key)
        self._delete_blob(old_cwd_id)

        # Update other children's parent refs
        for name, child_ce in cwd.children.items():
            if child_ce.inode_id == new_id:
                continue
            try:
                child = self._fetch_inode(child_ce.inode_id, child_ce.key)
                child.parent_id = cwd.inode_id
                child.parent_key = new_cwd_key
                self._store_inode(child, child_ce.key)
            except Exception:
                pass

        self.profile.current_inode_id = cwd.inode_id
        self.profile.current_key = new_cwd_key

        if cwd.parent_id is not None:
            parent = self._fetch_inode(cwd.parent_id, cwd.parent_key)
            for name, pce in parent.children.items():
                if pce.inode_id == old_cwd_id:
                    new_ce = ChildEntry(cwd.inode_id, new_cwd_key)
                    self._update_parents_to_root(name, new_ce, parent, cwd.parent_key)
                    break
        else:
            self.profile.root_inode_id = cwd.inode_id
            self.profile.root_key = new_cwd_key

        self._record_operation("put", new_id)
        self._save_profile()

    def get(self, remote_name: str, local_path: str = None):
        """Download a file from the encrypted filesystem."""
        self._verify_consistency()
        cwd = self._fetch_inode(self.profile.current_inode_id, self.profile.current_key)
        if remote_name not in cwd.children:
            raise FileNotFoundError(f"'{remote_name}' not found")

        ce = cwd.children[remote_name]
        file_inode = self._fetch_inode(ce.inode_id, ce.key)
        if file_inode.is_dir:
            raise IsADirectoryError(f"'{remote_name}' is a directory")

        if local_path is None:
            local_path = remote_name

        with open(local_path, "wb") as f:
            f.write(file_inode.data)

        self._record_operation("get", file_inode.inode_id)
        return local_path

    def rm(self, name: str):
        """Remove a file."""
        self._verify_consistency()
        cwd = self._fetch_inode(self.profile.current_inode_id, self.profile.current_key)
        if name not in cwd.children:
            raise FileNotFoundError(f"'{name}' not found")

        ce = cwd.children[name]
        target = self._fetch_inode(ce.inode_id, ce.key)
        if target.is_dir:
            raise IsADirectoryError(f"'{name}' is a directory, use rmdir")

        old_id = ce.inode_id
        del cwd.children[name]
        self._delete_blob(old_id)

        old_cwd_id = cwd.inode_id
        new_cwd_key = generate_key()
        cwd.inode_id = new_inode_id()
        self._store_inode(cwd, new_cwd_key)
        self._delete_blob(old_cwd_id)

        # Update children parent refs
        for child_name, child_ce in cwd.children.items():
            try:
                child = self._fetch_inode(child_ce.inode_id, child_ce.key)
                child.parent_id = cwd.inode_id
                child.parent_key = new_cwd_key
                self._store_inode(child, child_ce.key)
            except Exception:
                pass

        self.profile.current_inode_id = cwd.inode_id
        self.profile.current_key = new_cwd_key

        if cwd.parent_id is not None:
            parent = self._fetch_inode(cwd.parent_id, cwd.parent_key)
            for pname, pce in parent.children.items():
                if pce.inode_id == old_cwd_id:
                    new_ce = ChildEntry(cwd.inode_id, new_cwd_key)
                    self._update_parents_to_root(pname, new_ce, parent, cwd.parent_key)
                    break
        else:
            self.profile.root_inode_id = cwd.inode_id
            self.profile.root_key = new_cwd_key

        self._record_operation("rm", old_id)
        self._save_profile()

    def rmdir(self, dirname: str):
        """Remove an empty directory."""
        self._verify_consistency()
        cwd = self._fetch_inode(self.profile.current_inode_id, self.profile.current_key)
        if dirname not in cwd.children:
            raise FileNotFoundError(f"'{dirname}' not found")

        ce = cwd.children[dirname]
        target = self._fetch_inode(ce.inode_id, ce.key)
        if not target.is_dir:
            raise NotADirectoryError(f"'{dirname}' is not a directory")
        if target.children:
            raise OSError(f"Directory '{dirname}' is not empty")

        old_id = ce.inode_id
        del cwd.children[dirname]
        self._delete_blob(old_id)

        old_cwd_id = cwd.inode_id
        new_cwd_key = generate_key()
        cwd.inode_id = new_inode_id()
        self._store_inode(cwd, new_cwd_key)
        self._delete_blob(old_cwd_id)

        for child_name, child_ce in cwd.children.items():
            try:
                child = self._fetch_inode(child_ce.inode_id, child_ce.key)
                child.parent_id = cwd.inode_id
                child.parent_key = new_cwd_key
                self._store_inode(child, child_ce.key)
            except Exception:
                pass

        self.profile.current_inode_id = cwd.inode_id
        self.profile.current_key = new_cwd_key

        if cwd.parent_id is not None:
            parent = self._fetch_inode(cwd.parent_id, cwd.parent_key)
            for pname, pce in parent.children.items():
                if pce.inode_id == old_cwd_id:
                    new_ce = ChildEntry(cwd.inode_id, new_cwd_key)
                    self._update_parents_to_root(pname, new_ce, parent, cwd.parent_key)
                    break
        else:
            self.profile.root_inode_id = cwd.inode_id
            self.profile.root_key = new_cwd_key

        self._record_operation("rmdir", old_id)
        self._save_profile()

    # ── Sharing ───────────────────────────────────────────────────────

    def share(self, name: str, target_user: str, permission: str = "read") -> dict:
        """Share a file/directory with another user.

        Returns share info dict that must be transmitted to the target user
        through a secure channel.
        """
        self._verify_consistency()
        cwd = self._fetch_inode(self.profile.current_inode_id, self.profile.current_key)
        if name not in cwd.children:
            raise FileNotFoundError(f"'{name}' not found")

        ce = cwd.children[name]
        target = self._fetch_inode(ce.inode_id, ce.key)

        if target_user in target.shared_with:
            print(f"Already shared with '{target_user}'")
            return {}

        # Mark as shared
        target.shared_with.append(target_user)

        # Cut from tree -- make it a new root for the shared user
        # The shared node keeps its key but loses parent reference
        target.parent_id = None
        target.parent_key = None
        self._store_inode(target, ce.key)

        share_info = {
            "from_user": self.profile.username,
            "name": name,
            "inode_id": ce.inode_id,
            "key": bytes_to_b64(ce.key),
            "permission": permission,
        }

        self._record_operation("share", target.inode_id)
        self._save_profile()

        print(f"Shared '{name}' with '{target_user}' ({permission})")
        print(f"Share info (transmit securely): {json.dumps(share_info)}")
        return share_info

    def receive_share(self, share_info_json: str):
        """Accept a share from another user."""
        self._verify_consistency()
        info = json.loads(share_info_json)
        name = info["name"]
        inode_id = info["inode_id"]
        key = b64_to_bytes(info["key"])

        # Verify we can actually decrypt it
        inode = self._fetch_inode(inode_id, key)

        self.profile.shared_roots[name] = {
            "inode_id": inode_id,
            "key": key,
            "from_user": info["from_user"],
            "permission": info.get("permission", "read"),
        }
        self._record_operation("receive_share", inode_id)
        self._save_profile()
        print(f"Received share '{name}' from '{info['from_user']}'")

    def revoke(self, name: str, target_user: str):
        """Revoke a user's access to a shared file/directory.

        Re-encrypts the shared node and all children down to the next shared
        boundary (fix #1), then re-encrypts all parents up to root.
        """
        self._verify_consistency()
        cwd = self._fetch_inode(self.profile.current_inode_id, self.profile.current_key)
        if name not in cwd.children:
            raise FileNotFoundError(f"'{name}' not found")

        ce = cwd.children[name]
        target = self._fetch_inode(ce.inode_id, ce.key)

        if target_user not in target.shared_with:
            print(f"'{name}' is not shared with '{target_user}'")
            return

        target.shared_with.remove(target_user)

        # Fix #1: Re-encrypt all children down to next shared boundary
        new_key = generate_key()
        old_id = target.inode_id
        target.inode_id = new_inode_id()
        self._reencrypt_subtree_down(target, new_key)

        # Rejoin to parent tree if no longer shared with anyone
        if not target.shared_with:
            target.parent_id = cwd.inode_id
            target.parent_key = self.profile.current_key

        self._store_inode(target, new_key)
        self._delete_blob(old_id)

        # Update parent reference
        cwd.children[name] = ChildEntry(target.inode_id, new_key)
        old_cwd_id = cwd.inode_id
        new_cwd_key = generate_key()
        cwd.inode_id = new_inode_id()
        self._store_inode(cwd, new_cwd_key)
        self._delete_blob(old_cwd_id)

        # Update children parent refs
        for child_name, child_ce in cwd.children.items():
            try:
                child = self._fetch_inode(child_ce.inode_id, child_ce.key)
                child.parent_id = cwd.inode_id
                child.parent_key = new_cwd_key
                self._store_inode(child, child_ce.key)
            except Exception:
                pass

        self.profile.current_inode_id = cwd.inode_id
        self.profile.current_key = new_cwd_key

        if cwd.parent_id is not None:
            parent = self._fetch_inode(cwd.parent_id, cwd.parent_key)
            for pname, pce in parent.children.items():
                if pce.inode_id == old_cwd_id:
                    new_ce = ChildEntry(cwd.inode_id, new_cwd_key)
                    self._update_parents_to_root(pname, new_ce, parent, cwd.parent_key)
                    break
        else:
            self.profile.root_inode_id = cwd.inode_id
            self.profile.root_key = new_cwd_key

        self._record_operation("revoke", target.inode_id)
        self._save_profile()
        print(f"Revoked '{target_user}' access to '{name}'")

    def state(self):
        """Print current filesystem state for consistency verification."""
        merkle_root = self._get_merkle_root()
        print(f"User:        {self.profile.username}")
        print(f"Merkle Root: {merkle_root[:32]}...")
        print(f"Chain Head:  {self.profile.chain_head[:32]}..." if self.profile.chain_head else "Chain Head:  (empty)")
        if self.profile.shared_roots:
            print("Shared roots:")
            for name, info in self.profile.shared_roots.items():
                print(f"  {name} (from {info.get('from_user', '?')})")


# ── CLI ───────────────────────────────────────────────────────────────

class SecureFSShell(cmd.Cmd):
    intro = "Secure Encrypted File System. Type 'help' for commands.\n"
    prompt = "sefs> "

    def __init__(self, server_url: str = DEFAULT_SERVER):
        super().__init__()
        self.server_url = server_url
        self.fs = None

    def _require_login(self) -> bool:
        if self.fs is None or self.fs.profile is None:
            print("Not logged in. Use 'init <username>' or 'login <username>'")
            return False
        return True

    def _update_prompt(self):
        if self.fs and self.fs.profile:
            self.prompt = f"sefs:{self.fs.pwd()}> "

    def do_init(self, arg):
        """init <username> -- Create a new encrypted filesystem"""
        username = arg.strip()
        if not username:
            print("Usage: init <username>")
            return
        os.makedirs(PROFILES_DIR, exist_ok=True)
        profile_path = os.path.join(PROFILES_DIR, f"{username}.json")
        self.fs = SecureFS(profile_path, self.server_url)
        self.fs.init_filesystem(username)
        self._update_prompt()

    def do_login(self, arg):
        """login <username> -- Login to existing filesystem"""
        username = arg.strip()
        if not username:
            print("Usage: login <username>")
            return
        profile_path = os.path.join(PROFILES_DIR, f"{username}.json")
        self.fs = SecureFS(profile_path, self.server_url)
        if self.fs.login(username):
            self._update_prompt()

    def do_ls(self, arg):
        """List files in current directory"""
        if not self._require_login():
            return
        try:
            entries = self.fs.ls()
            for e in entries:
                print(f"  {e}")
            if not entries:
                print("  (empty)")
        except Exception as e:
            print(f"Error: {e}")

    def do_cd(self, arg):
        """cd <dirname> -- Change directory"""
        if not self._require_login():
            return
        dirname = arg.strip()
        if not dirname:
            print("Usage: cd <dirname>")
            return
        try:
            self.fs.cd(dirname)
            self._update_prompt()
        except Exception as e:
            print(f"Error: {e}")

    def do_pwd(self, arg):
        """Print working directory"""
        if not self._require_login():
            return
        print(self.fs.pwd())

    def do_mkdir(self, arg):
        """mkdir <dirname> -- Create directory"""
        if not self._require_login():
            return
        dirname = arg.strip()
        if not dirname:
            print("Usage: mkdir <dirname>")
            return
        try:
            self.fs.mkdir(dirname)
            print(f"Created directory '{dirname}'")
        except Exception as e:
            print(f"Error: {e}")

    def do_rmdir(self, arg):
        """rmdir <dirname> -- Remove empty directory"""
        if not self._require_login():
            return
        dirname = arg.strip()
        if not dirname:
            print("Usage: rmdir <dirname>")
            return
        try:
            self.fs.rmdir(dirname)
            print(f"Removed directory '{dirname}'")
        except Exception as e:
            print(f"Error: {e}")

    def do_put(self, arg):
        """put <local_file> [remote_name] -- Upload file"""
        if not self._require_login():
            return
        parts = arg.strip().split(maxsplit=1)
        if not parts:
            print("Usage: put <local_file> [remote_name]")
            return
        local_path = parts[0]
        remote_name = parts[1] if len(parts) > 1 else None
        try:
            self.fs.put(local_path, remote_name)
            print(f"Uploaded '{local_path}'")
        except Exception as e:
            print(f"Error: {e}")

    def do_get(self, arg):
        """get <remote_name> [local_path] -- Download file"""
        if not self._require_login():
            return
        parts = arg.strip().split(maxsplit=1)
        if not parts:
            print("Usage: get <remote_name> [local_path]")
            return
        remote_name = parts[0]
        local_path = parts[1] if len(parts) > 1 else None
        try:
            path = self.fs.get(remote_name, local_path)
            print(f"Downloaded to '{path}'")
        except Exception as e:
            print(f"Error: {e}")

    def do_rm(self, arg):
        """rm <filename> -- Remove file"""
        if not self._require_login():
            return
        name = arg.strip()
        if not name:
            print("Usage: rm <filename>")
            return
        try:
            self.fs.rm(name)
            print(f"Removed '{name}'")
        except Exception as e:
            print(f"Error: {e}")

    def do_share(self, arg):
        """share <name> <username> [read|write] -- Share file/dir with user"""
        if not self._require_login():
            return
        parts = arg.strip().split()
        if len(parts) < 2:
            print("Usage: share <name> <username> [read|write]")
            return
        name = parts[0]
        target = parts[1]
        perm = parts[2] if len(parts) > 2 else "read"
        try:
            self.fs.share(name, target, perm)
        except Exception as e:
            print(f"Error: {e}")

    def do_receive(self, arg):
        """receive <share_info_json> -- Accept a share from another user"""
        if not self._require_login():
            return
        if not arg.strip():
            print("Usage: receive <share_info_json>")
            return
        try:
            self.fs.receive_share(arg.strip())
        except Exception as e:
            print(f"Error: {e}")

    def do_revoke(self, arg):
        """revoke <name> <username> -- Revoke user's access"""
        if not self._require_login():
            return
        parts = arg.strip().split()
        if len(parts) < 2:
            print("Usage: revoke <name> <username>")
            return
        try:
            self.fs.revoke(parts[0], parts[1])
        except Exception as e:
            print(f"Error: {e}")

    def do_state(self, arg):
        """Print filesystem state for consistency check"""
        if not self._require_login():
            return
        try:
            self.fs.state()
        except Exception as e:
            print(f"Error: {e}")

    def do_exit(self, arg):
        """Exit the shell"""
        print("Goodbye!")
        return True

    def do_quit(self, arg):
        """Exit the shell"""
        return self.do_exit(arg)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Secure Encrypted File System Client")
    parser.add_argument("--server", default=DEFAULT_SERVER, help="Server URL")
    args = parser.parse_args()

    shell = SecureFSShell(server_url=args.server)
    shell.cmdloop()


if __name__ == "__main__":
    main()
