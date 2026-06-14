# Secure Encrypted File System

A userspace encrypted file system built on Merkle trees with support for secure file sharing and fork consistency. Designed as part of my final project for computer security class.

## Architecture

```
┌─────────────────────────────────────────────┐
│  Client (all crypto logic)                  │
│  ┌───────────┐ ┌──────────┐ ┌────────────┐ │
│  │ AES-256   │ │ Merkle   │ │ Hash Chain │ │
│  │ Encryption│ │ Integrity│ │ Consistency│ │
│  └───────────┘ └──────────┘ └────────────┘ │
└─────────────┬───────────────────────────────┘
              │ HTTP (encrypted blobs only)
┌─────────────▼───────────────────────────────┐
│  Server (untrusted, minimal)                │
│  Stores encrypted blobs by ID               │
│  No keys, no plaintext, no structure        │
└─────────────────────────────────────────────┘
```

**Privacy**: All data encrypted with AES-256-CBC. File names, directory structure, and content are invisible to the server.

**Integrity**: Merkle tree hashes from leaves to root. Any tampering is detected by comparing the root hash stored locally.

**Fork Consistency**: Every read/write operation appends to a hash chain (`d_n = SHA-256(r_n || d_{n-1})`). Users sharing files can detect if the server serves divergent views.

**Efficient Sharing**: Each inode has its own symmetric key. Sharing a file = handing over that key. No re-encryption of the shared subtree needed.

**Secure Revocation**: On revoke, re-encrypt the shared node, all children down to the next shared boundary, and all parents up to root. The revoked user loses access immediately.

## Setup

```bash
pip install -r requirements.txt
```

## Usage

**1. Start the server** (one terminal):
```bash
python server.py
```

**2. Start the client** (another terminal):
```bash
python client.py
```

**3. Basic commands**:
```
sefs> init alice                    # Create filesystem for user
sefs:/> mkdir documents
sefs:/> cd documents
sefs:/documents> put ~/report.txt   # Upload a file
sefs:/documents> ls
  report.txt
sefs:/documents> get report.txt ./downloaded.txt
sefs:/documents> cd ..
sefs:/> rm documents/report.txt
```

**4. File sharing**:
```
# Alice shares a directory with Bob
sefs:/> share documents bob write
# Output: Share info (transmit securely): {"from_user": "alice", "name": "documents", ...}

# Bob receives the share (in his own client session)
sefs:/> receive '{"from_user": "alice", "name": "documents", "inode_id": "...", "key": "...", "permission": "write"}'

# Alice revokes Bob's access
sefs:/> revoke documents bob
```

**5. Consistency check**:
```
sefs:/> state
User:        alice
Merkle Root: a1b2c3d4e5f6...
Chain Head:  f6e5d4c3b2a1...
```

## Design Details

### Inode Structure

Each inode (file or directory) is encrypted with its own unique AES-256 key and stored as an opaque blob on the server. A directory inode contains the names, blob IDs, and decryption keys of its children -- so decrypting a parent gives you access to decrypt its children. The chain of trust flows from the root key stored in the client's local profile.

### Sharing Mechanism

When a file is shared, the shared node is "cut" from the tree -- it becomes an independent root. Both the owner and the shared user hold the decryption key. Writes by either user re-encrypt with a new key and update the hash chain.

When a share is revoked, the system:
1. Re-encrypts the revoked node with a new key
2. Walks **down** the subtree re-encrypting all children until hitting another shared boundary
3. Re-encrypts all parent nodes **up** to the root
4. Rejoins the node to the original tree if no other users share it

### Fork Consistency

Every filesystem operation (including reads) appends to a hash chain:
```
d_0 = hash(r_0)
d_n = hash(r_n || d_{n-1})
```
where `r_n` is the operation record (timestamp, operation type, merkle root). The chain head is verified against the server on **every operation** -- not just manual checks. If the server attempts a replay attack or serves stale data, the mismatch is detected immediately.

## Project Structure

```
├── client.py          # CLI client -- all crypto and filesystem logic
├── server.py          # Minimal Flask storage server
├── crypto_utils.py    # AES encryption, hashing, key generation
├── models.py          # Inode, Profile, ChildEntry data structures
├── merkle.py          # Merkle tree hashing and consistency chain
├── requirements.txt   # Python dependencies
└── tests/
    └── test_crypto.py # Unit tests for crypto primitives
```

## Threat Model

- **Malicious server**: Cannot read data (encrypted), cannot tamper undetected (Merkle tree), cannot fork views undetected (hash chain on every op).
- **Revoked users**: Cannot access re-encrypted data. Stale copies of previously-accessed data are inherent to any system where data was once shared.
- **Network adversary**: Sees only encrypted blobs. No plaintext file names or content traverse the wire.

## Limitations

- Single-writer per session (no concurrent multi-client locking)
- Profile file contains root key in plaintext (production would encrypt with user password)
- Share info must be transmitted out-of-band through a secure channel
- Performance degrades with deep directory trees (each mutation re-encrypts path to root)
