"""Minimal untrusted storage server.

The server stores encrypted blobs by ID. It has no knowledge of encryption keys,
file contents, or filesystem structure. It also stores hash chain heads for
fork-consistency verification.
"""

import os
import json
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

STORAGE_DIR = os.path.join(os.path.dirname(__file__), "storage")
CHAINS_DIR = os.path.join(STORAGE_DIR, "chains")


def _ensure_dirs():
    os.makedirs(STORAGE_DIR, exist_ok=True)
    os.makedirs(CHAINS_DIR, exist_ok=True)


@app.route("/blob/<blob_id>", methods=["PUT"])
def put_blob(blob_id):
    """Store an encrypted blob."""
    data = request.get_data()
    if not data:
        return jsonify({"error": "empty body"}), 400
    path = os.path.join(STORAGE_DIR, blob_id)
    with open(path, "wb") as f:
        f.write(data)
    return jsonify({"status": "ok"}), 200


@app.route("/blob/<blob_id>", methods=["GET"])
def get_blob(blob_id):
    """Retrieve an encrypted blob."""
    path = os.path.join(STORAGE_DIR, blob_id)
    if not os.path.exists(path):
        return jsonify({"error": "not found"}), 404
    with open(path, "rb") as f:
        data = f.read()
    return Response(data, mimetype="application/octet-stream")


@app.route("/blob/<blob_id>", methods=["DELETE"])
def delete_blob(blob_id):
    """Delete an encrypted blob."""
    path = os.path.join(STORAGE_DIR, blob_id)
    if os.path.exists(path):
        os.remove(path)
    return jsonify({"status": "ok"}), 200


@app.route("/chain/<username>", methods=["GET"])
def get_chain(username):
    """Get the stored hash chain head for a user."""
    path = os.path.join(CHAINS_DIR, f"{username}.json")
    if not os.path.exists(path):
        return jsonify({"chain_head": "", "history": []}), 200
    with open(path, "r") as f:
        data = json.load(f)
    return jsonify(data), 200


@app.route("/chain/<username>", methods=["PUT"])
def put_chain(username):
    """Update the hash chain head for a user."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "empty body"}), 400
    path = os.path.join(CHAINS_DIR, f"{username}.json")
    # Load existing history
    existing = {"chain_head": "", "history": []}
    if os.path.exists(path):
        with open(path, "r") as f:
            existing = json.load(f)
    existing["chain_head"] = data.get("chain_head", "")
    if "record" in data:
        existing["history"].append(data["record"])
    with open(path, "w") as f:
        json.dump(existing, f, indent=2)
    return jsonify({"status": "ok"}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"}), 200


if __name__ == "__main__":
    _ensure_dirs()
    print("Starting encrypted filesystem storage server on :5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
