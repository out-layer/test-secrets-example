#!/bin/bash
# Helper functions for test scripts

# Normalize repo URL (same logic as keystore)
# Removes https://, http://, converts git@ format
normalize_repo_url() {
    local repo=$1

    # Remove https:// or http://
    repo=$(echo "$repo" | sed 's|^https://||' | sed 's|^http://||')

    # Convert git@github.com:user/repo.git to github.com/user/repo
    if [[ "$repo" =~ ^git@github.com: ]]; then
        repo=$(echo "$repo" | sed 's|^git@github.com:|github.com/|' | sed 's|\.git$||')
    fi

    # Ensure it starts with github.com/
    if [[ ! "$repo" =~ ^github.com/ ]]; then
        repo="github.com/$repo"
    fi

    echo "$repo"
}

# Load environment variables
load_env() {
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local env_file="$script_dir/../.env"

    if [ ! -f "$env_file" ]; then
        echo "Error: .env file not found at $env_file" >&2
        echo "Please copy .env.example to .env and configure it" >&2
        exit 1
    fi

    # Load .env file
    set -a
    source "$env_file"
    set +a

    # Validate required variables
    if [ -z "$KEYSTORE_BASE_URL" ]; then
        echo "Error: KEYSTORE_BASE_URL not set in .env" >&2
        exit 1
    fi

    if [ -z "$KEYSTORE_AUTH_TOKEN" ]; then
        echo "Error: KEYSTORE_AUTH_TOKEN not set in .env" >&2
        exit 1
    fi
}

# Encrypt secrets using keystore API directly
encrypt_secrets_json() {
    local repo=$1
    local owner=$2
    local branch=$3
    local secrets_json=$4

    # Normalize repo URL
    if [[ "$repo" =~ ^https://github.com/ ]]; then
        repo=$(echo "$repo" | sed 's|https://github.com/|github.com/|')
    elif [[ "$repo" =~ ^git@github.com: ]]; then
        repo=$(echo "$repo" | sed 's|git@github.com:|github.com/|' | sed 's|\.git$||')
    elif [[ ! "$repo" =~ ^github.com/ ]]; then
        repo="github.com/$repo"
    fi

    # Build seed: repo:owner[:branch]
    local seed="$repo:$owner"
    if [ -n "$branch" ]; then
        seed="$seed:$branch"
    fi

    echo "🔑 Seed: $seed" >&2

    # Get public key from keystore.
    #
    # POST with a JSON body, not GET with a query string: the keystore validates the
    # secrets alongside the seed (reserved keywords such as NEAR_SENDER_ID are rejected
    # here rather than at execution time), so `secrets_json` is part of the request.
    # A GET against this route answers 405.
    local pubkey_response
    pubkey_response=$(curl -s -X POST \
        -H "Authorization: Bearer $KEYSTORE_AUTH_TOKEN" \
        -H "Content-Type: application/json" \
        --data "$(jq -n --arg seed "$seed" --arg secrets "$secrets_json" \
            '{seed: $seed, secrets_json: $secrets}')" \
        "$KEYSTORE_BASE_URL/pubkey")

    if [ $? -ne 0 ]; then
        echo "Error: Failed to connect to keystore at $KEYSTORE_BASE_URL" >&2
        return 1
    fi

    local pubkey
    pubkey=$(echo "$pubkey_response" | jq -r '.pubkey' 2>/dev/null)

    if [ -z "$pubkey" ] || [ "$pubkey" = "null" ]; then
        echo "Error: Failed to get public key from keystore" >&2
        echo "Response: $pubkey_response" >&2
        return 1
    fi

    echo "✅ Got pubkey: ${pubkey:0:16}..." >&2

    # Encrypt with ECIES v1 — the format the keystore expects.
    #
    # Wire format (see keystore-worker/src/crypto.rs::decrypt_ecies):
    #   0x01 | ephemeral_x25519_pubkey (32) | nonce (12) | ciphertext | tag (16)
    #
    # /pubkey returns the recipient's X25519 public key in hex, so this is a plain
    # ECDH + HKDF-SHA256(info="outlayer-keystore-v1") + ChaCha20-Poly1305 with empty
    # associated data. The previous implementation here XOR-ed the plaintext against
    # SHA256(pubkey || "keystore-encryption-v1"), a scheme the keystore no longer
    # accepts — it failed at execution time with "Failed to decrypt secrets".
    local encrypted_base64
    encrypted_base64=$(SECRETS_PLAINTEXT="$secrets_json" PUBKEY_HEX="$pubkey" python3 -c "
import os, base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

recipient = X25519PublicKey.from_public_bytes(bytes.fromhex(os.environ['PUBKEY_HEX']))
ephemeral = X25519PrivateKey.generate()
eph_pub = ephemeral.public_key().public_bytes(
    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
)

shared = ephemeral.exchange(recipient)
key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
           info=b'outlayer-keystore-v1').derive(shared)

nonce = os.urandom(12)
ct = ChaCha20Poly1305(key).encrypt(nonce, os.environ['SECRETS_PLAINTEXT'].encode(), None)

print(base64.b64encode(bytes([0x01]) + eph_pub + nonce + ct).decode('ascii'))
" 2>&1)

    if [ $? -ne 0 ]; then
        echo "Error: Failed to encrypt secrets" >&2
        echo "$encrypted_base64" >&2
        return 1
    fi

    echo "$encrypted_base64"
}
