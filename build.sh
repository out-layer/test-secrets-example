#!/bin/bash
set -e

cd "$(dirname "$0")"
WASM_FILE=target/wasm32-wasip2/release/test-secrets-example.wasm

echo "Building test-secrets-example for wasm32-wasip2 (with the manifest)..."
cargo build --target wasm32-wasip2 --release --features manifest

# The published artefact must carry the manifest: it names the author's secret
# profile, and a project run without it never sees AUTHOR_SECRET.
if ! grep -qa 'outlayer.manifest' "$WASM_FILE"; then
    echo "ERROR: outlayer.manifest custom section is missing from $WASM_FILE" >&2
    exit 1
fi
python3 -c 'import json; json.load(open("manifest.json"))' || { echo "ERROR: manifest.json is not JSON" >&2; exit 1; }

echo "Build complete!"
echo "WASM file: $WASM_FILE"
echo ""
echo "File size:"
ls -lh "$WASM_FILE"
echo ""
echo "sha256:"
shasum -a 256 "$WASM_FILE"
