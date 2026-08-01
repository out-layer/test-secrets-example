#!/bin/bash
set -e

echo "Building test-secrets-example for wasm32-wasip2..."

cargo build --target wasm32-wasip2 --release

echo "Build complete!"
echo "WASM file: target/wasm32-wasip2/release/test-secrets-example.wasm"
echo ""
echo "File size:"
ls -lh target/wasm32-wasip2/release/test-secrets-example.wasm
