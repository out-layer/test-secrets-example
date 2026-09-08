# Secrets Ark - Access Control Test Suite

WASI WASM project for testing encrypted secrets with different access conditions.

## Overview

**test-secrets-example** is a WASI P2 application that:
- Reads JSON input from stdin (required by NEAR OutLayer)
- Reads the `SECRET` environment variable from WASI env
- Returns JSON output to stdout with secret status

This verifies:
1. Secrets are correctly decrypted by the keystore
2. Access control conditions are properly validated
3. WASI environment variables injection works
4. Proper WASI P2 stdin/stdout JSON format

## Build

```bash
# Ensure wasm32-wasip2 target is installed
rustup target add wasm32-wasip2

# Build
./build.sh

# Output: target/wasm32-wasip2/release/test-secrets-example.wasm
```

## Test Suite

### Configuration

All test settings are centralized in [tests/test_config.sh](tests/test_config.sh):

```bash
# Edit this file to customize:
export CONTRACT="outlayer.testnet"
export REPO="github.com/test-user/test-secrets-example"
export OWNER="owner.testnet"

# Test accounts for each scenario
export TEST2_WHITELIST=("allowed1.testnet" "allowed2.testnet")
export TEST6_ALLOWED_ACCOUNTS=("rich.testnet")
# ... etc
```

### Prerequisites

1. **Running services:**
   - Coordinator API (port 8080)
   - Keystore worker (port 8081)
   - Worker with event monitor
   - PostgreSQL + Redis

2. **Contract deployed:**
   - Edit `CONTRACT` in `tests/test_config.sh`

3. **Test accounts:**
   - Edit account names in `tests/test_config.sh`
   - Fund accounts as specified in config
   - Default accounts: owner.testnet, allowed1.testnet, alice.testnet, rich.testnet, etc.

4. **GitHub repository:**
   - Edit `REPO` in `tests/test_config.sh`
   - Upload `test-secrets-example.wasm` to the repo

### Quick Local Test

```bash
# Build first
./build.sh

# Test locally without secrets
echo '{"message":"test"}' | wasmtime target/wasm32-wasip2/release/test-secrets-example.wasm

# Expected output:
# {"status":"error","secret_value":null,"secret_found":false,"message":"SECRET environment variable not found"}

# Test with SECRET env var
echo '{"message":"test"}' | wasmtime --env SECRET=my-secret-value target/wasm32-wasip2/release/test-secrets-example.wasm

# Expected output:
# {"status":"success","secret_value":"my-secret-value","secret_found":true,"message":"SECRET found! Value: my-secret-value"}
```

### Step 1: Configure Tests

Edit `tests/test_config.sh` with your accounts and settings:

```bash
# Example: Run test 2 with custom accounts
export TEST2_WHITELIST=("myuser1.testnet" "myuser2.testnet")
export TEST2_ALLOWED_ACCOUNTS=("${TEST2_WHITELIST[@]}")
export TEST2_DENIED_ACCOUNTS=("other.testnet")
```

### Step 2: Store Secrets

```bash
cd ../../keystore-worker/

# Run all tests (1-13)
bash ../wasi-examples/test-secrets-example/tests/01_store_secrets.sh

# Run specific tests only
bash ../wasi-examples/test-secrets-example/tests/01_store_secrets.sh 1 2 3

# Run single test
bash ../wasi-examples/test-secrets-example/tests/01_store_secrets.sh 2
```

The script generates `near call` commands for storing secrets. Available tests:

| Test | Profile | Access Condition | Description |
|------|---------|------------------|-------------|
| 1 | `test1_allow_all` | `AllowAll` | Anyone can access |
| 2 | `test2_whitelist` | `Whitelist([allowed1, allowed2])` | Only whitelisted accounts |
| 3 | `test3_pattern_testnet` | `AccountPattern("*.testnet")` | Only *.testnet accounts |
| 4 | `test4_pattern_a` | `AccountPattern("a*")` | Accounts starting with 'a' |
| 5 | `test5_pattern_length` | `AccountPattern("?????????*")` | Accounts with 10+ chars |
| 6 | `test6_near_balance` | `NearBalance { min: 5 NEAR }` | Accounts with >= 5 NEAR |
| 7 | `test7_ft_balance` | `FtBalance { contract, min: 1000 }` | Token holders |
| 8 | `test8_nft_token` | `NftOwned { contract, token_id: "123" }` | Specific NFT owner |
| 9 | `test9_nft_any` | `NftOwned { contract, token_id: null }` | Any NFT from collection |
| 10 | `test10_logic_and` | `AND(*.testnet, >= 5 NEAR)` | Both conditions |
| 11 | `test11_logic_or` | `OR(whitelist, *.testnet)` | Either condition |
| 12 | `test12_logic_not` | `NOT(>= 1 NEAR)` | Accounts with < 1 NEAR |
| 13 | `test13_complex` | `AND(OR(whitelist, *.testnet), >= 5 NEAR)` | Nested logic |

**Copy and run each command manually** - the script outputs ready-to-use `near call` commands.

### Step 3: Request Execution

```bash
# From keystore-worker/ directory

# Run all tests
bash ../wasi-examples/test-secrets-example/tests/02_request_execution.sh

# Run specific tests only
bash ../wasi-examples/test-secrets-example/tests/02_request_execution.sh 1 2 3

# Run single test
bash ../wasi-examples/test-secrets-example/tests/02_request_execution.sh 2
```

The script generates `near call` commands using accounts from `test_config.sh`. For each test:
- **SUCCESS cases** - should decrypt secrets and return JSON:
  ```json
  {"status":"success","secret_value":"test1_allow_all","secret_found":true,"message":"SECRET found! Value: test1_allow_all"}
  ```
- **FAIL cases** - should fail at keystore decryption or return JSON:
  ```json
  {"status":"error","secret_value":null,"secret_found":false,"message":"SECRET environment variable not found"}
  ```

**Copy and run each command manually**. The script shows which accounts should succeed (✅) or fail (❌).

### Step 4: Verify Results

```bash
# Check execution result
near view outlayer.testnet get_request '{"request_id": 1}'

# Check worker logs
docker logs offchainvm-worker

# Check keystore logs
docker logs offchainvm-keystore
```

## Usage Examples

### Example 1: Quick test with --send flag (NEW!)

```bash
cd tests/

# Store secret and send to chain immediately
./01_store_secrets.sh 1 --send

# Output:
# 🔑 Seed: github.com/user/repo:owner.testnet:main
# ✅ Got pubkey: a1b2c3d4...
# 🔐 Encrypting via keystore...
# ✅ Encrypted successfully
# 📤 Sending transaction to chain...
# ✅ Transaction sent!

# Test execution and send immediately
./02_request_execution.sh 1 --send

# All transactions will be sent automatically!
```

### Example 2: Generate commands without sending

```bash
# Just generate commands for test 2
./01_store_secrets.sh 2

# Output shows command - copy and run manually
near contract call-function as-transaction \
  outlayer.testnet \
  store_secrets \
  json-args '{"repo":"..."}' \
  ...
```

### Example 3: Test multiple conditions (Tests 1, 3, 6)

```bash
# Generate commands for tests 1, 3, 6
./01_store_secrets.sh 1 3 6

# Or send all immediately
./01_store_secrets.sh 1 3 6 --send
```

### Example 4: View test configuration

```bash
# Check what test 10 will do
source tests/test_config.sh
print_test_info 10

# Output:
# Test 10 Configuration:
#   Type: Logic AND
#   Pattern: *.testnet
#   Min NEAR: 5000000000000000000000000 yoctoNEAR (5 NEAR)
#   Should ALLOW: rich.testnet
#   Should DENY: poor.testnet bob.near
```

## Access Condition Examples

### Pattern Matching

```rust
// Match *.testnet accounts
"AccountPattern": "*.testnet"

// Match accounts starting with 'a'
"AccountPattern": "a*"

// Match accounts with 10+ characters (9 '?' + '*')
"AccountPattern": "?????????*"

// Match accounts ending with '.near'
"AccountPattern": "*.near"
```

### Logic Combinations

```rust
// AND - both conditions must pass
"Logic": {
  "And": [
    {"AccountPattern": "*.testnet"},
    {"NearBalance": {"min": "5000000000000000000000000"}}
  ]
}

// OR - either condition can pass
"Logic": {
  "Or": [
    {"Whitelist": ["allowed1.testnet"]},
    {"AccountPattern": "*.testnet"}
  ]
}

// NOT - inverted condition
"Logic": {
  "Not": {
    "NearBalance": {"min": "1000000000000000000000000"}
  }
}

// Complex nested logic
"Logic": {
  "And": [
    {
      "Logic": {
        "Or": [
          {"Whitelist": ["allowed1.testnet"]},
          {"AccountPattern": "*.testnet"}
        ]
      }
    },
    {"NearBalance": {"min": "5000000000000000000000000"}}
  ]
}
```

## Expected Test Results

| Test | Account | Expected | Output Field | Reason |
|------|---------|----------|--------------|--------|
| 1 | alice.testnet | ✅ SUCCESS | `secret_found: true` | AllowAll |
| 2 | allowed1.testnet | ✅ SUCCESS | `secret_found: true` | In whitelist |
| 2b | bob.testnet | ❌ FAIL | `secret_found: false` | Not in whitelist |
| 3 | alice.testnet | ✅ SUCCESS | `secret_found: true` | Matches *.testnet |
| 3b | bob.near | ❌ FAIL | `secret_found: false` | Doesn't match *.testnet |
| 4 | alice.testnet | ✅ SUCCESS | `secret_found: true` | Starts with 'a' |
| 4b | bob.testnet | ❌ FAIL | `secret_found: false` | Doesn't start with 'a' |
| 5 | longaccount.testnet | ✅ SUCCESS | `secret_found: true` | 10+ chars |
| 5b | bob.near | ❌ FAIL | `secret_found: false` | < 10 chars |
| 6 | rich.testnet | ✅ SUCCESS | `secret_found: true` | >= 5 NEAR |
| 6b | poor.testnet | ❌ FAIL | `secret_found: false` | < 5 NEAR |
| 7 | holder.testnet | ✅ SUCCESS | `secret_found: true` | >= 1000 tokens |
| 8 | nftowner.testnet | ✅ SUCCESS | `secret_found: true` | Owns token #123 |
| 9 | nftowner.testnet | ✅ SUCCESS | `secret_found: true` | Owns any NFT |
| 10 | rich.testnet | ✅ SUCCESS | `secret_found: true` | *.testnet AND >= 5 NEAR |
| 10b | poor.testnet | ❌ FAIL | `secret_found: false` | *.testnet but < 5 NEAR |
| 11 | alice.testnet | ✅ SUCCESS | `secret_found: true` | Not whitelisted but *.testnet |
| 12 | poor.testnet | ✅ SUCCESS | `secret_found: true` | NOT(>= 1 NEAR) = < 1 NEAR |
| 13 | rich.testnet | ✅ SUCCESS | `secret_found: true` | Complex nested conditions |

## Manual Testing Adjustments

Before running tests, you may need to:

1. **Update test scripts:**
   - Change `REPO` to your GitHub repository
   - Change `CONTRACT` to your contract ID
   - Change `OWNER` to your secrets owner account

2. **Adjust balances:**
   ```bash
   # Transfer to rich.testnet
   near send <your-account> rich.testnet 10

   # Check balance
   near view rich.testnet state
   ```

3. **Setup FT/NFT contracts (optional):**
   - Deploy test FT contract
   - Mint tokens to `holder.testnet`
   - Deploy test NFT contract
   - Mint NFT to `nftowner.testnet`
   - Update contract IDs in `01_store_secrets.sh`

4. **Monitor worker:**
   ```bash
   # Watch worker logs in real-time
   docker logs -f offchainvm-worker

   # Watch keystore logs
   docker logs -f offchainvm-keystore
   ```

## Troubleshooting

**Secrets not decrypting:**
- Check keystore worker is running on port 8081
- Verify worker can reach keystore (`KEYSTORE_BASE_URLS` in worker `.env`)
- Check worker logs for decryption errors

**Access denied errors:**
- Verify account meets access conditions
- Check keystore logs for validation details
- Ensure NEAR RPC URL is correct for balance checks

**WASM execution fails:**
- Verify WASM file uploaded to correct GitHub repo/branch
- Check worker can compile/download WASM
- Verify coordinator cache settings

**"SECRET not found" in output (JSON with `secret_found: false`):**
- Secrets not decrypted (access control denied) OR
- Secrets successfully passed but WASM didn't receive env var
- Check keystore logs for access control validation
- Check worker WASI environment injection code
- Verify executor passes env vars to WASM instance

**Invalid JSON output:**
- Check WASM is reading from stdin and writing to stdout
- Ensure `io::stdout().flush()` is called
- Verify input_data is valid JSON: `{"message":"test"}`
