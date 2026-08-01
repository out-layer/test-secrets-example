#!/bin/bash
# Central configuration for all access control tests
# Edit this file to customize accounts, contract, and test parameters

# =============================================================================
# CONTRACT & REPO SETTINGS
# =============================================================================
export CONTRACT="outlayer.testnet"
export REPO="https://github.com/out-layer/test-secrets-example"
export BRANCH="main"
export OWNER="zavodil.testnet"

# =============================================================================
# TEST ACCOUNTS
# =============================================================================

# Test 1: AllowAll
export TEST1_ALLOWED_ACCOUNTS=("zavodil2.testnet" "zavodil3.testnet")

# Test 2: Whitelist
export TEST2_WHITELIST=("zavodil2.testnet" "zavodil3.testnet")
export TEST2_ALLOWED_ACCOUNTS=("zavodil2.testnet")
export TEST2_DENIED_ACCOUNTS=("denied_account.testnet")

# Test 3: AccountPattern *.offchainvm.testnet (regex with escaped dots)
# Note: Use double backslash for JSON escaping (\\ becomes \ in JSON string)
export TEST3_PATTERN=".*\\\\.offchainvm\\\\.testnet\$"
export TEST3_ALLOWED_ACCOUNTS=("c3.offchainvm.testnet" "c4.offchainvm.testnet")
export TEST3_DENIED_ACCOUNTS=("denied_account.testnet" "zavodil2.testnet")

# Test 4: AccountPattern a* (regex - starts with 'a')
export TEST4_PATTERN="^z.*"
export TEST4_ALLOWED_ACCOUNTS=("zavodil.testnet" "zavodil2.testnet" "zavodil3.testnet")
export TEST4_DENIED_ACCOUNTS=("denied_account.testnet")

# Test 5: AccountPattern length >= 16 (regex - at least 15 chars)
export TEST5_PATTERN="^.{16,}\$"
export TEST5_ALLOWED_ACCOUNTS=("c3.offchainvm.testnet")
export TEST5_DENIED_ACCOUNTS=("zavodil.testnet")

# Test 6: NearBalance >= 10 NEAR
export TEST6_MIN_NEAR="10000000000000000000000000"  # 10 NEAR in yoctoNEAR
export TEST6_ALLOWED_ACCOUNTS=("zavodil.testnet" "dev-1671306554268-23143189061640" "zavodil2.testnet")
export TEST6_DENIED_ACCOUNTS=("denied_account.testnet" "web4.testnet")

# Test 7: FtBalance >= 1000 tokens
export TEST7_FT_CONTRACT="usdn.testnet"
export TEST7_FT_MIN="1000000000000000000"
export TEST7_ALLOWED_ACCOUNTS=("zavodil2.testnet" "zavodil3.testnet")
export TEST7_DENIED_ACCOUNTS=("denied_account.testnet")

# Test 8: NftOwned - specific token
export TEST8_NFT_CONTRACT="jswm.testnet"
export TEST8_NFT_TOKEN="zavodil2.testnet"  # this is a specific token_id, not an owner_id
export TEST8_ALLOWED_ACCOUNTS=("zavodil2.testnet")
export TEST8_DENIED_ACCOUNTS=("denied_account.testnet"  "zavodil.testnet" "web4.testnet")

# Test 9: NftOwned - any token
export TEST9_NFT_CONTRACT="dev-1671306554268-23143189061640"
export TEST9_NFT_TOKEN=""  # Empty string = check any token (same as null). Set specific token_id if needed.
export TEST9_ALLOWED_ACCOUNTS=("zavodil.testnet" "test_alice.testnet")
export TEST9_DENIED_ACCOUNTS=("denied_account.testnet" "zavodil3.testnet")

# Test 10: Logic AND - z*.testnet AND >= 200 NEAR
export TEST10_PATTERN="^z.*"
export TEST10_MIN_NEAR="200000000000000000000000000"
export TEST10_ALLOWED_ACCOUNTS=("zavodil.testnet")
export TEST10_DENIED_ACCOUNTS=("zavodil2.testnet" "dev-1671306554268-23143189061640")

# Test 11: Logic OR - whitelist OR *.testnet
export TEST11_WHITELIST=("denied_account.testnet" "dev-1671306554268-23143189061640")
export TEST11_PATTERN="^z.*"
export TEST11_ALLOWED_ACCOUNTS=("zavodil.testnet" "zavodil2.testnet" "denied_account.testnet" "dev-1671306554268-23143189061640")
export TEST11_DENIED_ACCOUNTS=("web4.testnet")

# Test 12: Logic NOT - NOT (>= 200 NEAR)
export TEST12_MIN_NEAR="200000000000000000000000000"  # 200 NEAR
export TEST12_ALLOWED_ACCOUNTS=("zavodil2.testnet" "web4.testnet") # poor
export TEST12_DENIED_ACCOUNTS=("zavodil.testnet" "dev-1671306554268-23143189061640")

# Test 13: Complex Logic - (whitelist OR *.testnet) AND >= 200 NEAR
export TEST13_WHITELIST=("dev-1671306554268-23143189061640" "zavodil2.testnet")
export TEST13_PATTERN="^z.*"
export TEST13_MIN_NEAR="200000000000000000000000000"
export TEST13_ALLOWED_ACCOUNTS=("dev-1671306554268-23143189061640" "zavodil.testnet")
export TEST13_DENIED_ACCOUNTS=("web4.testnet" "zavodil2.testnet") # "zavodil2.testnet" is poor

# Test 14: Non-existent profile - create "production" but read "staging"
export TEST14_CREATE_PROFILE="production"
export TEST14_READ_PROFILE="staging"
export TEST14_ACCOUNT="denied_account.testnet"

# Test 15: Invalid JSON format - send "foo=bar" instead of valid JSON
export TEST15_INVALID_SECRETS="foo=bar"
export TEST15_ACCOUNT="denied_account.testnet"

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

# Print test info
print_test_info() {
    local test_num=$1
    echo "═══════════════════════════════════════════════════════════════"
    echo "Test $test_num Configuration:"

    case $test_num in
        1)
            echo "  Type: AllowAll"
            echo "  Allowed: ${TEST1_ALLOWED_ACCOUNTS[@]}"
            ;;
        2)
            echo "  Type: Whitelist"
            echo "  Whitelist: ${TEST2_WHITELIST[@]}"
            echo "  Should ALLOW: ${TEST2_ALLOWED_ACCOUNTS[@]}"
            echo "  Should DENY: ${TEST2_DENIED_ACCOUNTS[@]}"
            ;;
        3)
            echo "  Type: AccountPattern"
            echo "  Pattern: $TEST3_PATTERN"
            echo "  Should ALLOW: ${TEST3_ALLOWED_ACCOUNTS[@]}"
            echo "  Should DENY: ${TEST3_DENIED_ACCOUNTS[@]}"
            ;;
        4)
            echo "  Type: AccountPattern"
            echo "  Pattern: $TEST4_PATTERN"
            echo "  Should ALLOW: ${TEST4_ALLOWED_ACCOUNTS[@]}"
            echo "  Should DENY: ${TEST4_DENIED_ACCOUNTS[@]}"
            ;;
        5)
            echo "  Type: AccountPattern (length)"
            echo "  Pattern: $TEST5_PATTERN"
            echo "  Should ALLOW: ${TEST5_ALLOWED_ACCOUNTS[@]}"
            echo "  Should DENY: ${TEST5_DENIED_ACCOUNTS[@]}"
            ;;
        6)
            echo "  Type: NearBalance"
            echo "  Minimum: $TEST6_MIN_NEAR yoctoNEAR"
            echo "  Should ALLOW: ${TEST6_ALLOWED_ACCOUNTS[@]}"
            echo "  Should DENY: ${TEST6_DENIED_ACCOUNTS[@]}"
            ;;
        7)
            echo "  Type: FtBalance"
            echo "  Contract: $TEST7_FT_CONTRACT"
            echo "  Minimum: $TEST7_FT_MIN tokens"
            echo "  Should ALLOW: ${TEST7_ALLOWED_ACCOUNTS[@]}"
            echo "  Should DENY: ${TEST7_DENIED_ACCOUNTS[@]}"
            ;;
        8)
            echo "  Type: NftOwned (specific)"
            echo "  Contract: $TEST8_NFT_CONTRACT"
            echo "  Token: $TEST8_NFT_TOKEN"
            echo "  Should ALLOW: ${TEST8_ALLOWED_ACCOUNTS[@]}"
            echo "  Should DENY: ${TEST8_DENIED_ACCOUNTS[@]}"
            ;;
        9)
            echo "  Type: NftOwned (any)"
            echo "  Contract: $TEST9_NFT_CONTRACT"
            echo "  Should ALLOW: ${TEST9_ALLOWED_ACCOUNTS[@]}"
            echo "  Should DENY: ${TEST9_DENIED_ACCOUNTS[@]}"
            ;;
        10)
            echo "  Type: Logic AND"
            echo "  Pattern: $TEST10_PATTERN"
            echo "  Min NEAR: $TEST10_MIN_NEAR yoctoNEAR (200 NEAR)"
            echo "  Should ALLOW: ${TEST10_ALLOWED_ACCOUNTS[@]}"
            echo "  Should DENY: ${TEST10_DENIED_ACCOUNTS[@]}"
            ;;
        11)
            echo "  Type: Logic OR"
            echo "  Whitelist: ${TEST11_WHITELIST[@]}"
            echo "  Pattern: $TEST11_PATTERN"
            echo "  Should ALLOW: ${TEST11_ALLOWED_ACCOUNTS[@]}"
            echo "  Should DENY: ${TEST11_DENIED_ACCOUNTS[@]}"
            ;;
        12)
            echo "  Type: Logic NOT"
            echo "  NOT (>= $TEST12_MIN_NEAR yoctoNEAR)"
            echo "  Should ALLOW: ${TEST12_ALLOWED_ACCOUNTS[@]}"
            echo "  Should DENY: ${TEST12_DENIED_ACCOUNTS[@]}"
            ;;
        13)
            echo "  Type: Complex Logic"
            echo "  (Whitelist OR Pattern) AND MinBalance"
            echo "  Should ALLOW: ${TEST13_ALLOWED_ACCOUNTS[@]}"
            echo "  Should DENY: ${TEST13_DENIED_ACCOUNTS[@]}"
            ;;
        14)
            echo "  Type: Non-existent profile"
            echo "  Account: $TEST14_ACCOUNT"
            echo "  Creates profile: $TEST14_CREATE_PROFILE"
            echo "  Tries to read: $TEST14_READ_PROFILE (does not exist)"
            ;;
        15)
            echo "  Type: Invalid JSON format"
            echo "  Account: $TEST15_ACCOUNT"
            echo "  Invalid data: $TEST15_INVALID_SECRETS (should be JSON)"
            echo "  Expected: Decryption/parsing error"
            ;;
    esac
    echo "═══════════════════════════════════════════════════════════════"
}

# Convert array to JSON array string
array_to_json() {
    local arr=("$@")
    local json="["
    for i in "${!arr[@]}"; do
        json+="\"${arr[$i]}\""
        if [ $i -lt $((${#arr[@]} - 1)) ]; then
            json+=", "
        fi
    done
    json+="]"
    echo "$json"
}
