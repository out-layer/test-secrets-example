#!/bin/bash
# Store secrets with different access conditions
# Usage: ./01_store_secrets.sh [test_numbers...] [--send]
# Example: ./01_store_secrets.sh 1 2 3  # Generate commands for tests 1, 2, 3
#          ./01_store_secrets.sh 1 --send  # Create and send test 1 to chain
#          ./01_store_secrets.sh         # Run all tests

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load helpers (includes .env loading)
source "$SCRIPT_DIR/helpers.sh"

# Load environment
load_env

# Load test configuration
source "$SCRIPT_DIR/test_config.sh"

# Normalize repo URL (same as keystore does)
REPO=$(normalize_repo_url "$REPO")

# Parse command line arguments
SEND_TO_CHAIN=false
TESTS_TO_RUN=()

for arg in "$@"; do
    if [ "$arg" = "--send" ]; then
        SEND_TO_CHAIN=true
    else
        TESTS_TO_RUN+=("$arg")
    fi
done

# Default to all tests if none specified
if [ ${#TESTS_TO_RUN[@]} -eq 0 ]; then
    TESTS_TO_RUN=(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)
fi

echo "═══════════════════════════════════════════════════════════════"
echo "Storing Secrets - Access Control Tests"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Configuration:"
echo "  Contract: $CONTRACT"
echo "  Repo: $REPO"
echo "  Branch: $BRANCH"
echo "  Owner: $OWNER"
echo "  Tests to run: ${TESTS_TO_RUN[@]}"
echo "  Send to chain: $SEND_TO_CHAIN"
echo ""
echo "Environment:"
echo "  Keystore: $KEYSTORE_BASE_URL"
echo "  Auth token: ${KEYSTORE_AUTH_TOKEN:0:10}..."
echo ""
echo "Prerequisites:"
echo "1. Keystore running on $KEYSTORE_BASE_URL"
echo "2. .env file configured with KEYSTORE_AUTH_TOKEN"
echo "3. Accounts funded (see test_config.sh)"
echo ""

# -------------------------------------------------------------------
# Helper function to store secrets
# -------------------------------------------------------------------
store_secret() {
    local test_num=$1
    local profile=$2
    local secret_value=$3
    local access_condition=$4

    echo ""
    print_test_info "$test_num"
    echo ""
    echo "Creating secret: $secret_value"
    echo ""

    # Create secrets JSON
    local secrets_json="{\"SECRET\":\"$secret_value\"}"

    # Encrypt secrets using keystore API
    echo "🔐 Encrypting via keystore..." >&2
    local encrypted_base64
    encrypted_base64=$(encrypt_secrets_json "$REPO" "$OWNER" "$BRANCH" "$secrets_json")

    if [ -z "$encrypted_base64" ]; then
        echo "Error: Failed to encrypt secrets" >&2
        exit 1
    fi

    echo "✅ Encrypted successfully" >&2
    echo ""

    # Build JSON args (use printf to avoid shell interpretation of backslashes)
    local json_args
    # `accessor` replaced the flat repo/branch pair, and `vault_id` must be present
    # even when null: near-sdk's argument deserialiser rejects JSON that omits a
    # required Option field (see contract/src/secrets.rs).
    json_args=$(printf '{
  "accessor": { "Repo": { "repo": "%s", "branch": "%s" } },
  "profile": "%s",
  "encrypted_secrets_base64": "%s",
  "access": %s,
  "vault_id": null
}' "$REPO" "$BRANCH" "$profile" "$encrypted_base64" "$access_condition")

    if [ "$SEND_TO_CHAIN" = true ]; then
        # Send transaction to chain
        echo "📤 Sending transaction to chain..." >&2

        # Write JSON to temp file to avoid shell escaping issues with backslashes
        local temp_json=$(mktemp /tmp/near_args.XXXXXX)
        echo "$json_args" > "$temp_json"

        near contract call-function as-transaction \
            "$CONTRACT" \
            store_secrets \
            file-args "$temp_json" \
            prepaid-gas '100.0 Tgas' \
            attached-deposit '0.1 NEAR' \
            sign-as "$OWNER" \
            network-config testnet \
            sign-with-keychain \
            send

        rm -f "$temp_json"
        echo ""
        echo "✅ Transaction sent!" >&2
    else
        # Just print the command
        echo "near contract call-function as-transaction \\"
        echo "  $CONTRACT \\"
        echo "  store_secrets \\"
        echo "  json-args '$json_args' \\"
        echo "  prepaid-gas '100.0 Tgas' \\"
        echo "  attached-deposit '0.1 NEAR' \\"
        echo "  sign-as $OWNER \\"
        echo "  network-config testnet \\"
        echo "  sign-with-keychain \\"
        echo "  send"
    fi
    echo ""
}

# -------------------------------------------------------------------
# Run selected tests
# -------------------------------------------------------------------

for test_num in "${TESTS_TO_RUN[@]}"; do
    case $test_num in
        1)
            # Test 1: AllowAll
            store_secret 1 \
                "test1_allow_all" \
                "test1_allow_all" \
                '"AllowAll"'
            ;;

        2)
            # Test 2: Whitelist
            WHITELIST_JSON=$(array_to_json "${TEST2_WHITELIST[@]}")
            store_secret 2 \
                "test2_whitelist" \
                "test2_whitelist_only" \
                '{"Whitelist": {"accounts": '"$WHITELIST_JSON"'}}'
            ;;

        3)
            # Test 3: AccountPattern *.testnet
            store_secret 3 \
                "test3_pattern_testnet" \
                "test3_testnet_accounts" \
                '{"AccountPattern": {"pattern": "'"$TEST3_PATTERN"'"}}'
            ;;

        4)
            # Test 4: AccountPattern a*
            store_secret 4 \
                "test4_pattern_a" \
                "test4_starts_with_a" \
                '{"AccountPattern": {"pattern": "'"$TEST4_PATTERN"'"}}'
            ;;

        5)
            # Test 5: AccountPattern length >= 10
            store_secret 5 \
                "test5_pattern_length" \
                "test5_long_accounts" \
                '{"AccountPattern": {"pattern": "'"$TEST5_PATTERN"'"}}'
            ;;

        6)
            # Test 6: NearBalance >= 5 NEAR
            store_secret 6 \
                "test6_near_balance" \
                "test6_rich_users_only" \
                '{"NearBalance": {"operator": "Gte", "value": "'"$TEST6_MIN_NEAR"'"}}'
            ;;

        7)
            # Test 7: FtBalance >= 1000 tokens
            store_secret 7 \
                "test7_ft_balance" \
                "test7_token_holders" \
                '{"FtBalance": {"contract": "'"$TEST7_FT_CONTRACT"'", "operator": "Gte", "value": "'"$TEST7_FT_MIN"'"}}'
            ;;

        8)
            # Test 8: NftOwned - specific token (or any if token_id is empty)
            # If TEST8_NFT_TOKEN is empty, use null. Otherwise use the token_id.
            TOKEN_ID_VALUE="null"
            if [ -n "$TEST8_NFT_TOKEN" ]; then
                TOKEN_ID_VALUE="\"$TEST8_NFT_TOKEN\""
            fi
            store_secret 8 \
                "test8_nft_token" \
                "test8_nft_owners" \
                '{"NftOwned": {"contract": "'"$TEST8_NFT_CONTRACT"'", "token_id": '"$TOKEN_ID_VALUE"'}}'
            ;;

        9)
            # Test 9: NftOwned - any token
            store_secret 9 \
                "test9_nft_any" \
                "test9_nft_collection" \
                '{"NftOwned": {"contract": "'"$TEST9_NFT_CONTRACT"'", "token_id": null}}'
            ;;

        10)
            # Test 10: Logic AND - *.testnet AND >= 5 NEAR
            store_secret 10 \
                "test10_logic_and" \
                "test10_testnet_rich" \
                '{"Logic": {"operator": "And", "conditions": [{"AccountPattern": {"pattern": "'"$TEST10_PATTERN"'"}}, {"NearBalance": {"operator": "Gte", "value": "'"$TEST10_MIN_NEAR"'"}}]}}'
            ;;

        11)
            # Test 11: Logic OR - whitelist OR *.testnet
            WHITELIST_JSON=$(array_to_json "${TEST11_WHITELIST[@]}")
            store_secret 11 \
                "test11_logic_or" \
                "test11_whitelist_or_testnet" \
                '{"Logic": {"operator": "Or", "conditions": [{"Whitelist": {"accounts": '"$WHITELIST_JSON"'}}, {"AccountPattern": {"pattern": "'"$TEST11_PATTERN"'"}}]}}'
            ;;

        12)
            # Test 12: Logic NOT - NOT (>= 1 NEAR)
            store_secret 12 \
                "test12_logic_not" \
                "test12_not_poor" \
                '{"Not": {"condition": {"NearBalance": {"operator": "Gte", "value": "'"$TEST12_MIN_NEAR"'"}}}}'
            ;;

        13)
            # Test 13: Complex Logic - (whitelist OR *.testnet) AND >= 5 NEAR
            WHITELIST_JSON=$(array_to_json "${TEST13_WHITELIST[@]}")
            store_secret 13 \
                "test13_complex" \
                "test13_complex" \
                '{"Logic": {"operator": "And", "conditions": [{"Logic": {"operator": "Or", "conditions": [{"Whitelist": {"accounts": '"$WHITELIST_JSON"'}}, {"AccountPattern": {"pattern": "'"$TEST13_PATTERN"'"}}]}}, {"NearBalance": {"operator": "Gte", "value": "'"$TEST13_MIN_NEAR"'"}}]}}'
            ;;

        14)
            # Test 14: Non-existent profile - create "production" but will read "staging"
            # This test only creates the secret. Test 02 will try to read wrong profile.
            store_secret 14 \
                "$TEST14_CREATE_PROFILE" \
                "test14_production_secret" \
                '"AllowAll"'
            ;;

        15)
            # Test 15: Invalid JSON format - encrypt "foo=bar" instead of valid JSON
            # This should cause decryption/parsing error when worker tries to use it
            echo ""
            print_test_info "$test_num"
            echo ""
            echo "Creating secret with INVALID format: $TEST15_INVALID_SECRETS"
            echo ""

            # Encrypt the invalid string (not JSON) using keystore API
            echo "🔐 Encrypting invalid data via keystore..." >&2
            encrypted_base64=$(encrypt_secrets_json "$REPO" "$OWNER" "$BRANCH" "$TEST15_INVALID_SECRETS")

            if [ -z "$encrypted_base64" ]; then
                echo "Error: Failed to encrypt secrets" >&2
                exit 1
            fi

            echo "✅ Encrypted successfully (but data is invalid JSON)" >&2
            echo ""

            # Build JSON args
            json_args=$(printf '{
  "accessor": { "Repo": { "repo": "%s", "branch": "%s" } },
  "profile": "%s",
  "encrypted_secrets_base64": "%s",
  "access": "AllowAll",
  "vault_id": null
}' "$REPO" "$BRANCH" "test15_invalid_json" "$encrypted_base64")

            if [ "$SEND_TO_CHAIN" = true ]; then
                echo "📤 Sending transaction to chain..." >&2

                temp_json=$(mktemp /tmp/near_args.XXXXXX)
                echo "$json_args" > "$temp_json"

                near contract call-function as-transaction \
                    "$CONTRACT" \
                    store_secrets \
                    file-args "$temp_json" \
                    prepaid-gas '100.0 Tgas' \
                    attached-deposit '0.1 NEAR' \
                    sign-as "$OWNER" \
                    network-config testnet \
                    sign-with-keychain \
                    send

                rm -f "$temp_json"
                echo ""
                echo "✅ Transaction sent!" >&2
            else
                echo "near contract call-function as-transaction \\"
                echo "  $CONTRACT \\"
                echo "  store_secrets \\"
                echo "  json-args '$json_args' \\"
                echo "  prepaid-gas '100.0 Tgas' \\"
                echo "  attached-deposit '0.1 NEAR' \\"
                echo "  sign-as $OWNER \\"
                echo "  network-config testnet \\"
                echo "  sign-with-keychain \\"
                echo "  send"
            fi
            echo ""
            ;;

        *)
            echo "Unknown test number: $test_num (valid: 1-15)"
            ;;
    esac
done

if [ "$SEND_TO_CHAIN" = false ]; then
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "All secrets prepared! Copy and run the 'near call' commands above."
    echo "Or run with --send flag to execute immediately."
    echo "Then run: ./02_request_execution.sh [test_numbers...] [--send]"
    echo "═══════════════════════════════════════════════════════════════"
else
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "All secrets stored successfully!"
    echo "Next: ./02_request_execution.sh ${TESTS_TO_RUN[@]} --send"
    echo "═══════════════════════════════════════════════════════════════"
fi
