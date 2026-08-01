#!/bin/bash
# Request execution with secrets from different accounts
# Usage: ./02_request_execution.sh [test_numbers...] [--send] [--verbose]
# Example: ./02_request_execution.sh 1 2 3        # Generate commands for tests 1, 2, 3
#          ./02_request_execution.sh 2 --send    # Test 2 and send (compact output)
#          ./02_request_execution.sh 2 --send --verbose  # Test 2 with full output
#          ./02_request_execution.sh             # Run all tests

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load helpers
source "$SCRIPT_DIR/helpers.sh"

# Load configuration
source "$SCRIPT_DIR/test_config.sh"

# Normalize repo URL (same as keystore does)
REPO=$(normalize_repo_url "$REPO")

# Parse command line arguments
SEND_TO_CHAIN=false
VERBOSE=false
TESTS_TO_RUN=()

for arg in "$@"; do
    if [ "$arg" = "--send" ]; then
        SEND_TO_CHAIN=true
    elif [ "$arg" = "--verbose" ]; then
        VERBOSE=true
    else
        TESTS_TO_RUN+=("$arg")
    fi
done

# Default to all tests if none specified
if [ ${#TESTS_TO_RUN[@]} -eq 0 ]; then
    TESTS_TO_RUN=(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)
fi

echo "═══════════════════════════════════════════════════════════════"
echo "Testing Execution Requests - Access Control Validation"
echo "═══════════════════════════════════════════════════════════════"
echo ""
if [ "$VERBOSE" = true ]; then
    echo "Configuration:"
    echo "  Contract: $CONTRACT"
    echo "  Repo: $REPO"
    echo "  Branch: $BRANCH"
    echo "  Owner: $OWNER"
    echo "  Tests to run: ${TESTS_TO_RUN[@]}"
    echo "  Send to chain: $SEND_TO_CHAIN"
    echo ""
    echo "Prerequisites:"
    echo "1. Run 01_store_secrets.sh first"
    echo "2. Coordinator + worker + keystore running"
    echo "3. Upload test-secrets-example.wasm to GitHub repo: $REPO"
    echo ""
else
    echo "Tests: ${TESTS_TO_RUN[@]} | Repo: $REPO | Send: $SEND_TO_CHAIN"
    echo ""
fi

# -------------------------------------------------------------------
# Helper function to request execution
# -------------------------------------------------------------------
request_execution() {
    local test_num=$1
    local profile=$2
    local account=$3
    local expected=$4  # "SUCCESS" or "FAIL"

    local emoji=""
    if [ "$expected" = "SUCCESS" ]; then
        emoji="✅"
    else
        emoji="❌"
    fi

    if [ "$VERBOSE" = true ]; then
        echo ""
        echo "─────────────────────────────────────────────────────────────"
        echo "Test ${test_num} - ${profile} - Account: ${account}"
        echo "Expected: ${emoji} ${expected}"
        echo "─────────────────────────────────────────────────────────────"
    else
        # Compact output
        printf "Test %2d | %-30s | %s" "$test_num" "$account" "$emoji $expected"
    fi

    # Build JSON args
    local json_args
    json_args=$(cat <<EOF
{
  "code_source": {
    "repo": "$REPO",
    "commit": "$BRANCH",
    "build_target": "wasm32-wasip1"
  },
  "secrets_ref": {
    "profile": "$profile",
    "account_id": "$OWNER"
  },
  "input_data": "{\"message\":\"test\"}"
}
EOF
)

    if [ "$SEND_TO_CHAIN" = true ]; then
        # Send transaction to chain
        if [ "$VERBOSE" = true ]; then
            echo "📤 Sending from $account..." >&2
        fi

        # Capture output (disable exit on error for this command)
        local output
        local exit_code
        set +e
        output=$(near contract call-function as-transaction \
            "$CONTRACT" \
            request_execution \
            json-args "$json_args" \
            prepaid-gas '300.0 Tgas' \
            attached-deposit '0.1 NEAR' \
            sign-as "$account" \
            network-config testnet \
            sign-with-keychain \
            send 2>&1)
        exit_code=$?
        set -e

        if [ "$VERBOSE" = true ]; then
            echo "$output"
            echo ""
        fi

        # Check result and determine actual outcome
        local actual_result=""
        local result_icon=""
        local result_msg=""

        if echo "$output" | grep -q "SECRET found"; then
            # Execution succeeded and secret was found
            actual_result="SUCCESS"
            result_icon="🔓"
            result_msg="Secret accessible"
        elif echo "$output" | grep -q "Access.*denied"; then
            # Access was denied by keystore (expected for FAIL cases)
            actual_result="FAIL"
            result_icon="🔒"
            result_msg="Access denied"
        elif echo "$output" | grep -q "Secrets not found"; then
            # Secrets not found - user configuration issue (expected for FAIL cases like test 14)
            actual_result="FAIL"
            result_icon="🔍"
            result_msg="Secrets not found"
        elif echo "$output" | grep -q "Invalid secrets format"; then
            # Invalid secrets format - user provided wrong data (expected for FAIL cases like test 15)
            actual_result="FAIL"
            result_icon="📝"
            result_msg="Invalid secrets format"
        elif [ $exit_code -ne 0 ]; then
            # Other error (compilation, execution failure, etc.)
            actual_result="ERROR"
            result_icon="❌"
            if echo "$output" | grep -q "Compilation failed"; then
                result_msg="Compilation failed"
            elif echo "$output" | grep -q "Execution failed"; then
                result_msg="Execution failed"
            else
                result_msg="Transaction error"
            fi
        else
            # Success but secret not found (shouldn't happen with our test)
            actual_result="FAIL"
            result_icon="❌"
            result_msg="Secret not found"
        fi

        # Compare with expected result and print result
        if [ "$VERBOSE" = true ]; then
            echo "$result_icon $result_msg" >&2
            echo "" >&2
        fi

        if [ "$actual_result" = "$expected" ]; then
            if [ "$VERBOSE" = true ]; then
                echo "✅ TEST PASSED (expected: $expected, got: $actual_result)" >&2
            else
                printf " → %s %s ✅\n" "$result_icon" "$result_msg"
            fi
        elif [ "$actual_result" = "ERROR" ]; then
            if [ "$VERBOSE" = true ]; then
                echo "⚠️  TEST INCONCLUSIVE: Unexpected error occurred" >&2
            else
                printf " → %s %s ⚠️\n" "$result_icon" "$result_msg"
            fi
        else
            if [ "$VERBOSE" = true ]; then
                echo "❌ TEST FAILED (expected: $expected, got: $actual_result)" >&2
            else
                printf " → %s %s ❌ (expected %s)\n" "$result_icon" "$result_msg" "$expected"
            fi
        fi

        if [ "$VERBOSE" = true ]; then
            echo ""
        fi
    else
        # Just print the command
        echo "near contract call-function as-transaction \\"
        echo "  $CONTRACT \\"
        echo "  request_execution \\"
        echo "  json-args '$json_args' \\"
        echo "  prepaid-gas '300.0 Tgas' \\"
        echo "  attached-deposit '0.1 NEAR' \\"
        echo "  sign-as $account \\"
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
    echo ""
    print_test_info "$test_num"

    case $test_num in
        1)
            # Test 1: AllowAll - all should succeed
            for account in "${TEST1_ALLOWED_ACCOUNTS[@]}"; do
                request_execution 1 "test1_allow_all" "$account" "SUCCESS"
            done
            ;;

        2)
            # Test 2: Whitelist
            echo ""
            echo "--- Allowed accounts (should succeed) ---"
            for account in "${TEST2_ALLOWED_ACCOUNTS[@]}"; do
                request_execution 2 "test2_whitelist" "$account" "SUCCESS"
            done

            echo ""
            echo "--- Denied accounts (should fail) ---"
            for account in "${TEST2_DENIED_ACCOUNTS[@]}"; do
                request_execution 2 "test2_whitelist" "$account" "FAIL"
            done
            ;;

        3)
            # Test 3: AccountPattern *.testnet
            echo ""
            echo "--- Allowed accounts (should succeed) ---"
            for account in "${TEST3_ALLOWED_ACCOUNTS[@]}"; do
                request_execution 3 "test3_pattern_testnet" "$account" "SUCCESS"
            done

            echo ""
            echo "--- Denied accounts (should fail) ---"
            for account in "${TEST3_DENIED_ACCOUNTS[@]}"; do
                request_execution 3 "test3_pattern_testnet" "$account" "FAIL"
            done
            ;;

        4)
            # Test 4: AccountPattern a*
            echo ""
            echo "--- Allowed accounts (should succeed) ---"
            for account in "${TEST4_ALLOWED_ACCOUNTS[@]}"; do
                request_execution 4 "test4_pattern_a" "$account" "SUCCESS"
            done

            echo ""
            echo "--- Denied accounts (should fail) ---"
            for account in "${TEST4_DENIED_ACCOUNTS[@]}"; do
                request_execution 4 "test4_pattern_a" "$account" "FAIL"
            done
            ;;

        5)
            # Test 5: AccountPattern length >= 10
            echo ""
            echo "--- Allowed accounts (should succeed) ---"
            for account in "${TEST5_ALLOWED_ACCOUNTS[@]}"; do
                request_execution 5 "test5_pattern_length" "$account" "SUCCESS"
            done

            echo ""
            echo "--- Denied accounts (should fail) ---"
            for account in "${TEST5_DENIED_ACCOUNTS[@]}"; do
                request_execution 5 "test5_pattern_length" "$account" "FAIL"
            done
            ;;

        6)
            # Test 6: NearBalance >= 5 NEAR
            echo ""
            echo "--- Allowed accounts (should succeed) ---"
            for account in "${TEST6_ALLOWED_ACCOUNTS[@]}"; do
                request_execution 6 "test6_near_balance" "$account" "SUCCESS"
            done

            echo ""
            echo "--- Denied accounts (should fail) ---"
            for account in "${TEST6_DENIED_ACCOUNTS[@]}"; do
                request_execution 6 "test6_near_balance" "$account" "FAIL"
            done
            ;;

        7)
            # Test 7: FtBalance >= 1000 tokens
            echo ""
            echo "--- Allowed accounts (should succeed) ---"
            for account in "${TEST7_ALLOWED_ACCOUNTS[@]}"; do
                request_execution 7 "test7_ft_balance" "$account" "SUCCESS"
            done

            echo ""
            echo "--- Denied accounts (should fail) ---"
            for account in "${TEST7_DENIED_ACCOUNTS[@]}"; do
                request_execution 7 "test7_ft_balance" "$account" "FAIL"
            done
            ;;

        8)
            # Test 8: NftOwned - specific token
            echo ""
            echo "--- Allowed accounts (should succeed) ---"
            for account in "${TEST8_ALLOWED_ACCOUNTS[@]}"; do
                request_execution 8 "test8_nft_token" "$account" "SUCCESS"
            done

            echo ""
            echo "--- Denied accounts (should fail) ---"
            for account in "${TEST8_DENIED_ACCOUNTS[@]}"; do
                request_execution 8 "test8_nft_token" "$account" "FAIL"
            done
            ;;

        9)
            # Test 9: NftOwned - any token
            echo ""
            echo "--- Allowed accounts (should succeed) ---"
            for account in "${TEST9_ALLOWED_ACCOUNTS[@]}"; do
                request_execution 9 "test9_nft_any" "$account" "SUCCESS"
            done

            echo ""
            echo "--- Denied accounts (should fail) ---"
            for account in "${TEST9_DENIED_ACCOUNTS[@]}"; do
                request_execution 9 "test9_nft_any" "$account" "FAIL"
            done
            ;;

        10)
            # Test 10: Logic AND - *.testnet AND >= 5 NEAR
            echo ""
            echo "--- Allowed accounts (should succeed) ---"
            for account in "${TEST10_ALLOWED_ACCOUNTS[@]}"; do
                request_execution 10 "test10_logic_and" "$account" "SUCCESS"
            done

            echo ""
            echo "--- Denied accounts (should fail) ---"
            for account in "${TEST10_DENIED_ACCOUNTS[@]}"; do
                request_execution 10 "test10_logic_and" "$account" "FAIL"
            done
            ;;

        11)
            # Test 11: Logic OR - whitelist OR *.testnet
            echo ""
            echo "--- Allowed accounts (should succeed) ---"
            for account in "${TEST11_ALLOWED_ACCOUNTS[@]}"; do
                request_execution 11 "test11_logic_or" "$account" "SUCCESS"
            done

            echo ""
            echo "--- Denied accounts (should fail) ---"
            for account in "${TEST11_DENIED_ACCOUNTS[@]}"; do
                request_execution 11 "test11_logic_or" "$account" "FAIL"
            done
            ;;

        12)
            # Test 12: Logic NOT - NOT (>= 1 NEAR)
            echo ""
            echo "--- Allowed accounts (should succeed) ---"
            for account in "${TEST12_ALLOWED_ACCOUNTS[@]}"; do
                request_execution 12 "test12_logic_not" "$account" "SUCCESS"
            done

            echo ""
            echo "--- Denied accounts (should fail) ---"
            for account in "${TEST12_DENIED_ACCOUNTS[@]}"; do
                request_execution 12 "test12_logic_not" "$account" "FAIL"
            done
            ;;

        13)
            # Test 13: Complex Logic - (whitelist OR *.testnet) AND >= 5 NEAR
            echo ""
            echo "--- Allowed accounts (should succeed) ---"
            for account in "${TEST13_ALLOWED_ACCOUNTS[@]}"; do
                request_execution 13 "test13_complex" "$account" "SUCCESS"
            done

            echo ""
            echo "--- Denied accounts (should fail) ---"
            for account in "${TEST13_DENIED_ACCOUNTS[@]}"; do
                request_execution 13 "test13_complex" "$account" "FAIL"
            done
            ;;

        14)
            # Test 14: Non-existent profile
            # We created profile "production" but will try to read "staging" (doesn't exist)
            echo ""
            echo "--- Reading non-existent profile (should fail) ---"
            request_execution 14 "$TEST14_READ_PROFILE" "$TEST14_ACCOUNT" "FAIL"
            ;;

        15)
            # Test 15: Invalid JSON format
            # We stored "foo=bar" instead of valid JSON, should fail during decryption/parsing
            echo ""
            echo "--- Reading invalid JSON data (should fail) ---"
            request_execution 15 "test15_invalid_json" "$TEST15_ACCOUNT" "FAIL"
            ;;

        *)
            echo "Unknown test number: $test_num (valid: 1-15)"
            ;;
    esac
done

if [ "$SEND_TO_CHAIN" = false ]; then
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "All test execution requests generated!"
    echo ""
    echo "Next steps:"
    echo "1. Copy and run the 'near call' commands above"
    echo "2. Or run with --send flag to execute immediately"
    echo "3. Check results: near view $CONTRACT get_request '{\"request_id\": N}'"
    echo "4. Check logs: docker logs offchainvm-worker"
    echo "5. Verify SUCCESS cases show: {\"secret_found\": true}"
    echo "6. Verify FAIL cases show: {\"secret_found\": false}"
    echo "═══════════════════════════════════════════════════════════════"
else
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "All tests completed!"
    echo "Review the results above (✅ = passed, ❌ = failed)"
    echo "═══════════════════════════════════════════════════════════════"
fi
