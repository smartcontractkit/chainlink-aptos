#!/bin/bash

# Setup test environment
setup_test_env() {
    export GITHUB_ENV=$(mktemp)
    export GITHUB_OUTPUT=$(mktemp)
}

# Cleanup test files
cleanup() {
    rm -f "$GITHUB_ENV" "$GITHUB_OUTPUT" HACKED* 2>/dev/null
}

# Run test and check results
run_test() {
    local test_name="$1"
    local pr_body="$2"
    local expected="$3"

    echo "Test: $test_name"
    echo "Input: $pr_body"
    
    setup_test_env
    export PR_BODY="$pr_body"
    
    ./get_core_ref.sh
    
    local actual=$(grep "core_ref=" "$GITHUB_ENV" | cut -d= -f2)
    if [[ "$actual" == "$expected" ]]; then
        echo "✅ Passed: got expected value '$expected'"
    else 
        echo "❌ Failed: expected '$expected', got '$actual'"
    fi
    echo
}

# Main test execution
trap cleanup EXIT

# Normal cases
run_test "Simple valid ref" \
         "core_ref: develop" \
         "develop"

run_test "Complex valid ref" \
         "core_ref: feature/abc-123_test" \
         "feature/abc-123_test"

run_test "Multiple colons" \
         "core_ref: abc:def:ghi" \
         "develop-plugins"

# Git SHA test cases
run_test "Full git SHA" \
         "core_ref: 1234567890abcdef1234567890abcdef12345678" \
         "1234567890abcdef1234567890abcdef12345678"

run_test "Short git SHA" \
         "core_ref: 1234567" \
         "1234567"

# Security test cases
run_test "Command injection via backticks" \
         "core_ref: \`touch HACKED1\`" \
         "develop-plugins"

run_test "Command injection via semicolon" \
         "core_ref: valid-ref; touch HACKED2" \
         "develop-plugins"

run_test "Command injection via pipeline" \
         "core_ref: valid-ref | touch HACKED3" \
         "develop-plugins"

run_test "Command injection via subshell" \
         "core_ref: \$(touch HACKED4)" \
         "develop-plugins"

run_test "SQL injection attempt" \
         "core_ref: ' DROP TABLE users--" \
         "develop-plugins"

run_test "Path traversal attempt" \
         "core_ref: ../../../etc/passwd" \
         "develop-plugins"

# Format test cases
run_test "Empty value" \
         "core_ref:" \
         "develop-plugins"

run_test "Missing value" \
         "some other text" \
         "develop-plugins"

run_test "Extra whitespace" \
         "   core_ref:    spaces-everywhere   " \
         "spaces-everywhere"

# Final security check
if ls HACKED* 1>/dev/null 2>&1; then
    echo "❌ CRITICAL: Command injection was successful!"
    exit 1
else 
    echo "✅ All security checks passed"
fi
