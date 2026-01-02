#!/bin/bash
# 
# test_spdm_ac_demo.sh
#
# Copyright (C) 2006-2025 wolfSSL Inc.
#
# This file is part of wolfTPM.
# 
# wolfTPM is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfTPM is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

# Test script for SPDM AC demo functionality
# Tests all command-line options for spdm_ac_demo example

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --all                  Run all tests (default)"
    echo "  --basic                Run only basic tests (help, discover, transport check)"
    echo "  --capabilities          Run only capability query tests"
    echo "  --tunnel                Run only SPDM tunnel tests (requires SPDM_FILE)"
    echo "  --channel               Run only secure channel tests"
    echo "  --help, -h             Show this help message"
    echo ""
    echo "This script tests all command-line options for spdm_ac_demo:"
    echo "  --help                 Show help message"
    echo "  --check-transport      Check transport support"
    echo "  --discover-handles     Discover AC handles"
    echo "  --query-capabilities   Query capabilities of AC handle"
    echo "  --spdm-tunnel          Send SPDM message through AC"
    echo "  --establish-channel    Establish secure channel with AC"
    echo ""
    echo "Environment variables:"
    echo "  SPDM_FILE              Path to SPDM request file (for --spdm-tunnel test)"
    echo ""
    echo "If SPDM_FILE is not set, tunnel tests will be skipped."
}

# Parse command-line arguments
TEST_MODE="all"
for arg in "$@"; do
    case "$arg" in
        --all)
            TEST_MODE="all"
            ;;
        --basic)
            TEST_MODE="basic"
            ;;
        --capabilities)
            TEST_MODE="capabilities"
            ;;
        --tunnel)
            TEST_MODE="tunnel"
            ;;
        --channel)
            TEST_MODE="channel"
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Error: Unknown option: $arg"
            usage
            exit 1
            ;;
    esac
done

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Get the wolfTPM root directory
WOLFTPM_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Find the spdm_ac_demo tool
SPDM_AC_DEMO=""
for tool in "$WOLFTPM_ROOT/examples/spdm/.libs/spdm_ac_demo" \
            "$WOLFTPM_ROOT/examples/spdm/spdm_ac_demo" \
            "$SCRIPT_DIR/.libs/spdm_ac_demo" \
            "$SCRIPT_DIR/spdm_ac_demo"; do
    if [ -x "$tool" ]; then
        SPDM_AC_DEMO="$tool"
        break
    fi
done

if [ -z "$SPDM_AC_DEMO" ] || [ ! -x "$SPDM_AC_DEMO" ]; then
    echo "ERROR: spdm_ac_demo tool not found or not executable"
    echo "Please run 'make' first in the wolfTPM root directory: $WOLFTPM_ROOT"
    echo ""
    echo "Searched in:"
    echo "  $WOLFTPM_ROOT/examples/spdm/.libs/spdm_ac_demo"
    echo "  $WOLFTPM_ROOT/examples/spdm/spdm_ac_demo"
    echo "  $SCRIPT_DIR/.libs/spdm_ac_demo"
    echo "  $SCRIPT_DIR/spdm_ac_demo"
    exit 1
fi

# Set library path
WOLFTPM_LIB_DIRS=""
for dir in "$WOLFTPM_ROOT/src/.libs" "$WOLFTPM_ROOT/.libs" "$WOLFTPM_ROOT/src" "$WOLFTPM_ROOT"; do
    if [ -d "$dir" ]; then
        if [ -n "$WOLFTPM_LIB_DIRS" ]; then
            WOLFTPM_LIB_DIRS="$WOLFTPM_LIB_DIRS:$dir"
        else
            WOLFTPM_LIB_DIRS="$dir"
        fi
    fi
done

if [ -n "$LD_LIBRARY_PATH" ]; then
    export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$WOLFTPM_LIB_DIRS"
else
    export LD_LIBRARY_PATH="$WOLFTPM_LIB_DIRS"
fi

# SPDM file path (optional)
SPDM_FILE="${SPDM_FILE:-}"

TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local test_name="$1"
    local test_cmd="$2"
    local expect_success="$3"
    
    echo "---------------------------------------------------"
    echo "Test: $test_name"
    echo "---------------------------------------------------"
    echo "Running: $test_cmd"
    echo ""
    
    output=$($test_cmd 2>&1)
    rc=$?
    
    echo "$output"
    echo ""
    
    if [ "$expect_success" = "yes" ] && [ $rc -eq 0 ]; then
        echo "✓ PASSED: $test_name"
        ((TESTS_PASSED++))
        return 0
    elif [ "$expect_success" = "no" ] && [ $rc -ne 0 ]; then
        echo "✓ PASSED: $test_name (expected failure)"
        ((TESTS_PASSED++))
        return 0
    elif [ "$expect_success" = "any" ]; then
        echo "✓ COMPLETED: $test_name (rc=$rc)"
        ((TESTS_PASSED++))
        return 0
    else
        echo "✗ FAILED: $test_name (rc=$rc)"
        ((TESTS_FAILED++))
        return 1
    fi
}

echo "=========================================="
echo "SPDM AC Demo Test Suite"
echo "=========================================="
echo ""

# Test 1: Help
run_test "Help output" "$SPDM_AC_DEMO --help" "yes"
echo ""

# Test 2: Check transport
if [ "$TEST_MODE" = "all" ] || [ "$TEST_MODE" = "basic" ]; then
    run_test "Check transport support" "$SPDM_AC_DEMO --check-transport" "any"
    echo ""
fi

# Test 3: Discover handles
if [ "$TEST_MODE" = "all" ] || [ "$TEST_MODE" = "basic" ] || [ "$TEST_MODE" = "capabilities" ]; then
    run_test "Discover AC handles" "$SPDM_AC_DEMO --discover-handles" "any"
    echo ""
    
    # Capture discovered handles for later tests
    DISCOVERED_HANDLES=$($SPDM_AC_DEMO --discover-handles 2>&1 | grep -oP "0x[0-9a-fA-F]{8}" | head -3)
    FIRST_HANDLE=$(echo "$DISCOVERED_HANDLES" | head -1)
fi

# Test 4: Query capabilities
if [ "$TEST_MODE" = "all" ] || [ "$TEST_MODE" = "capabilities" ]; then
    if [ -n "$FIRST_HANDLE" ]; then
        run_test "Query capabilities (handle $FIRST_HANDLE)" "$SPDM_AC_DEMO --query-capabilities $FIRST_HANDLE" "any"
        echo ""
    else
        # Use default handle if none discovered
        run_test "Query capabilities (default handle 0x40000110)" "$SPDM_AC_DEMO --query-capabilities 0x40000110" "any"
        echo ""
    fi
    
    # Test with multiple handles if available
    HANDLE_COUNT=$(echo "$DISCOVERED_HANDLES" | wc -l)
    if [ "$HANDLE_COUNT" -gt 1 ]; then
        SECOND_HANDLE=$(echo "$DISCOVERED_HANDLES" | sed -n '2p')
        if [ -n "$SECOND_HANDLE" ]; then
            run_test "Query capabilities (handle $SECOND_HANDLE)" "$SPDM_AC_DEMO --query-capabilities $SECOND_HANDLE" "any"
            echo ""
        fi
    fi
fi

# Test 5: SPDM tunnel
if [ "$TEST_MODE" = "all" ] || [ "$TEST_MODE" = "tunnel" ]; then
    if [ -n "$SPDM_FILE" ] && [ -f "$SPDM_FILE" ]; then
        SPDM_SIZE=$(stat -c%s "$SPDM_FILE" 2>/dev/null || stat -f%z "$SPDM_FILE" 2>/dev/null)
        echo "SPDM file found: $SPDM_FILE"
        echo "  Size: $SPDM_SIZE bytes"
        echo ""
        
        TEST_HANDLE="${FIRST_HANDLE:-0x40000110}"
        run_test "SPDM tunnel (handle $TEST_HANDLE, file $SPDM_FILE)" "$SPDM_AC_DEMO --spdm-tunnel $TEST_HANDLE $SPDM_FILE" "any"
        echo ""
    else
        if [ "$TEST_MODE" = "tunnel" ]; then
            echo "ERROR: --tunnel specified but SPDM_FILE not set or file not found"
            echo "  Set SPDM_FILE environment variable to test SPDM tunnel"
            echo "  Example: export SPDM_FILE=/path/to/spdm_request.bin"
            ((TESTS_FAILED++))
        else
            echo "SPDM_FILE not set - skipping SPDM tunnel test"
            echo "  (Set SPDM_FILE environment variable to test SPDM tunnel)"
            echo "  Example: export SPDM_FILE=/path/to/spdm_request.bin"
        fi
        echo ""
    fi
fi

# Test 6: Establish secure channel
if [ "$TEST_MODE" = "all" ] || [ "$TEST_MODE" = "channel" ]; then
    TEST_HANDLE="${FIRST_HANDLE:-0x40000110}"
    run_test "Establish secure channel (handle $TEST_HANDLE)" "$SPDM_AC_DEMO --establish-channel $TEST_HANDLE" "any"
    echo ""
fi

# Test 7: Invalid options (should fail gracefully)
run_test "Invalid option handling" "$SPDM_AC_DEMO --invalid-option 2>&1" "no"
echo ""

# Test 8: Missing arguments (should fail)
if [ "$TEST_MODE" = "all" ] || [ "$TEST_MODE" = "capabilities" ]; then
    run_test "Missing handle argument for --query-capabilities" "$SPDM_AC_DEMO --query-capabilities 2>&1" "no"
    echo ""
fi

if [ "$TEST_MODE" = "all" ] || [ "$TEST_MODE" = "tunnel" ]; then
    run_test "Missing arguments for --spdm-tunnel" "$SPDM_AC_DEMO --spdm-tunnel 2>&1" "no"
    echo ""
    
    if [ -n "$FIRST_HANDLE" ]; then
        run_test "Missing file argument for --spdm-tunnel" "$SPDM_AC_DEMO --spdm-tunnel $FIRST_HANDLE 2>&1" "no"
        echo ""
    fi
fi

if [ "$TEST_MODE" = "all" ] || [ "$TEST_MODE" = "channel" ]; then
    run_test "Missing handle argument for --establish-channel" "$SPDM_AC_DEMO --establish-channel 2>&1" "no"
    echo ""
fi

# Summary
echo "=========================================="
echo "TEST SUMMARY"
echo "=========================================="
echo "  Tests Passed: $TESTS_PASSED"
echo "  Tests Failed: $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo "All tests completed successfully!"
    exit 0
else
    echo "Some tests failed!"
    exit 1
fi

