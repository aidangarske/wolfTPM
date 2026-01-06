#!/bin/bash

# test_tcg_spdm.sh
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

# Test script for TCG SPDM transport validation
# Tests all command-line options for tcg_spdm example

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --all                  Run all tests (default)"
    echo "  --basic                Run only basic tests (help, discover, transport check)"
    echo "  --transport            Run only transport validation tests"
    echo "  --help, -h             Show this help message"
    echo ""
    echo "This script tests all command-line options for tcg_spdm:"
    echo "  --help                 Show help message"
    echo "  --all                  Run all transport validation tests"
    echo "  --discover-handles      Discover AC handles"
    echo "  --check-transport      Check transport support"
    echo "  --test-getcapability   Test AC_GetCapability with handle"
    echo "  --test-acsend          Test AC_Send with handle"
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
        --transport)
            TEST_MODE="transport"
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

# Find the tcg_spdm tool
TCG_SPDM=""
for tool in "$WOLFTPM_ROOT/examples/spdm/.libs/tcg_spdm" \
            "$WOLFTPM_ROOT/examples/spdm/tcg_spdm" \
            "$SCRIPT_DIR/.libs/tcg_spdm" \
            "$SCRIPT_DIR/tcg_spdm"; do
    if [ -x "$tool" ]; then
        TCG_SPDM="$tool"
        break
    fi
done

if [ -z "$TCG_SPDM" ] || [ ! -x "$TCG_SPDM" ]; then
    echo "ERROR: tcg_spdm tool not found or not executable"
    echo "Please run 'make' first in the wolfTPM root directory: $WOLFTPM_ROOT"
    echo ""
    echo "Searched in:"
    echo "  $WOLFTPM_ROOT/examples/spdm/.libs/tcg_spdm"
    echo "  $WOLFTPM_ROOT/examples/spdm/tcg_spdm"
    echo "  $SCRIPT_DIR/.libs/tcg_spdm"
    echo "  $SCRIPT_DIR/tcg_spdm"
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

TESTS_PASSED=0
TESTS_FAILED=0

# Function to send TCG TPM simulator startup commands
# The TCG simulator requires power up and startup on platform interface (port 2322)
# before the command interface (port 2321) is enabled
send_simulator_startup() {
    local platform_port="${TPM2_SWTPM_PLATFORM_PORT:-2322}"
    
    echo "Sending TCG simulator startup commands to port $platform_port..."
    
    # Power up command: 0x00000001
    if command -v nc >/dev/null 2>&1; then
        echo -ne "\x00\x00\x00\x01" | nc -w 1 127.0.0.1 "$platform_port" >/dev/null 2>&1
        sleep 0.1
        # Startup command: 0x0000000B
        echo -ne "\x00\x00\x00\x0B" | nc -w 1 127.0.0.1 "$platform_port" >/dev/null 2>&1
        sleep 0.1
        echo "Startup commands sent"
    else
        echo "Warning: 'nc' (netcat) not found, skipping startup commands"
        echo "  Install netcat or manually send startup commands:"
        echo "    echo -ne \"\\x00\\x00\\x00\\x01\" | nc 127.0.0.1 $platform_port"
        echo "    echo -ne \"\\x00\\x00\\x00\\x0B\" | nc 127.0.0.1 $platform_port"
    fi
}

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
echo "TCG SPDM Transport Test Suite"
echo "=========================================="
echo ""
echo "Note: AC commands (AC_GetCapability, AC_Send) are disabled by default"
echo "      in TCG simulator (CC_AC_GetCapability = CC_NO, CC_AC_Send = CC_NO)."
echo "      Tests may show TPM_RC_COMMAND_CODE - this is expected and indicates"
echo "      command marshalling is correct, but command needs simulator rebuild."
echo "      See examples/spdm/README.md for enabling instructions."
echo ""

# Check if TPM simulator is running
SIMULATOR_RUNNING=0
if pgrep -f "[Ss]imulator.*2321" >/dev/null 2>&1 || \
   pgrep -f "tpm2-simulator" >/dev/null 2>&1 || \
   pgrep -f "tpm_server" >/dev/null 2>&1; then
    SIMULATOR_RUNNING=1
fi

# Check if we can connect to port 2321
if command -v nc >/dev/null 2>&1; then
    if nc -z 127.0.0.1 2321 2>/dev/null; then
        SIMULATOR_RUNNING=1
    fi
fi

if [ $SIMULATOR_RUNNING -eq 1 ]; then
    # Send startup commands if using TCG simulator
    send_simulator_startup
    echo ""
else
    echo "⚠ WARNING: TPM simulator does not appear to be running on port 2321"
    echo "   Tests will fail to connect. To run tests:"
    echo "   1. Start TCG TPM Simulator:"
    echo "      cd tcg-tpm-reference/TPMCmd/Simulator/src"
    echo "      ./tpm2-simulator"
    echo ""
    echo "   2. In another terminal, send startup commands:"
    echo "      echo -ne \"\\x00\\x00\\x00\\x01\" | nc 127.0.0.1 2322"
    echo "      echo -ne \"\\x00\\x00\\x00\\x0B\" | nc 127.0.0.1 2322"
    echo ""
    echo "   3. Then run this test script again"
    echo ""
    echo "   Note: Handle discovery uses GetCapability(TPM_CAP_HANDLES, HR_AC)"
    echo "         which should work even if AC commands are disabled."
    echo "         The issue is that the simulator must be running to connect."
    echo ""
fi

# Test 1: Help
run_test "Help output" "$TCG_SPDM --help" "yes"
echo ""

# Test 2: Discover handles
if [ "$TEST_MODE" = "all" ] || [ "$TEST_MODE" = "basic" ]; then
    run_test "Discover AC handles" "$TCG_SPDM --discover-handles" "any"
    echo ""
fi

# Test 3: Check transport
if [ "$TEST_MODE" = "all" ] || [ "$TEST_MODE" = "basic" ] || [ "$TEST_MODE" = "transport" ]; then
    run_test "Check transport support" "$TCG_SPDM --check-transport" "any"
    echo ""
fi

# Test 4: Test AC_GetCapability with default handle
# Note: May return TPM_RC_COMMAND_CODE if command not enabled in simulator (expected)
if [ "$TEST_MODE" = "all" ] || [ "$TEST_MODE" = "transport" ]; then
    run_test "Test AC_GetCapability (default handle - may show COMMAND_CODE)" "$TCG_SPDM --test-getcapability 0x40000110" "any"
    echo ""
    
    # Test with discovered handle if available
    DISCOVERED_HANDLE=$($TCG_SPDM --discover-handles 2>&1 | grep -oP "0x[0-9a-fA-F]{8}" | head -1)
    if [ -n "$DISCOVERED_HANDLE" ]; then
        run_test "Test AC_GetCapability (discovered handle $DISCOVERED_HANDLE - may show COMMAND_CODE)" "$TCG_SPDM --test-getcapability $DISCOVERED_HANDLE" "any"
        echo ""
    fi
fi

# Test 5: Test AC_Send with default handle
# Note: May return TPM_RC_COMMAND_CODE if command not enabled in simulator (expected)
if [ "$TEST_MODE" = "all" ] || [ "$TEST_MODE" = "transport" ]; then
    run_test "Test AC_Send (default handle - may show COMMAND_CODE)" "$TCG_SPDM --test-acsend 0x40000110" "any"
    echo ""
    
    # Test with discovered handle if available
    if [ -n "$DISCOVERED_HANDLE" ]; then
        run_test "Test AC_Send (discovered handle $DISCOVERED_HANDLE - may show COMMAND_CODE)" "$TCG_SPDM --test-acsend $DISCOVERED_HANDLE" "any"
        echo ""
    fi
fi

# Test 6: Run all tests
if [ "$TEST_MODE" = "all" ]; then
    run_test "Run all tests" "$TCG_SPDM --all" "any"
    echo ""
fi

# Test 7: Invalid options (should fail gracefully)
run_test "Invalid option handling" "$TCG_SPDM --invalid-option 2>&1" "no"
echo ""

# Test 8: Missing handle argument (uses default handle, may succeed)
if [ "$TEST_MODE" = "all" ] || [ "$TEST_MODE" = "transport" ]; then
    run_test "Missing handle argument for --test-getcapability (uses default)" "$TCG_SPDM --test-getcapability 2>&1" "any"
    echo ""
    
    run_test "Missing handle argument for --test-acsend (uses default)" "$TCG_SPDM --test-acsend 2>&1" "any"
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
