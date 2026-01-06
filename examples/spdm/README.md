# SPDM Authenticated Controller (AC) Examples

This directory contains examples demonstrating SPDM (Security Protocol and Data Model) Authenticated Controller (AC) functionality as specified in TCG TPM 2.0 Library Specification v1.84 (March 2025).

## Overview

The SPDM examples demonstrate how to use wolfTPM to interact with TPM Authenticated Controllers, which enable secure communication channels between the host and peripheral devices (NICs, GPUs, etc.) using the SPDM protocol.

**Important Notes:**
- **TCG TPM Simulator AC Command Status:**
  - AC commands (`AC_GetCapability`, `AC_Send`) are **disabled by default** in TCG simulator (`CC_AC_GetCapability = CC_NO`, `CC_AC_Send = CC_NO`)
  - Enabling them requires modifying `TpmProfile_CommandList.h` and rebuilding the simulator
  - Even when enabled, the simulator provides **stub implementations** for testing command interface only
  - The simulator requires **startup commands** on platform interface (port 2322) before command interface works
- **swtpm does NOT support AC commands** - it will return `TPM_RC_COMMAND_CODE` for AC commands
- **For real SPDM support on hardware TPMs**, contact **support@wolfssl.com**
- These examples focus on **transport layer validation** (command formatting) rather than full SPDM protocol implementation

## Examples

### 1. `tcg_spdm.c` - TCG Simulator AC/SPDM Transport Validation

**Purpose:** Validates that wolfTPM correctly formats TCG AC commands for the TPM simulator. This example tests transport layer correctness, not SPDM protocol logic.

**What it tests:**
- AC handle discovery
- Transport layer support checking
- AC_GetCapability command formatting
- AC_Send command formatting

**Command-line Options:**

```bash
./tcg_spdm --help                 # Show help message
./tcg_spdm --all                  # Run all transport validation tests
./tcg_spdm --discover-handles     # Discover all AC handles on TPM
./tcg_spdm --check-transport      # Check if transport supports AC commands
./tcg_spdm --test-getcapability <handle>  # Test AC_GetCapability with handle (hex)
./tcg_spdm --test-acsend <handle>         # Test AC_Send with handle (hex)
```

**Example Usage:**

```bash
# Discover AC handles
./tcg_spdm --discover-handles

# Test with a discovered handle
./tcg_spdm --test-getcapability 0x40000110

# Run all tests
./tcg_spdm --all
```

**What Works:**
- ✅ AC handle discovery (returns handles from TCG simulator)
- ✅ Transport layer validation (commands are correctly formatted)
- ✅ Error handling (TPM_RC_HANDLE, TPM_RC_VALUE, etc.)
- ✅ Command marshalling/unmarshalling

**What Doesn't Work / Limitations:**
- ⚠️ **TCG Simulator AC commands disabled by default** - returns `TPM_RC_COMMAND_CODE` unless enabled in build
- ⚠️ **TCG Simulator doesn't implement SPDM protocol logic** - even when enabled, provides stub implementations
- ⚠️ **AC_Send returns dummy data** - `AcSendObject()` always returns `{TPM_AT_ERROR, TPM_AE_NONE}` (simulator limitation)
- ⚠️ **AC handle discovery may return permanent handles** - simulator AC handle `0x40000001` overlaps with permanent handle range
- ⚠️ **Requires startup commands** - TCG simulator needs power-up/startup on port 2322 before port 2321 works

**Why:**
- TCG Simulator validates command structure but doesn't process SPDM messages
- This is expected behavior - the simulator validates transport, not protocol
- For full SPDM functionality, you need hardware TPM with v1.84 firmware

### 2. `spdm_ac_demo` - SPDM AC Demo

**Purpose:** Demonstrates complete AC functionality including handle discovery, capability query, SPDM message tunneling, and secure channel establishment. Would be used to validate with working hardware impllantion of the SPDM protocol.

**Command-line Options:**

```bash
./spdm_ac_demo --help                           # Show help message
./spdm_ac_demo --check-transport                 # Check if transport supports AC commands
./spdm_ac_demo --discover-handles               # Discover all AC handles on TPM
./spdm_ac_demo --query-capabilities <handle>    # Query capabilities of AC handle (hex)
./spdm_ac_demo --spdm-tunnel <handle> <file>    # Send SPDM message from file through AC
./spdm_ac_demo --establish-channel <handle>      # Establish secure channel with AC (demo)
```

**Example Usage:**

```bash
# Check transport support
./spdm_ac_demo --check-transport

# Discover handles
./spdm_ac_demo --discover-handles

# Query capabilities of a handle
./spdm_ac_demo --query-capabilities 0x40000110

# Send SPDM message through AC tunnel
./spdm_ac_demo --spdm-tunnel 0x40000110 spdm_request.bin

# Establish secure channel (requires shared secret from SPDM KEY_EXCHANGE)
./spdm_ac_demo --establish-channel 0x40000110
```

**What Works:**
- ✅ AC handle discovery
- ✅ Capability query (returns AC capabilities and type)
- ✅ Transport support checking
- ✅ SPDM message tunneling (sends messages through AC)
- ✅ Secure channel establishment (with proper shared secret)

**What Doesn't Work / Limitations:**
- ⚠️ **Secure channel establishment requires real SPDM KEY_EXCHANGE** - demo uses placeholder values
- ⚠️ **SPDM responses are empty with TCG Simulator** - simulator doesn't process SPDM
- ⚠️ **Only works with TCG TPM Simulator** - swtpm doesn't support AC commands
- ⚠️ **Full SPDM handshake not implemented** - requires libspdm integration

**Why:**
- Secure channel needs real shared secret from SPDM KEY_EXCHANGE phase
- TCG Simulator accepts commands but doesn't process SPDM protocol
- For production use, integrate with libspdm for complete SPDM handshake

## TCG Simulator Setup

### Enabling AC Commands in TCG Simulator

The TCG TPM reference simulator has AC commands **disabled by default**. To enable them for testing:

1. **Edit the command profile:**
   ```bash
   # In tcg-tpm-reference/TPMCmd/TpmConfiguration/TpmConfiguration/TpmProfile_CommandList.h
   # Change:
   #define CC_AC_GetCapability           CC_NO
   #define CC_AC_Send                    CC_NO
   # To:
   #define CC_AC_GetCapability           CC_YES
   #define CC_AC_Send                    CC_YES
   ```

2. **Rebuild the simulator:**
   ```bash
   cd tcg-tpm-reference/TPMCmd/build
   make clean
   make
   ```

3. **Note:** Enabling AC commands requires regenerating command dispatch structures, which may require additional build steps.

### Startup Commands

The TCG TPM simulator requires **power-up and startup commands** on the platform interface (port 2322) before the command interface (port 2321) is enabled:

```bash
# Power up command
echo -ne "\x00\x00\x00\x01" | nc 127.0.0.1 2322

# Startup command  
echo -ne "\x00\x00\x00\x0B" | nc 127.0.0.1 2322
```

The test script `test_tcg_spdm.sh` automatically sends these commands if the simulator is detected.

### What Actually Works in TCG Simulator

Based on analysis of the TCG simulator source code:

**✅ Fully Implemented:**
- `AC_GetCapability` - Returns AC capabilities from hardcoded data (`acData0001`)
- Command marshalling/unmarshalling - All structures are correctly defined
- Handle validation - AC handle type checking works

**⚠️ Stub Implementation:**
- `AC_Send` - `AcSendObject()` always returns `{TPM_AT_ERROR, TPM_AE_NONE}` (dummy data)
- No actual SPDM message processing - commands are accepted but not processed

**❌ Not Implemented:**
- `Policy_AC_SendSelect` - Command exists but not implemented
- `PolicyTransportSPDM` - Command exists but not implemented  
- `TPM_CAP_SPDM_SESSION_INFO` - Capability not implemented

**Key Finding:** The simulator code comments state: *"This code in this clause is provided for testing of the TPM's command interface. The implementation of Attached Components is not expected to be as shown in this code."*

This confirms the simulator is designed for **command interface testing**, not full SPDM protocol implementation.

## Test Scripts

### `test_tcg_spdm.sh` - Test Script for tcg_spdm

Comprehensive test script that exercises all command-line options for `tcg_spdm`.

**Usage:**

```bash
./test_tcg_spdm.sh [OPTIONS]

Options:
  --all                  Run all tests (default)
  --basic                Run only basic tests (help, discover, transport check)
  --transport            Run only transport validation tests
  --help, -h             Show help message
```

**Example:**

```bash
# Run all tests
./test_tcg_spdm.sh --all

# Run only basic tests
./test_tcg_spdm.sh --basic

# Run only transport tests
./test_tcg_spdm.sh --transport
```

### `test_spdm_ac_demo.sh` - Test Script for spdm_ac_demo

Comprehensive test script that exercises all command-line options for `spdm_ac_demo`.

**Usage:**

```bash
./test_spdm_ac_demo.sh [OPTIONS]

Options:
  --all                  Run all tests (default)
  --basic                Run only basic tests (help, discover, transport check)
  --capabilities         Run only capability query tests
  --tunnel               Run only SPDM tunnel tests (requires SPDM_FILE)
  --channel              Run only secure channel tests
  --help, -h             Show help message

Environment variables:
  SPDM_FILE              Path to SPDM request file (for --spdm-tunnel test)
```

**Example:**

```bash
# Run all tests
./test_spdm_ac_demo.sh --all

# Run tunnel test with SPDM file
SPDM_FILE=/path/to/spdm_request.bin ./test_spdm_ac_demo.sh --tunnel

# Run only capability tests
./test_spdm_ac_demo.sh --capabilities
```

## Building and Running

### Prerequisites

1. **Build wolfTPM with SPDM support:**
   ```bash
   ./configure --enable-spdm
   make -j$(nproc)
   ```

2. **For TCG Simulator testing:**
   - TCG TPM Simulator must be running
   - Configure with: `./configure --enable-spdm --enable-swtpm` (for swtpm transport, but note swtpm doesn't support AC commands)

## TPM Simulator Support

### TCG TPM Simulator

**Status:** ✅ **Fully Supported** - This is the **only usable simulator** for testing AC commands

**What works:**
- AC handle discovery
- AC_GetCapability
- AC_Send (command accepted, but responses are empty - simulator limitation)
- Transport layer validation

**Limitations:**
- Simulator doesn't implement SPDM protocol logic
- AC_Send returns empty responses
- Secure channel establishment works but uses placeholder values

**How to use:**
1. Start TCG TPM Simulator
2. Configure wolfTPM: `./configure --enable-spdm`
3. Run examples as documented above

### Getting Real SPDM Support

**For production use with hardware TPMs and full SPDM protocol support, contact:**

📧 **support@wolfssl.com**
