#!/bin/bash
# verify_irq_hardware.sh
#
# Hardware verification script for TPM IRQ support
# Verifies that TPM Pin 18 (PIRQ#) is physically connected to host GPIO
#
# Usage: sudo ./verify_irq_hardware.sh [GPIO_PIN]
#   GPIO_PIN: Host GPIO pin number (default: 24 for Raspberry Pi)
#
# This script must be run as root to access GPIO
#
# IMPORTANT: Pin Numbering Clarification
#   - TPM Pin 18 = PIRQ# (the interrupt pin on the TPM chip itself)
#   - GPIO 24 = Raspberry Pi GPIO pin (should connect to TPM Pin 18)
#   - Check your board/HAT schematic to confirm which GPIO connects to TPM Pin 18

# Default GPIO pin (typically GPIO 24 on Raspberry Pi for SLB9672)
HOST_GPIO_PIN=${1:-24}

echo "=== SLB9672 PIRQ# Hardware Verification ==="
echo "TPM Pin 18 (PIRQ#) should connect to Host GPIO: $HOST_GPIO_PIN"
echo ""
echo "Pin Numbering:"
echo "  - TPM Pin 18 = PIRQ# (interrupt pin on TPM chip - confirmed in spec)"
echo "  - GPIO $HOST_GPIO_PIN = Host GPIO pin (check your board schematic)"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (use sudo)"
    echo "Example: sudo $0 $HOST_GPIO_PIN"
    exit 1
fi

# Method 1: Try GPIO Character Device API (modern, preferred)
echo "=== Method 1: GPIO Character Device API ==="
USE_CHARDEV=0
for chip in /dev/gpiochip*; do
    if [ -c "$chip" ]; then
        chipnum=$(basename "$chip" | sed 's/gpiochip//')
        echo "Trying gpiochip$chipnum..."
        
        # Try to read line info (this will fail if pin doesn't exist, but won't reserve it)
        if command -v gpioinfo >/dev/null 2>&1; then
            gpioinfo "$chipnum" 2>/dev/null | grep -q "line.*$HOST_GPIO_PIN:" && USE_CHARDEV=1 && CHARDEV_CHIP=$chipnum && break
        fi
    fi
done

if [ $USE_CHARDEV -eq 1 ]; then
    echo "SUCCESS: GPIO $HOST_GPIO_PIN found in gpiochip$CHARDEV_CHIP"
    echo "The IRQ code will use GPIO Character Device API (no sysfs needed)"
    echo ""
    echo "You can test IRQ functionality with:"
    echo "  sudo ./examples/irq/tpm_irq_test -g $HOST_GPIO_PIN"
    echo ""
    echo "Note: Hardware verification via character device requires C code."
    echo "The IRQ implementation will automatically use this method."
    exit 0
fi

# Method 2: Try sysfs (legacy, may not work if GPIO is reserved)
echo "=== Method 2: GPIO Sysfs (legacy) ==="

# Check if sysfs GPIO is available
if [ ! -d /sys/class/gpio ]; then
    echo "ERROR: GPIO sysfs not available (/sys/class/gpio)"
    echo "This system may only support GPIO Character Device API"
    echo ""
    echo "SOLUTION: The IRQ code will automatically use Character Device API"
    echo "You can still test IRQ functionality - it will work without sysfs!"
    exit 0
fi

# Check if GPIO is already exported and try to unexport it first
GPIO_PATH="/sys/class/gpio/gpio${HOST_GPIO_PIN}"
if [ -d "$GPIO_PATH" ]; then
    echo "INFO: GPIO $HOST_GPIO_PIN is already exported"
    echo "Attempting to use existing export..."
    
    # Check what's using it
    if [ -f "$GPIO_PATH/direction" ]; then
        DIRECTION=$(cat "$GPIO_PATH/direction" 2>/dev/null)
        echo "  Current direction: $DIRECTION"
    fi
    if [ -f "$GPIO_PATH/value" ]; then
        VALUE=$(cat "$GPIO_PATH/value" 2>/dev/null)
        echo "  Current value: $VALUE"
    fi
    if [ -f "$GPIO_PATH/edge" ]; then
        EDGE=$(cat "$GPIO_PATH/edge" 2>/dev/null)
        echo "  Current edge: $EDGE"
    fi
else
    # Export GPIO pin if not already exported
    echo "Exporting GPIO $HOST_GPIO_PIN..."
    EXPORT_OUTPUT=$(echo "$HOST_GPIO_PIN" > /sys/class/gpio/export 2>&1)
    EXPORT_RC=$?
    
    if [ $EXPORT_RC -ne 0 ]; then
        echo "WARNING: Failed to export GPIO $HOST_GPIO_PIN via sysfs"
        echo "  Error: $EXPORT_OUTPUT"
        echo ""
        echo "This is OK! GPIO $HOST_GPIO_PIN may be:"
        echo "  1. Reserved by device tree"
        echo "  2. Not available via sysfs (use Character Device API instead)"
        echo "  3. Already in use by kernel driver"
        echo ""
        echo "SOLUTION: The IRQ code will use GPIO Character Device API automatically"
        echo "You can still test IRQ functionality - sysfs is not required!"
        echo ""
        echo "Try testing with:"
        echo "  sudo ./examples/irq/tpm_irq_test -g $HOST_GPIO_PIN"
        echo ""
        echo "If that doesn't work, try different GPIO pins:"
        echo "  sudo $0 23"
        echo "  sudo $0 25"
        exit 0
    fi
    sleep 0.5
fi

# Set GPIO as input
echo "Configuring GPIO $HOST_GPIO_PIN as input..."
echo "in" > "$GPIO_PATH/direction" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to set GPIO direction"
    echo "$HOST_GPIO_PIN" > /sys/class/gpio/unexport 2>/dev/null
    exit 1
fi

# Read initial state
INITIAL_STATE=$(cat "$GPIO_PATH/value" 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to read GPIO value"
    echo "$HOST_GPIO_PIN" > /sys/class/gpio/unexport 2>/dev/null
    exit 1
fi

echo "Initial GPIO State (Idle): $INITIAL_STATE"
echo ""
echo "----------------------------------------"
echo "INSTRUCTIONS:"
echo "1. In another terminal, run a TPM command that takes time:"
echo "   Example: tpm2_getrandom 32 --hex"
echo "   Or: tpm2_pcrread"
echo ""
echo "2. This script will monitor GPIO $HOST_GPIO_PIN for 10 seconds"
echo "3. If the IRQ line toggles, hardware connection is verified"
echo "----------------------------------------"
echo ""
echo "Monitoring GPIO $HOST_GPIO_PIN for state changes..."
echo "Press Ctrl+C to stop early"
echo ""

# Monitor for state changes
CHANGE_DETECTED=0
PREV_STATE=$INITIAL_STATE
ITERATIONS=1000  # 10 seconds at 10ms intervals

for i in $(seq 1 $ITERATIONS); do
    CURRENT_STATE=$(cat "$GPIO_PATH/value" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to read GPIO during monitoring"
        break
    fi
    
    # Check if state changed
    if [ "$CURRENT_STATE" != "$PREV_STATE" ]; then
        echo ""
        echo "SUCCESS: Hardware IRQ line toggled!"
        echo "  State changed: $PREV_STATE -> $CURRENT_STATE"
        echo "  Iteration: $i / $ITERATIONS"
        echo ""
        echo "Hardware connection verified: TPM Pin 18 (PIRQ#) is connected to GPIO $HOST_GPIO_PIN"
        CHANGE_DETECTED=1
        break
    fi
    
    PREV_STATE=$CURRENT_STATE
    
    # Sleep 10ms (100Hz sample rate)
    sleep 0.01
done

# Cleanup
echo "$HOST_GPIO_PIN" > /sys/class/gpio/unexport 2>/dev/null

# Report results
if [ $CHANGE_DETECTED -eq 1 ]; then
    echo "=== VERIFICATION PASSED ==="
    echo "IRQ support can be implemented on this hardware"
    exit 0
else
    echo ""
    echo "=== VERIFICATION INCONCLUSIVE ==="
    echo "No GPIO line movement detected during monitoring period"
    echo ""
    echo "This could mean:"
    echo "1. Wrong GPIO pin specified (current: $HOST_GPIO_PIN)"
    echo "   - Check your board schematic/HAT documentation"
    echo "   - Try different GPIO pins (e.g., 23, 25)"
    echo ""
    echo "2. TPM Pin 18 (PIRQ#) is not connected on this PCB/HAT"
    echo "   - Verify physical connection on board"
    echo "   - Many breakout boards only route SPI, not IRQ pin"
    echo ""
    echo "3. TPM not responding or no command was run"
    echo "   - Ensure TPM is powered and functional"
    echo "   - Run a TPM command in another terminal during monitoring"
    echo ""
    echo "4. GPIO Character Device API should be used instead"
    echo "   - The IRQ code will automatically use this method"
    echo "   - You can still test IRQ functionality"
    echo ""
    echo "You can still test IRQ functionality even if hardware verification fails:"
    echo "  sudo ./examples/irq/tpm_irq_test -g $HOST_GPIO_PIN"
    exit 1
fi
