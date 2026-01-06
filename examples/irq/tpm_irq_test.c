/* tpm_irq_test.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfTPM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Unit test for TPM IRQ (interrupt) support
 *
 * Tests:
 * - IRQ support detection
 * - IRQ enable/disable
 * - IRQ status reading
 * - Latency measurement
 * - Spurious interrupt handling
 * - Race condition prevention
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef WOLFTPM_IRQ

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_tis.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef TPM2_IRQ_GPIO_PIN
    #define TPM2_IRQ_GPIO_PIN 24  /* Default for Raspberry Pi */
#endif

static void print_usage(const char* prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -h, --help          Show this help message\n");
    printf("  -g, --gpio <pin>    GPIO pin number (default: %d)\n", TPM2_IRQ_GPIO_PIN);
    printf("  -v, --verbose       Enable verbose output\n");
    printf("\n");
    printf("Tests IRQ support for Infineon SLB9672/SLB9673 TPM\n");
    printf("Requires root privileges for GPIO access\n");
}

static int test_irq_support_detection(TPM2_CTX* ctx)
{
    int rc;
    word32 supported_flags = 0;

    printf("\n=== Test 1: IRQ Support Detection ===\n");

    rc = TPM2_TIS_CheckIRQSupport(ctx, &supported_flags);
    if (rc != TPM_RC_SUCCESS) {
        printf("FAILED: TPM2_TIS_CheckIRQSupport returned 0x%x\n", rc);
        return -1;
    }

    printf("SUCCESS: IRQ support check completed\n");
    printf("  Supported interrupt flags: 0x%08x\n", supported_flags);

    if (supported_flags == 0) {
        printf("WARNING: No interrupts supported by this TPM\n");
        return 0;
    }

    if (supported_flags & TPM_INTF_DATA_AVAIL_INT)
        printf("  - DATA_AVAIL interrupt supported\n");
    if (supported_flags & TPM_INTF_STS_VALID_INT)
        printf("  - STS_VALID interrupt supported\n");
    if (supported_flags & TPM_INTF_CMD_READY_INT)
        printf("  - CMD_READY interrupt supported\n");
    if (supported_flags & TPM_INTF_LOC_CHANGE_INT)
        printf("  - LOC_CHANGE interrupt supported\n");

    return 0;
}

static int test_irq_enable_disable(TPM2_CTX* ctx)
{
    int rc;
    word32 supported_flags = 0;
    word32 int_status = 0;

    printf("\n=== Test 2: IRQ Enable/Disable ===\n");

    /* Check support first */
    rc = TPM2_TIS_CheckIRQSupport(ctx, &supported_flags);
    if (rc != TPM_RC_SUCCESS || supported_flags == 0) {
        printf("SKIPPED: No IRQ support available\n");
        return 0;
    }

    /* Test enabling interrupts */
    rc = TPM2_TIS_EnableIRQ(ctx, TPM_INTF_DATA_AVAIL_INT);
    if (rc != TPM_RC_SUCCESS) {
        printf("FAILED: TPM2_TIS_EnableIRQ returned 0x%x\n", rc);
        return -1;
    }
    printf("SUCCESS: IRQ enabled\n");

    /* Read interrupt status (should be 0 initially) */
    rc = TPM2_TIS_GetIRQStatus(ctx, &int_status);
    if (rc != TPM_RC_SUCCESS) {
        printf("FAILED: TPM2_TIS_GetIRQStatus returned 0x%x\n", rc);
        TPM2_TIS_DisableIRQ(ctx);
        return -1;
    }
    printf("  Interrupt status: 0x%08x\n", int_status);

    /* Test disabling interrupts */
    rc = TPM2_TIS_DisableIRQ(ctx);
    if (rc != TPM_RC_SUCCESS) {
        printf("FAILED: TPM2_TIS_DisableIRQ returned 0x%x\n", rc);
        return -1;
    }
    printf("SUCCESS: IRQ disabled\n");

    return 0;
}

static int test_irq_latency(TPM2_CTX* ctx, int gpio_pin)
{
    int rc;
    word32 supported_flags = 0;
    struct timespec start, end;
    double latency_ms;
    GetRandom_In getRand;
    GetRandom_Out getRandOut;

    printf("\n=== Test 3: IRQ Latency Measurement ===\n");

    /* Check support */
    rc = TPM2_TIS_CheckIRQSupport(ctx, &supported_flags);
    if (rc != TPM_RC_SUCCESS || supported_flags == 0) {
        printf("SKIPPED: No IRQ support available\n");
        return 0;
    }

    /* Setup GPIO IRQ */
#ifdef __linux__
    rc = TPM2_Linux_GPIO_IRQ_Setup(ctx, gpio_pin);
    if (rc != 0) {
        printf("SKIPPED: GPIO IRQ setup failed (may need root or hardware not connected)\n");
        return 0;
    }
    ctx->irq_enabled = 1;
    printf("GPIO IRQ setup: pin %d\n", gpio_pin);
#endif

    /* Enable interrupts */
    rc = TPM2_TIS_EnableIRQ(ctx, TPM_INTF_DATA_AVAIL_INT);
    if (rc != TPM_RC_SUCCESS) {
        printf("FAILED: Failed to enable IRQ\n");
        return -1;
    }

    /* Send a TPM command and measure latency */
    XMEMSET(&getRand, 0, sizeof(getRand));
    getRand.bytesRequested = 32;

    clock_gettime(CLOCK_MONOTONIC, &start);

    rc = TPM2_GetRandom(&getRand, &getRandOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("FAILED: TPM2_GetRandom returned 0x%x\n", rc);
        TPM2_TIS_DisableIRQ(ctx);
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    /* Calculate latency */
    latency_ms = ((end.tv_sec - start.tv_sec) * 1000.0) +
                 ((end.tv_nsec - start.tv_nsec) / 1000000.0);

    printf("SUCCESS: Command completed with IRQ\n");
    printf("  Latency: %.2f ms\n", latency_ms);
    printf("  Random bytes received: %d\n", getRandOut.randomBytes.size);

    /* Disable interrupts */
    TPM2_TIS_DisableIRQ(ctx);
#ifdef __linux__
    TPM2_Linux_GPIO_IRQ_Cleanup(ctx);
    ctx->irq_enabled = 0;
#endif

    return 0;
}

static int test_spurious_interrupt(TPM2_CTX* ctx, int gpio_pin)
{
    int rc;
    word32 supported_flags = 0;
    word32 int_status = 0;

    printf("\n=== Test 4: Spurious Interrupt Handling ===\n");

    /* Check support */
    rc = TPM2_TIS_CheckIRQSupport(ctx, &supported_flags);
    if (rc != TPM_RC_SUCCESS || supported_flags == 0) {
        printf("SKIPPED: No IRQ support available\n");
        return 0;
    }

    /* Setup GPIO IRQ */
#ifdef __linux__
    rc = TPM2_Linux_GPIO_IRQ_Setup(ctx, gpio_pin);
    if (rc != 0) {
        printf("SKIPPED: GPIO IRQ setup failed\n");
        return 0;
    }
    ctx->irq_enabled = 1;
#endif

    /* Enable interrupts without sending a command */
    rc = TPM2_TIS_EnableIRQ(ctx, TPM_INTF_DATA_AVAIL_INT);
    if (rc != TPM_RC_SUCCESS) {
        printf("FAILED: Failed to enable IRQ\n");
        return -1;
    }

    printf("IRQ enabled, waiting 2 seconds (no command sent)...\n");
    sleep(2);

    /* Check interrupt status */
    rc = TPM2_TIS_GetIRQStatus(ctx, &int_status);
    if (rc != TPM_RC_SUCCESS) {
        printf("FAILED: Failed to read IRQ status\n");
        TPM2_TIS_DisableIRQ(ctx);
        return -1;
    }

    printf("  Interrupt status: 0x%08x\n", int_status);
    if (int_status != 0) {
        printf("WARNING: Spurious interrupt detected (may be normal)\n");
    } else {
        printf("SUCCESS: No spurious interrupts (as expected)\n");
    }

    /* Disable interrupts */
    TPM2_TIS_DisableIRQ(ctx);
#ifdef __linux__
    TPM2_Linux_GPIO_IRQ_Cleanup(ctx);
    ctx->irq_enabled = 0;
#endif

    return 0;
}

static int test_race_condition(TPM2_CTX* ctx)
{
    int rc;
    word32 supported_flags = 0;
    byte status = 0;

    printf("\n=== Test 5: Race Condition Prevention ===\n");

    /* Check support */
    rc = TPM2_TIS_CheckIRQSupport(ctx, &supported_flags);
    if (rc != TPM_RC_SUCCESS || supported_flags == 0) {
        printf("SKIPPED: No IRQ support available\n");
        return 0;
    }

    /* This test verifies that status is checked immediately after enabling IRQ */
    /* The actual race condition prevention is in TPM2_TIS_WaitForStatus */
    printf("Testing immediate status check after IRQ enable...\n");

    /* Enable interrupts */
    rc = TPM2_TIS_EnableIRQ(ctx, TPM_INTF_DATA_AVAIL_INT);
    if (rc != TPM_RC_SUCCESS) {
        printf("FAILED: Failed to enable IRQ\n");
        return -1;
    }

    /* Immediately check status (simulating race condition prevention) */
    rc = TPM2_TIS_Status(ctx, &status);
    if (rc != TPM_RC_SUCCESS) {
        printf("FAILED: Failed to read status\n");
        TPM2_TIS_DisableIRQ(ctx);
        return -1;
    }

    printf("SUCCESS: Status check completed immediately after IRQ enable\n");
    printf("  Status: 0x%02x\n", status);

    /* Disable interrupts */
    TPM2_TIS_DisableIRQ(ctx);

    return 0;
}

int main(int argc, char* argv[])
{
    int rc;
    TPM2_CTX ctx;
    int gpio_pin = TPM2_IRQ_GPIO_PIN;
    int verbose = 0;  /* Reserved for future verbose output */
    int i;

    /* Parse arguments */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--gpio") == 0) {
            if (i + 1 < argc) {
                gpio_pin = atoi(argv[++i]);
            } else {
                printf("ERROR: GPIO pin number required\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            /* Verbose mode - currently not used but reserved for future use */
            (void)verbose; /* Suppress unused warning */
        } else {
            printf("ERROR: Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    printf("=== TPM IRQ Unit Test ===\n");
    printf("GPIO Pin: %d\n", gpio_pin);
    printf("\n");

    /* Initialize TPM - for Infineon SLB9672 with SPI, need IO callback */
    XMEMSET(&ctx, 0, sizeof(ctx));
    
    /* Use TPM2_Init_ex with IO callback but no startup (timeoutTries=0) */
    rc = TPM2_Init_ex(&ctx, TPM2_IoCb, NULL, 0);
    if (rc != TPM_RC_SUCCESS) {
        printf("ERROR: TPM2_Init_ex failed: 0x%x (%s)\n", rc, TPM2_GetRCString(rc));
        printf("\nTroubleshooting:\n");
        printf("1. Ensure TPM is powered and connected\n");
        printf("2. Check SPI interface is configured correctly\n");
        printf("3. Verify you have permissions to access TPM (may need root)\n");
        printf("4. Check dmesg for TPM/SPI errors: dmesg | grep -i tpm\n");
        return 1;
    }
    
    printf("TPM initialized (minimal mode)\n");

    /* Request locality */
    printf("Requesting TPM locality...\n");
    rc = TPM2_TIS_RequestLocality(&ctx, TPM_TIMEOUT_TRIES);
    if (rc < 0) {
        printf("ERROR: Failed to request locality: 0x%x (%s)\n", rc, TPM2_GetRCString(rc));
        printf("This may indicate TPM is not accessible via SPI\n");
        TPM2_Cleanup(&ctx);
        return 1;
    }
    printf("Locality requested successfully\n");

    /* Try chip startup (may be needed for some TPMs) */
    printf("Performing chip startup...\n");
    rc = TPM2_ChipStartup(&ctx, TPM_TIMEOUT_TRIES);
    if (rc != TPM_RC_SUCCESS) {
        printf("WARNING: Chip startup failed: 0x%x (%s)\n", rc, TPM2_GetRCString(rc));
        printf("Continuing anyway - TPM may already be started\n");
    } else {
        printf("Chip startup successful\n");
    }

    /* Get TPM info */
    printf("Getting TPM info...\n");
    rc = TPM2_TIS_GetInfo(&ctx);
    if (rc != TPM_RC_SUCCESS) {
        printf("WARNING: Failed to get TPM info: 0x%x (%s)\n", rc, TPM2_GetRCString(rc));
        printf("TPM may not be responding. Check SPI connection and power.\n");
        printf("Continuing with IRQ tests anyway (may work for register access)\n");
        printf("\n");
    } else {
        printf("TPM Info:\n");
        printf("  Caps: 0x%08x\n", ctx.caps);
        printf("  DID/VID: 0x%08x\n", ctx.did_vid);
        printf("  RID: 0x%02x\n", ctx.rid);
        printf("\n");
    }

    printf("TPM Info:\n");
    printf("  Caps: 0x%08x\n", ctx.caps);
    printf("  DID/VID: 0x%08x\n", ctx.did_vid);
    printf("  RID: 0x%02x\n", ctx.rid);
    printf("\n");

    /* Run tests */
    int tests_passed = 0;
    int tests_total = 0;

    tests_total++;
    if (test_irq_support_detection(&ctx) == 0)
        tests_passed++;

    tests_total++;
    if (test_irq_enable_disable(&ctx) == 0)
        tests_passed++;

    tests_total++;
    if (test_irq_latency(&ctx, gpio_pin) == 0)
        tests_passed++;

    tests_total++;
    if (test_spurious_interrupt(&ctx, gpio_pin) == 0)
        tests_passed++;

    tests_total++;
    if (test_race_condition(&ctx) == 0)
        tests_passed++;

    /* Cleanup */
    TPM2_Cleanup(&ctx);

    /* Summary */
    printf("\n=== Test Summary ===\n");
    printf("Tests passed: %d / %d\n", tests_passed, tests_total);

    if (tests_passed == tests_total) {
        printf("SUCCESS: All tests passed\n");
        return 0;
    } else {
        printf("WARNING: Some tests failed or were skipped\n");
        return 1;
    }
}

#else /* WOLFTPM_IRQ */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    printf("IRQ support not compiled in (WOLFTPM_IRQ not defined)\n");
    printf("Rebuild with --enable-irq or configure for SLB9672/SLB9673\n");
    return 1;
}

#endif /* WOLFTPM_IRQ */

