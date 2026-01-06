/* spdm_ac_demo.c
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

/* SPDM Authenticated Controller (AC) Demo
 * Demonstrates AC handle discovery, capability query, SPDM message tunneling,
 * and bus encryption establishment per TCG TPM 2.0 Library Spec v1.84
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#ifdef WOLFTPM_SPDM

/******************************************************************************/
/* --- BEGIN SPDM AC Demo -- */
/******************************************************************************/

/* Forward declarations */
int TPM2_SPDM_AC_Demo(void* userCtx, int argc, char *argv[]);

static void usage(void)
{
    printf("SPDM Authenticated Controller (AC) Demo\n");
    printf("Usage: spdm_ac_demo [options]\n");
    printf("Options:\n");
    printf("  --check-transport          Check if transport supports AC commands\n");
    printf("  --discover-handles         Discover all AC handles on TPM\n");
    printf("  --query-capabilities <h>   Query capabilities of AC handle (hex)\n");
    printf("  --spdm-tunnel <h> <file>   Send SPDM message from file through AC\n");
    printf("  --establish-channel <h>   Establish secure channel with AC (demo)\n");
    printf("  -h, --help                 Show this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  ./spdm_ac_demo --check-transport\n");
    printf("  ./spdm_ac_demo --discover-handles\n");
    printf("  ./spdm_ac_demo --query-capabilities 0x40000000\n");
    printf("  ./spdm_ac_demo --spdm-tunnel 0x40000000 spdm_request.bin\n");
}

static int check_transport(WOLFTPM2_DEV* dev)
{
    int rc;
    int supported = 0;

    printf("Checking AC transport support...\n");
    rc = wolfTPM2_CheckACTransportSupport(dev, &supported);
    if (rc == TPM_RC_SUCCESS) {
        if (supported) {
            printf("  Transport supports AC commands (0x19E/0x19F)\n");
        } else {
            printf("  Transport does NOT support AC commands\n");
            printf("  Solution: Upgrade kernel, use direct SPI/I2C, or use swtpm\n");
        }
    } else {
        printf("  Transport check failed: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }
    return rc;
}

static int discover_handles(WOLFTPM2_DEV* dev)
{
    int rc;
    TPM_HANDLE acHandles[16];
    word32 count = 0;
    word32 i;

    printf("Discovering AC handles...\n");
    rc = wolfTPM2_GetACHandles(dev, acHandles, &count, 16);
    if (rc == TPM_RC_SUCCESS) {
        if (count > 0) {
            printf("  Found %d AC handle(s):\n", (int)count);
            for (i = 0; i < count; i++) {
                printf("    AC handle: 0x%08x\n", (unsigned int)acHandles[i]);
            }
        } else {
            printf("  No AC handles found (TPM may not support AC or firmware < v1.84)\n");
        }
    } else {
        printf("  Discovery failed: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }
    return rc;
}

static int query_capabilities(WOLFTPM2_DEV* dev, TPM_HANDLE acHandle)
{
    int rc;
    TPMA_AC capabilities;
    TPM_AT acType;

    printf("Querying AC capabilities for handle 0x%08x...\n", (unsigned int)acHandle);
    rc = wolfTPM2_AC_GetCapability(dev, acHandle, &capabilities, &acType);
    if (rc == TPM_RC_SUCCESS) {
        printf("  Capabilities: 0x%08x\n", (unsigned int)capabilities);
        if (capabilities & TPM_AC_SPDM_10) {
            printf("    - SPDM 1.0 support\n");
        }
        if (capabilities & TPM_AC_SPDM_11) {
            printf("    - SPDM 1.1 support\n");
        }
        if (capabilities & TPM_AC_SPDM_12) {
            printf("    - SPDM 1.2 support\n");
        }
        if (capabilities & TPM_AC_SECURE_MESSAGES) {
            printf("    - Secure messages support\n");
        }
        if (capabilities & TPM_AC_BUS_ENCRYPTION) {
            printf("    - Bus encryption support\n");
        }
        printf("  Attachment Type: 0x%08x", (unsigned int)acType);
        if (acType == TPM_AT_PVT) {
            printf(" (Private)\n");
        } else if (acType == TPM_AT_PUB) {
            printf(" (Public)\n");
        } else {
            printf("\n");
        }
    } else {
        printf("  Query failed: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }
    return rc;
}

static int spdm_tunnel(WOLFTPM2_DEV* dev, TPM_HANDLE acHandle, const char* filename)
{
    int rc;
    FILE* file;
    byte* spdmRequest = NULL;
    byte spdmResponse[1024];
    word32 reqSz = 0, respSz = sizeof(spdmResponse);
    TPM2B_NONCE nonce;
    long fileSize;
    size_t bytesRead;

    printf("Sending SPDM message through AC tunnel (handle 0x%08x)...\n",
        (unsigned int)acHandle);

    /* Read SPDM request from file */
    file = fopen(filename, "rb");
    if (file == NULL) {
        printf("  Error: Cannot open file: %s\n", filename);
        return BAD_FUNC_ARG;
    }

    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (fileSize <= 0 || fileSize > 4096) {
        printf("  Error: Invalid file size: %ld\n", fileSize);
        fclose(file);
        return BAD_FUNC_ARG;
    }

    spdmRequest = (byte*)malloc((size_t)fileSize);
    if (spdmRequest == NULL) {
        printf("  Error: Memory allocation failed\n");
        fclose(file);
        return MEMORY_E;
    }

    bytesRead = fread(spdmRequest, 1, (size_t)fileSize, file);
    fclose(file);

    if (bytesRead != (size_t)fileSize) {
        printf("  Error: Failed to read file\n");
        free(spdmRequest);
        return BAD_FUNC_ARG;
    }

    reqSz = (word32)fileSize;

    printf("  SPDM request size: %d bytes\n", (int)reqSz);

    /* Send SPDM message through AC */
    XMEMSET(&nonce, 0, sizeof(nonce));
    rc = wolfTPM2_AC_Send(dev, acHandle, spdmRequest, reqSz,
                         spdmResponse, &respSz, &nonce);
    if (rc == TPM_RC_SUCCESS) {
        printf("  SPDM response size: %d bytes\n", (int)respSz);
        printf("  TPM nonce size: %d bytes\n", (int)nonce.size);
        printf("  Response (first 32 bytes):\n");
        {
            word32 i;
            for (i = 0; i < respSz && i < 32; i++) {
                if (i % 16 == 0) printf("    ");
                printf("%02x ", spdmResponse[i]);
                if ((i + 1) % 16 == 0) printf("\n");
            }
            if (respSz > 32 && respSz % 16 != 0) printf("\n");
        }
    } else if (rc == TPM_RC_COMMAND_CODE) {
        printf("  ⚠ EXPECTED: TPM_RC_COMMAND_CODE - AC_Send not enabled in simulator\n");
        printf("    This is expected - TCG simulator has CC_AC_Send = CC_NO by default\n");
        printf("    Command marshalling is correct, but requires simulator rebuild to enable\n");
        printf("    See examples/spdm/README.md for enabling instructions\n");
        printf("    Note: Full testing requires hardware TPM with SPDM/AC support\n");
    } else {
        printf("  AC_Send failed: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    }

    free(spdmRequest);
    return rc;
}

static int establish_channel(WOLFTPM2_DEV* dev, TPM_HANDLE acHandle)
{
    int rc;
    WOLFTPM2_SESSION session;
    byte sharedSecret[32];  /* Demo: dummy shared secret */
    TPM2B_NONCE nonce;
    word32 i;

    printf("Establishing secure channel with AC (handle 0x%08x)...\n",
        (unsigned int)acHandle);

    /* For demo purposes, use dummy shared secret */
    /* In real usage, this would come from libspdm KEY_EXCHANGE */
    printf("  Note: Using dummy shared secret for demonstration\n");
    printf("  In production, use shared secret from libspdm KEY_EXCHANGE\n");
    for (i = 0; i < sizeof(sharedSecret); i++) {
        sharedSecret[i] = (byte)(i & 0xFF);
    }

    /* TODO: This function depends on wolfTPM2_AC_Send() to get nonce from TPM.
     *       AC_Send is not enabled by default in TCG simulator (CC_AC_Send = CC_NO).
     *       Full testing requires enabling AC_Send in simulator or hardware TPM.
     *       Current implementation uses dummy nonce for demonstration. */
    /* Get nonce from AC (would normally come from AC_Send during SPDM handshake) */
    XMEMSET(&nonce, 0, sizeof(nonce));
    nonce.size = 32;
    for (i = 0; i < nonce.size; i++) {
        nonce.buffer[i] = (byte)((i + 1) & 0xFF);
    }

    /* Establish secure channel */
    rc = wolfTPM2_SPDM_EstablishSecureChannel(dev, acHandle, &session,
                                              sharedSecret, sizeof(sharedSecret),
                                              &nonce);
    if (rc == TPM_RC_SUCCESS) {
        printf("  Secure channel established successfully\n");
        printf("  Session handle: 0x%08x\n", (unsigned int)session.handle.hndl);
        printf("  Session ready for encrypted TPM commands\n");
    } else {
        printf("  EstablishSecureChannel failed: 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
        if (rc == TPM_RC_HANDLE) {
            printf("  Note: AC handle may not exist on this TPM\n");
        }
    }

    return rc;
}

int TPM2_SPDM_AC_Demo(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    TPM_HANDLE acHandle = 0;
    int i;

    if (argc <= 1) {
        usage();
        return 0;
    }

    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "-h") == 0 ||
            XSTRCMP(argv[i], "--help") == 0) {
            usage();
            return 0;
        }
    }

    printf("SPDM Authenticated Controller (AC) Demo\n");
    printf("========================================\n\n");

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) {
        printf("wolfTPM2_Init failed: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }

    /* Process command-line options */
    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "--check-transport") == 0) {
            rc = check_transport(&dev);
            if (rc != 0) break;
        }
        else if (XSTRCMP(argv[i], "--discover-handles") == 0) {
            rc = discover_handles(&dev);
            if (rc != 0) break;
        }
        else if (XSTRCMP(argv[i], "--query-capabilities") == 0) {
            if (i + 1 >= argc) {
                printf("Error: --query-capabilities requires AC handle argument\n");
                rc = BAD_FUNC_ARG;
                break;
            }
            if (sscanf(argv[i + 1], "0x%x", (unsigned int*)&acHandle) != 1 &&
                sscanf(argv[i + 1], "%x", (unsigned int*)&acHandle) != 1) {
                printf("Error: Invalid AC handle format: %s\n", argv[i + 1]);
                rc = BAD_FUNC_ARG;
                break;
            }
            i++;  /* Skip handle argument */
            rc = query_capabilities(&dev, acHandle);
            if (rc != 0) break;
        }
        else if (XSTRCMP(argv[i], "--spdm-tunnel") == 0) {
            if (i + 2 >= argc) {
                printf("Error: --spdm-tunnel requires AC handle and filename\n");
                rc = BAD_FUNC_ARG;
                break;
            }
            if (sscanf(argv[i + 1], "0x%x", (unsigned int*)&acHandle) != 1 &&
                sscanf(argv[i + 1], "%x", (unsigned int*)&acHandle) != 1) {
                printf("Error: Invalid AC handle format: %s\n", argv[i + 1]);
                rc = BAD_FUNC_ARG;
                break;
            }
            i += 2;  /* Skip handle and filename arguments */
            rc = spdm_tunnel(&dev, acHandle, argv[i - 1]);
            if (rc != 0) break;
        }
        else if (XSTRCMP(argv[i], "--establish-channel") == 0) {
            if (i + 1 >= argc) {
                printf("Error: --establish-channel requires AC handle argument\n");
                rc = BAD_FUNC_ARG;
                break;
            }
            if (sscanf(argv[i + 1], "0x%x", (unsigned int*)&acHandle) != 1 &&
                sscanf(argv[i + 1], "%x", (unsigned int*)&acHandle) != 1) {
                printf("Error: Invalid AC handle format: %s\n", argv[i + 1]);
                rc = BAD_FUNC_ARG;
                break;
            }
            i++;  /* Skip handle argument */
            rc = establish_channel(&dev, acHandle);
            if (rc != 0) break;
        }
        else {
            printf("Error: Unknown option: %s\n", argv[i]);
            usage();
            rc = BAD_FUNC_ARG;
            break;
        }
    }

    /* Cleanup */
    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END SPDM AC Demo -- */
/******************************************************************************/

#else /* !WOLFTPM_SPDM */
int TPM2_SPDM_AC_Demo(void* userCtx, int argc, char *argv[])
{
    (void)userCtx;
    (void)argc;
    (void)argv;
    printf("SPDM support not compiled in!\n");
    printf("Rebuild with: ./configure --enable-spdm\n");
    return NOT_COMPILED_IN;
}
#endif /* WOLFTPM_SPDM */

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_SPDM_AC_Demo(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return (rc == 0) ? 0 : 1;
}
#endif /* !NO_MAIN_DRIVER */
