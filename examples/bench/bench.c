/* bench.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

/* This example shows benchmarks using the TPM2 wrapper API's in
    TPM2_Wrapper_Bench() below. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(NO_TPM_BENCH)

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>
#include <examples/bench/bench.h>

/* Configuration */
#define TPM2_BENCH_DURATION_SEC         1
#define TPM2_BENCH_DURATION_KEYGEN_SEC  15
static int gUseBase2 = 1;
static int gMarkdown = 0;

/* Emit one markdown table row, printing the header before the first row. */
static void bench_md_row(const char* algo, const char* level, const char* op,
    const char* latency, const char* rate)
{
    static int headerDone = 0;

    if (!headerDone) {
        printf("| Algorithm | Level | Operation | Avg latency | Throughput |\n");
        printf("|---|---|---|---|---|\n");
        headerDone = 1;
    }
    printf("| %s | %s | %s | %s | %s |\n", algo, level, op, latency, rate);
}

static inline void bench_stats_start(int* count, double* start)
{
    *count = 0;
    *start = gettime_secs(1);
}

static inline int bench_stats_check(double start, int* count, double maxDurSec)
{
    (*count)++;
    return ((gettime_secs(0) - start) < maxDurSec);
}

/* countSz is number of bytes that 1 count represents. Normally bench_size,
 * except for AES direct that operates on AES_BLOCK_SIZE blocks */
static void bench_stats_sym_finish(const char* desc, int count, int countSz,
    double start)
{
    double total, persec = 0, blocks = count;
    const char* blockType;

    total = gettime_secs(0) - start;

    /* calculate actual bytes */
    blocks *= countSz;

    /* base 2 result */
    if (gUseBase2) {
        /* determine if we should show as KB or MB */
        if (blocks > (1024 * 1024)) {
            blocks /= (1024 * 1024);
            blockType = "MB";
        }
        else if (blocks > 1024) {
            blocks /= 1024; /* make KB */
            blockType = "KB";
        }
        else {
            blockType = "bytes";
        }
    }
    /* base 10 result */
    else {
        /* determine if we should show as kB or mB */
        if (blocks > (1000 * 1000)) {
            blocks /= (1000 * 1000);
            blockType = "mB";
        }
        else if (blocks > 1000) {
            blocks /= 1000; /* make kB */
            blockType = "kB";
        }
        else {
            blockType = "bytes";
        }
    }

    /* calculate blocks per second */
    if (total > 0) {
        persec = (1 / total) * blocks;
    }

    if (gMarkdown) {
        char rate[64];
        XSNPRINTF(rate, sizeof(rate), "%.3f %s/s", persec, blockType);
        bench_md_row(desc, "", "", "-", rate);
        return;
    }

    /* format and print to terminal */
    printf("%-16s %5.0f %s took %5.3f seconds, %8.3f %s/s\n",
        desc, blocks, blockType, total, persec, blockType);
}

static void bench_stats_asym_finish(const char* algo, int strength,
    const char* desc, int count, double start)
{
    double total, each = 0, opsSec, milliEach;

    total = gettime_secs(0) - start;
    if (count > 0)
        each  = total / count; /* per second  */
    opsSec = count / total;    /* ops second */
    milliEach = each * 1000;   /* milliseconds */

    if (gMarkdown) {
        char lvl[16], latency[32], rate[32];
        XSNPRINTF(lvl, sizeof(lvl), "%d", strength);
        XSNPRINTF(latency, sizeof(latency), "%.1f ms", milliEach);
        XSNPRINTF(rate, sizeof(rate), "%.3f ops/s", opsSec);
        bench_md_row(algo, lvl, desc, latency, rate);
        return;
    }

    printf("%-6s %5d %-9s %6d ops took %5.3f sec, avg %5.3f ms,"
        " %.3f ops/sec\n", algo, strength, desc,
        count, total, milliEach, opsSec);
}

/* True if rc means the TPM does not implement the operation (so the bench
 * can skip it instead of aborting). Masks parameter bits on FMT1 codes. */
static int bench_unsupported(int rc)
{
    /* TPM_RC_DISABLED: Infineon parts ship with TPM2_EncryptDecrypt off.
     * TPM_RC_TYPE: the key type (e.g. ML-DSA/ML-KEM) is not implemented.
     * TPM_RC_VALUE: the parameter set (e.g. ML-DSA-44) is not implemented. */
    return ((rc & RC_MAX_FMT1) == TPM_RC_SCHEME) ||
        ((rc & RC_MAX_FMT1) == (TPM_RC_TYPE & RC_MAX_FMT1)) ||
        ((rc & RC_MAX_FMT1) == TPM_RC_VALUE) ||
        WOLFTPM_IS_COMMAND_UNAVAILABLE(rc) ||
        (rc == TPM_RC_DISABLED);
}

/* Print timing on success, "Skipped" if the op was not implemented. Returns
 * 0 when handled (the bench should continue) or rc on a hard error. */
static int bench_asym_done(const char* algo, int strength, const char* desc,
    int count, double start, int rc)
{
    if (rc == 0) {
        bench_stats_asym_finish(algo, strength, desc, count, start);
        return 0;
    }
    if (bench_unsupported(rc)) {
        if (gMarkdown) {
            char lvl[16];
            XSNPRINTF(lvl, sizeof(lvl), "%d", strength);
            bench_md_row(algo, lvl, desc, "N/A", "not supported");
        }
        else {
            printf("%-6s %5d %-9s Skipped (not supported)\n", algo, strength,
                desc);
        }
        return 0;
    }
    return rc;
}

static int bench_sym_hash(WOLFTPM2_DEV* dev, const char* desc, int algo,
    const byte* in, word32 inSz, byte* digest, word32 digestSz, double maxDuration)
{
    int rc;
    int count;
    double start;
    WOLFTPM2_HASH hash;

    XMEMSET(&hash, 0, sizeof(hash));
    bench_stats_start(&count, &start);
    do {
        rc = wolfTPM2_HashStart(dev, &hash, algo,
        (const byte*)gUsageAuth, sizeof(gUsageAuth)-1);
        if (rc != 0) goto exit;
        rc = wolfTPM2_HashUpdate(dev, &hash, in, inSz);
        if (rc != 0) goto exit;
        rc = wolfTPM2_HashFinish(dev, &hash, digest, &digestSz);
        if (rc != 0) goto exit;
    } while (bench_stats_check(start, &count, maxDuration));
    bench_stats_sym_finish(desc, count, inSz, start);

exit:
    wolfTPM2_UnloadHandle(dev, &hash.handle);
    return rc;
}

static int bench_sym_aes(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* storageKey,
    const char* desc, int algo, int keyBits, const byte* in, byte* out,
    word32 inOutSz, int isDecrypt, double maxDuration)
{
    int rc;
    int count;
    double start;
    TPMT_PUBLIC publicTemplate;
    WOLFTPM2_KEY aesKey;
    byte iv[MAX_AES_BLOCK_SIZE_BYTES];

    XMEMSET(&aesKey, 0, sizeof(aesKey));
    rc = wolfTPM2_GetKeyTemplate_Symmetric(&publicTemplate, keyBits, algo,
        YES, YES);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreateAndLoadKey(dev, &aesKey, &storageKey->handle,
        &publicTemplate, (byte*)gUsageAuth, sizeof(gUsageAuth)-1);
    if ((rc & RC_MAX_FMT1) == TPM_RC_MODE ||
            (rc & RC_MAX_FMT1) == TPM_RC_VALUE) {
        if (gMarkdown)
            bench_md_row(desc, "", "", "N/A", "not supported");
        else
            printf("Benchmark symmetric %s not supported!\n", desc);
        rc = 0; goto exit;
    }
    else if (rc != 0) goto exit;

    bench_stats_start(&count, &start);
    do {
        XMEMSET(iv, 0, sizeof(iv));
        rc = wolfTPM2_EncryptDecrypt(dev, &aesKey, in, out, inOutSz, iv,
            sizeof(iv), isDecrypt);
        if (bench_unsupported(rc)) {
            if (gMarkdown) {
                bench_md_row(desc, "", "", "N/A", "command disabled");
                rc = 0; goto exit;
            }
            printf("Encrypt/Decrypt unavailable\n");
            break;
        }
        if (rc != 0) goto exit;
    } while (bench_stats_check(start, &count, maxDuration));
    bench_stats_sym_finish(desc, count, inOutSz, start);

exit:
    wolfTPM2_UnloadHandle(dev, &aesKey.handle);
    return rc;
}

#if defined(WOLFTPM_MLDSA) || defined(WOLFTPM_HASH_MLDSA)
/* Display strength for an ML-DSA parameter set constant. */
static int mldsa_bits(int paramSet)
{
    if (paramSet == TPM_MLDSA_87) return 87;
    if (paramSet == TPM_MLDSA_65) return 65;
    return 44;
}
#endif

#ifdef WOLFTPM_MLKEM
/* Display strength for an ML-KEM parameter set constant. */
static int mlkem_bits(int paramSet)
{
    if (paramSet == TPM_MLKEM_1024) return 1024;
    if (paramSet == TPM_MLKEM_768) return 768;
    return 512;
}
#endif

#ifdef WOLFTPM_HASH_MLDSA
/* Largest command the TPM accepts, 0 if it does not report the property. */
static word32 bench_input_buffer(void)
{
    int rc;
    GetCapability_In in;
    GetCapability_Out out;

    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    in.capability = TPM_CAP_TPM_PROPERTIES;
    in.property = TPM_PT_INPUT_BUFFER;
    in.propertyCount = 1;
    rc = TPM2_GetCapability(&in, &out);
    if (rc != TPM_RC_SUCCESS)
        return 0;
    return out.capabilityData.data.tpmProperties.tpmProperty[0].value;
}

/* Benchmark Hash-ML-DSA (pre-hashed SignDigest/VerifyDigestSignature). Some
 * parts implement only this surface and only one parameter set. */
static int bench_pqc_hash_mldsa(WOLFTPM2_DEV* dev, double maxDuration,
    double maxKeyGenDurSec, int paramSet)
{
    int rc, count, bits;
    double start;
    word32 inputBuffer;
    WOLFTPM2_KEY mldsaKey;
    TPMT_PUBLIC publicTemplate;
    TPMT_TK_VERIFIED validation;
    byte digest[TPM_SHA256_DIGEST_SIZE];
    byte sig[MAX_MLDSA_SIG_SIZE];
    int sigSz = 0;

    XMEMSET(&mldsaKey, 0, sizeof(mldsaKey));
    XMEMSET(&publicTemplate, 0, sizeof(publicTemplate));
    XMEMSET(&validation, 0, sizeof(validation));
    XMEMSET(digest, 0xAA, sizeof(digest));
    XMEMSET(sig, 0, sizeof(sig));

    bits = mldsa_bits(paramSet);

    rc = wolfTPM2_GetKeyTemplate_HASH_MLDSA(&publicTemplate,
        TPMA_OBJECT_sign | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA, paramSet, TPM_ALG_SHA256);
    if (rc != 0) return rc;

    bench_stats_start(&count, &start);
    do {
        if (count > 0)
            wolfTPM2_UnloadHandle(dev, &mldsaKey.handle);
        rc = wolfTPM2_CreatePrimaryKey(dev, &mldsaKey, TPM_RH_OWNER,
            &publicTemplate, NULL, 0);
        if (rc != 0) break;
    } while (bench_stats_check(start, &count, maxKeyGenDurSec));
    rc = bench_asym_done("HMLDSA", bits, "key gen", count, start, rc);
    if (rc != 0)
        return rc;
    if (count == 0)
        return 0;

    bench_stats_start(&count, &start);
    do {
        sigSz = (int)sizeof(sig);
        rc = wolfTPM2_SignDigest(dev, &mldsaKey, digest, (int)sizeof(digest),
            NULL, 0, sig, &sigSz);
        if (rc != 0) break;
    } while (bench_stats_check(start, &count, maxDuration));
    rc = bench_asym_done("HMLDSA", bits, "signdig", count, start, rc);
    if (rc != 0) goto exit;
    if (count == 0)
        goto exit;

    bench_stats_start(&count, &start);
    do {
        rc = wolfTPM2_VerifyDigestSignature(dev, &mldsaKey, digest,
            (int)sizeof(digest), sig, sigSz, NULL, 0, &validation);
        if (rc != 0) break;
    } while (bench_stats_check(start, &count, maxDuration));
    /* An ML-DSA signature can exceed TPM_PT_INPUT_BUFFER, which bounds a single
     * command parameter. Parts differ on whether they accept it anyway, so
     * report the limit only once a verify has actually failed. */
    inputBuffer = bench_input_buffer();
    if (rc != 0 && inputBuffer != 0 && (word32)sigSz > inputBuffer) {
        if (gMarkdown) {
            char lvl[16], why[64];
            XSNPRINTF(lvl, sizeof(lvl), "%d", bits);
            XSNPRINTF(why, sizeof(why), "sig %d > input buffer %u",
                sigSz, (unsigned int)inputBuffer);
            bench_md_row("HMLDSA", lvl, "verifydig", "N/A", why);
        }
        else {
            printf("%-6s %5d %-9s Skipped (sig %d > input buffer %u)\n",
                "HMLDSA", bits, "verifydig", sigSz, (unsigned int)inputBuffer);
        }
        rc = 0;
    }
    else {
        rc = bench_asym_done("HMLDSA", bits, "verifydig", count, start, rc);
    }

exit:
    wolfTPM2_UnloadHandle(dev, &mldsaKey.handle);
    return rc;
}
#endif /* WOLFTPM_HASH_MLDSA */

#ifdef WOLFTPM_MLDSA
/* Benchmark Pure ML-DSA: key gen, sign and verify (sign/verify sequence). */
static int bench_pqc_mldsa(WOLFTPM2_DEV* dev, double maxDuration,
    double maxKeyGenDurSec, int paramSet)
{
    int rc, count, bits;
    double start;
    WOLFTPM2_KEY mldsaKey;
    TPMT_PUBLIC publicTemplate;
    TPMT_TK_VERIFIED validation;
    TPM_HANDLE seqHandle;
    WOLFTPM2_HANDLE seqObj;
    byte message[TPM_SHA256_DIGEST_SIZE];
    byte sig[MAX_MLDSA_SIG_SIZE];
    int sigSz;

    XMEMSET(&mldsaKey, 0, sizeof(mldsaKey));
    XMEMSET(&publicTemplate, 0, sizeof(publicTemplate));
    XMEMSET(message, 0x11, sizeof(message));
    XMEMSET(sig, 0, sizeof(sig));

    bits = mldsa_bits(paramSet);

    rc = wolfTPM2_GetKeyTemplate_MLDSA(&publicTemplate,
        TPMA_OBJECT_sign | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA, paramSet, 0);
    if (rc != 0) return rc;

    bench_stats_start(&count, &start);
    do {
        if (count > 0)
            wolfTPM2_UnloadHandle(dev, &mldsaKey.handle);
        rc = wolfTPM2_CreatePrimaryKey(dev, &mldsaKey, TPM_RH_OWNER,
            &publicTemplate, NULL, 0);
        if (rc != 0) break;
    } while (bench_stats_check(start, &count, maxKeyGenDurSec));
    rc = bench_asym_done("ML-DSA", bits, "key gen", count, start, rc);
    if (rc != 0)
        return rc;
    if (count == 0)
        return 0; /* ML-DSA not implemented; skip the rest of the section */

    /* Pure ML-DSA is one-shot: the message is supplied to Complete. */
    bench_stats_start(&count, &start);
    do {
        sigSz = (int)sizeof(sig);
        rc = wolfTPM2_SignSequenceStart(dev, &mldsaKey, NULL, 0, &seqHandle);
        if (rc == 0) {
            rc = wolfTPM2_SignSequenceComplete(dev, seqHandle, &mldsaKey,
                message, (int)sizeof(message), sig, &sigSz);
            if (rc != 0) {
                /* SignSequenceComplete does not consume the sequence on
                 * error; flush it so the transient slot is not leaked. */
                XMEMSET(&seqObj, 0, sizeof(seqObj));
                seqObj.hndl = seqHandle;
                wolfTPM2_UnloadHandle(dev, &seqObj);
            }
        }
        if (rc != 0) break;
    } while (bench_stats_check(start, &count, maxDuration));
    rc = bench_asym_done("ML-DSA", bits, "sign", count, start, rc);
    if (rc != 0) goto exit;
    if (count == 0)
        goto exit; /* no signature produced; nothing to verify */

    bench_stats_start(&count, &start);
    do {
        rc = wolfTPM2_VerifySequenceStart(dev, &mldsaKey, NULL, 0, &seqHandle);
        if (rc == 0)
            rc = wolfTPM2_VerifySequenceComplete(dev, seqHandle, &mldsaKey,
                message, (int)sizeof(message), sig, sigSz, &validation);
        if (rc != 0) break;
    } while (bench_stats_check(start, &count, maxDuration));
    rc = bench_asym_done("ML-DSA", bits, "verify", count, start, rc);
    if (rc != 0) goto exit;

exit:
    wolfTPM2_UnloadHandle(dev, &mldsaKey.handle);
    return rc;
}
#endif /* WOLFTPM_MLDSA */

#ifdef WOLFTPM_MLKEM
/* Benchmark ML-KEM: key gen, encapsulate and decapsulate. */
static int bench_pqc_mlkem(WOLFTPM2_DEV* dev, double maxDuration,
    double maxKeyGenDurSec, int paramSet)
{
    int rc, count, bits;
    double start;
    WOLFTPM2_KEY mlkemKey;
    TPMT_PUBLIC publicTemplate;
    byte ciphertext[1600];
    int ciphertextSz;
    byte secret[64];
    int secretSz;

    XMEMSET(&mlkemKey, 0, sizeof(mlkemKey));
    XMEMSET(&publicTemplate, 0, sizeof(publicTemplate));

    bits = mlkem_bits(paramSet);

    rc = wolfTPM2_GetKeyTemplate_MLKEM(&publicTemplate,
        TPMA_OBJECT_decrypt | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA, paramSet);
    if (rc != 0) return rc;

    bench_stats_start(&count, &start);
    do {
        if (count > 0)
            wolfTPM2_UnloadHandle(dev, &mlkemKey.handle);
        rc = wolfTPM2_CreatePrimaryKey(dev, &mlkemKey, TPM_RH_OWNER,
            &publicTemplate, NULL, 0);
        if (rc != 0) break;
    } while (bench_stats_check(start, &count, maxKeyGenDurSec));
    rc = bench_asym_done("ML-KEM", bits, "key gen", count, start, rc);
    if (rc != 0)
        return rc;
    if (count == 0)
        return 0; /* ML-KEM not implemented; skip the rest of the section */

    bench_stats_start(&count, &start);
    do {
        ciphertextSz = (int)sizeof(ciphertext);
        secretSz = (int)sizeof(secret);
        rc = wolfTPM2_Encapsulate(dev, &mlkemKey, ciphertext, &ciphertextSz,
            secret, &secretSz);
        if (rc != 0) break;
    } while (bench_stats_check(start, &count, maxDuration));
    rc = bench_asym_done("ML-KEM", bits, "encap", count, start, rc);
    if (rc != 0) goto exit;

    bench_stats_start(&count, &start);
    do {
        secretSz = (int)sizeof(secret);
        rc = wolfTPM2_Decapsulate(dev, &mlkemKey, ciphertext, ciphertextSz,
            secret, &secretSz);
        if (rc != 0) break;
    } while (bench_stats_check(start, &count, maxDuration));
    rc = bench_asym_done("ML-KEM", bits, "decap", count, start, rc);
    if (rc != 0) goto exit;

exit:
    wolfTPM2_UnloadHandle(dev, &mlkemKey.handle);
    return rc;
}
#endif /* WOLFTPM_MLKEM */

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/bench/bench [-aes/xor]\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
    printf("* -maxdur=[ms]: Maximum runtime for each algorithm in milliseconds "
        "(default %d)\n", TPM2_BENCH_DURATION_SEC*1000);
    printf("* --md: Emit results as a markdown table\n");
    printf("* --mldsa=44|65|87: Benchmark only this pure ML-DSA level\n");
    printf("* --hash-mldsa=44|65|87: Benchmark only this Hash-ML-DSA level\n");
    printf("* --mlkem=512|768|1024: Benchmark only this ML-KEM level\n");
    printf("  (PQC options may be repeated; with none given every level runs)\n");
}

#if defined(WOLFTPM_MLDSA) || defined(WOLFTPM_HASH_MLDSA) || \
    defined(WOLFTPM_MLKEM)
/* A parameter set the TPM half-implements can drop it into failure mode.
 * Report the level as unsupported and try to bring the TPM back so the
 * remaining levels still run. Returns 0 if the sweep can continue. */
static int bench_pqc_failed(const char* algo, int strength, int rc)
{
    Startup_In startupIn;

    if (rc != (int)TPM_RC_FAILURE)
        return rc;

    printf("%-6s %5d %-9s Skipped (not supported)\n", algo, strength, "all");

    XMEMSET(&startupIn, 0, sizeof(startupIn));
    startupIn.startupType = TPM_SU_CLEAR;
    if (TPM2_Startup(&startupIn) != TPM_RC_SUCCESS) {
        printf("       TPM is in failure mode, reset it and re-run with "
            "--mldsa= / --hash-mldsa= / --mlkem= to finish the sweep\n");
        return rc;
    }
    return 0;
}

/* Parse "--opt=<val>" into a parameter-set bit. Returns 1 if arg matched. */
static int pqc_select(const char* arg, const char* opt, int* mask,
    const int* vals, const int* bits, int count)
{
    int i;
    size_t optLen = XSTRLEN(opt);

    if (XSTRNCMP(arg, opt, optLen) != 0 || arg[optLen] != '=')
        return 0;
    for (i = 0; i < count; i++) {
        if (XATOI(arg + optLen + 1) == bits[i]) {
            *mask |= (1 << i);
            return 1;
        }
    }
    printf("Warning: unsupported level for %s: %s\n", opt, arg + optLen + 1);
    (void)vals;
    return 1;
}
#endif

/******************************************************************************/
/* --- BEGIN Bench Wrapper -- */
/******************************************************************************/
int TPM2_Wrapper_Bench(void* userCtx)
{
    return TPM2_Wrapper_BenchArgs(userCtx, 0, NULL);
}

int TPM2_Wrapper_BenchArgs(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storageKey;
    WOLFTPM2_KEY rsaKey;
    WOLFTPM2_KEY eccKey;
    WOLFTPM2_BUFFER message;
    WOLFTPM2_BUFFER cipher;
    WOLFTPM2_BUFFER plain;
    TPMT_PUBLIC publicTemplate;
    TPM2B_ECC_POINT pubPoint;
    double start;
    int count;
    int skipDec = 0; /* skip a decrypt op whose paired encrypt was unsupported */
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    WOLFTPM2_SESSION tpmSession;
    double maxDuration = TPM2_BENCH_DURATION_SEC;
    double maxKeyGenDurSec = TPM2_BENCH_DURATION_KEYGEN_SEC;
#if defined(WOLFTPM_MLDSA) || defined(WOLFTPM_HASH_MLDSA) || \
    defined(WOLFTPM_MLKEM)
    static const int mldsaSets[3] = { TPM_MLDSA_44, TPM_MLDSA_65,
        TPM_MLDSA_87 };
    static const int mldsaLvls[3] = { 44, 65, 87 };
    static const int mlkemSets[3] = { TPM_MLKEM_512, TPM_MLKEM_768,
        TPM_MLKEM_1024 };
    static const int mlkemLvls[3] = { 512, 768, 1024 };
    int mldsaMask = 0, hashMldsaMask = 0, mlkemMask = 0;
    int i;
#endif

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else if (XSTRCMP(argv[argc-1], "--md") == 0) {
            gMarkdown = 1;
        }
        else if (XSTRNCMP(argv[argc-1], "-maxdur=", XSTRLEN("-maxdur=")) == 0) {
            const char* maxStr = argv[argc-1] + XSTRLEN("-maxdur=");
            maxKeyGenDurSec = maxDuration = XATOI(maxStr) / 1000.0;
        }
#if defined(WOLFTPM_MLDSA) || defined(WOLFTPM_HASH_MLDSA) || \
    defined(WOLFTPM_MLKEM)
        else if (pqc_select(argv[argc-1], "--mldsa", &mldsaMask, mldsaSets,
                mldsaLvls, 3)) {
        }
        else if (pqc_select(argv[argc-1], "--hash-mldsa", &hashMldsaMask,
                mldsaSets, mldsaLvls, 3)) {
        }
        else if (pqc_select(argv[argc-1], "--mlkem", &mlkemMask, mlkemSets,
                mlkemLvls, 3)) {
        }
#endif
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

#if defined(WOLFTPM_MLDSA) || defined(WOLFTPM_HASH_MLDSA) || \
    defined(WOLFTPM_MLKEM)
    /* No PQC level requested means benchmark every level. */
    if (mldsaMask == 0 && hashMldsaMask == 0 && mlkemMask == 0) {
        mldsaMask = hashMldsaMask = mlkemMask = 0x7;
    }
#endif

    XMEMSET(&storageKey, 0, sizeof(storageKey));
    XMEMSET(&eccKey, 0, sizeof(eccKey));
    XMEMSET(&rsaKey, 0, sizeof(rsaKey));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));


    printf("TPM2 Benchmark using Wrapper API's\n");
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) {
        printf("wolfTPM2_Init failed\n");
        return rc;
    }

    /* See if primary storage key already exists */
    rc = getPrimaryStoragekey(&dev, &storageKey, TPM_ALG_RSA);
    if (rc != 0) goto exit;

    if (paramEncAlg != TPM_ALG_NULL) {
        WOLFTPM2_KEY* bindKey = &storageKey;
    #ifdef NO_RSA
        bindKey = NULL; /* cannot bind to key without RSA enabled */
    #endif
        /* Start an authenticated session (salted / unbound) with parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, bindKey, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the storage key */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    /* RNG Benchmark */
    bench_stats_start(&count, &start);
    do {
        rc = wolfTPM2_GetRandom(&dev, message.buffer, sizeof(message.buffer));
        if (rc != 0) goto exit;
    } while (bench_stats_check(start, &count, maxDuration));
    bench_stats_sym_finish("RNG", count, sizeof(message.buffer), start);

    /* AES Benchmarks */
    /* AES CBC */
    rc = bench_sym_aes(&dev, &storageKey, "AES-128-CBC-enc", TPM_ALG_CBC, 128,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_ENCRYPT, maxDuration);
    if (rc != 0 && !bench_unsupported(rc)) goto exit;
    rc = bench_sym_aes(&dev, &storageKey, "AES-128-CBC-dec", TPM_ALG_CBC, 128,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_DECRYPT, maxDuration);
    if (rc != 0 && !bench_unsupported(rc)) goto exit;
    rc = bench_sym_aes(&dev, &storageKey, "AES-256-CBC-enc", TPM_ALG_CBC, 256,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_ENCRYPT, maxDuration);
    if (rc != 0 && !bench_unsupported(rc)) goto exit;
    rc = bench_sym_aes(&dev, &storageKey, "AES-256-CBC-dec", TPM_ALG_CBC, 256,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_DECRYPT, maxDuration);
    if (rc != 0 && !bench_unsupported(rc)) goto exit;

    /* AES CTR */
    rc = bench_sym_aes(&dev, &storageKey, "AES-128-CTR-enc", TPM_ALG_CTR, 128,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_ENCRYPT, maxDuration);
    if (rc != 0 && !bench_unsupported(rc)) goto exit;
    rc = bench_sym_aes(&dev, &storageKey, "AES-128-CTR-dec", TPM_ALG_CTR, 128,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_DECRYPT, maxDuration);
    if (rc != 0 && !bench_unsupported(rc)) goto exit;
    rc = bench_sym_aes(&dev, &storageKey, "AES-256-CTR-enc", TPM_ALG_CTR, 256,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_ENCRYPT, maxDuration);
    if (rc != 0 && !bench_unsupported(rc)) goto exit;
    rc = bench_sym_aes(&dev, &storageKey, "AES-256-CTR-dec", TPM_ALG_CTR, 256,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_DECRYPT, maxDuration);
    if (rc != 0 && !bench_unsupported(rc)) goto exit;

    /* AES CFB */
    rc = bench_sym_aes(&dev, &storageKey, "AES-128-CFB-enc", TPM_ALG_CFB, 128,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_ENCRYPT, maxDuration);
    if (rc != 0 && !bench_unsupported(rc)) goto exit;
    rc = bench_sym_aes(&dev, &storageKey, "AES-128-CFB-dec", TPM_ALG_CFB, 128,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_DECRYPT, maxDuration);
    if (rc != 0 && !bench_unsupported(rc)) goto exit;
    rc = bench_sym_aes(&dev, &storageKey, "AES-256-CFB-enc", TPM_ALG_CFB, 256,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_ENCRYPT, maxDuration);
    if (rc != 0 && !bench_unsupported(rc)) goto exit;
    rc = bench_sym_aes(&dev, &storageKey, "AES-256-CFB-dec", TPM_ALG_CFB, 256,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_DECRYPT, maxDuration);
    if (rc != 0 && !bench_unsupported(rc)) goto exit;

    /* Hashing Benchmarks */
    /* SHA1 */
    rc = bench_sym_hash(&dev, "SHA1", TPM_ALG_SHA1, message.buffer,
        sizeof(message.buffer), cipher.buffer, TPM_SHA_DIGEST_SIZE, maxDuration);
    if (rc != 0 && (rc & TPM_RC_HASH) != TPM_RC_HASH) goto exit;
    /* SHA256 */
    rc = bench_sym_hash(&dev, "SHA256", TPM_ALG_SHA256, message.buffer,
        sizeof(message.buffer), cipher.buffer, TPM_SHA256_DIGEST_SIZE, maxDuration);
    if (rc != 0 && (rc & TPM_RC_HASH) != TPM_RC_HASH) goto exit;
    /* SHA384 */
    rc = bench_sym_hash(&dev, "SHA384", TPM_ALG_SHA384, message.buffer,
        sizeof(message.buffer), cipher.buffer, TPM_SHA384_DIGEST_SIZE, maxDuration);
    if (rc != 0 && (rc & TPM_RC_HASH) != TPM_RC_HASH) goto exit;
    /* SHA512 */
    rc = bench_sym_hash(&dev, "SHA512", TPM_ALG_SHA512, message.buffer,
        sizeof(message.buffer), cipher.buffer, TPM_SHA512_DIGEST_SIZE, maxDuration);
    if (rc != 0 && (rc & TPM_RC_HASH) != TPM_RC_HASH) goto exit;


    /* Create RSA key for encrypt/decrypt */
    rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
    if (rc != 0) goto exit;
    bench_stats_start(&count, &start);
    do {
        if (count > 0) {
            rc = wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
            if (rc != 0) goto exit;
        }
        rc = wolfTPM2_CreateAndLoadKey(&dev, &rsaKey, &storageKey.handle,
            &publicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
        if (rc != 0) goto exit;
    } while (bench_stats_check(start, &count, maxKeyGenDurSec));
    bench_stats_asym_finish("RSA", 2048, "key gen", count, start);

    /* Perform RSA encrypt / decrypt (no pad) */
    message.size = 256; /* test message 0x11,0x11,etc */
    XMEMSET(message.buffer, 0x11, message.size);

    bench_stats_start(&count, &start);
    do {
        cipher.size = sizeof(cipher.buffer); /* encrypted data */
        rc = wolfTPM2_RsaEncrypt(&dev, &rsaKey, TPM_ALG_NULL,
            message.buffer, message.size, cipher.buffer, &cipher.size);
        if (rc != 0) break;
    } while (bench_stats_check(start, &count, maxDuration));
    skipDec = (rc != 0 && bench_unsupported(rc));
    rc = bench_asym_done("RSA", 2048, "Public", count, start, rc);
    if (rc != 0) goto exit;

    if (skipDec) {
        printf("%-6s %5d %-9s Skipped (not supported)\n", "RSA", 2048, "Private");
    }
    else {
        bench_stats_start(&count, &start);
        do {
            plain.size = sizeof(plain.buffer);
            rc = wolfTPM2_RsaDecrypt(&dev, &rsaKey, TPM_ALG_NULL,
                cipher.buffer, cipher.size, plain.buffer, &plain.size);
            if (rc != 0) break;
        } while (bench_stats_check(start, &count, maxDuration));
        rc = bench_asym_done("RSA", 2048, "Private", count, start, rc);
        if (rc != 0) goto exit;
    }


    /* Perform RSA encrypt / decrypt (OAEP pad) */
    message.size = TPM_SHA256_DIGEST_SIZE; /* test message 0x11,0x11,etc */
    XMEMSET(message.buffer, 0x11, message.size);

    bench_stats_start(&count, &start);
    do {
        cipher.size = sizeof(cipher.buffer); /* encrypted data */
        rc = wolfTPM2_RsaEncrypt(&dev, &rsaKey, TPM_ALG_OAEP,
            message.buffer, message.size, cipher.buffer, &cipher.size);
        if (rc != 0) break;
    } while (bench_stats_check(start, &count, maxDuration));
    skipDec = (rc != 0 && bench_unsupported(rc));
    rc = bench_asym_done("RSA", 2048, "Pub  OAEP", count, start, rc);
    if (rc != 0) goto exit;

    if (skipDec) {
        printf("%-6s %5d %-9s Skipped (not supported)\n", "RSA", 2048,
            "Priv OAEP");
    }
    else {
        bench_stats_start(&count, &start);
        do {
            plain.size = sizeof(plain.buffer);
            rc = wolfTPM2_RsaDecrypt(&dev, &rsaKey, TPM_ALG_OAEP,
                cipher.buffer, cipher.size, plain.buffer, &plain.size);
            if (rc != 0) break;
        } while (bench_stats_check(start, &count, maxDuration));
        rc = bench_asym_done("RSA", 2048, "Priv OAEP", count, start, rc);
        if (rc != 0) goto exit;
    }

    rc = wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    if (rc != 0) goto exit;


    /* Create an ECC key for ECDSA */
    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
        TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
    if (rc != 0) goto exit;
    bench_stats_start(&count, &start);
    do {
        if (count > 0) {
            rc = wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
            if (rc != 0) goto exit;
        }
        rc = wolfTPM2_CreateAndLoadKey(&dev, &eccKey, &storageKey.handle,
            &publicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
        if (rc != 0) goto exit;
    } while (bench_stats_check(start, &count, maxDuration));
    bench_stats_asym_finish("ECC", 256, "key gen", count, start);

    /* Perform sign / verify */
    message.size = TPM_SHA256_DIGEST_SIZE; /* test message 0x11,0x11,etc */
    XMEMSET(message.buffer, 0x11, message.size);

    bench_stats_start(&count, &start);
    do {
        cipher.size = sizeof(cipher.buffer); /* signature */
        rc = wolfTPM2_SignHash(&dev, &eccKey, message.buffer, message.size,
            cipher.buffer, &cipher.size);
        if (rc != 0) break;
    } while (bench_stats_check(start, &count, maxDuration));
    rc = bench_asym_done("ECDSA", 256, "sign", count, start, rc);
    if (rc != 0) goto exit;

    bench_stats_start(&count, &start);
    do {
        rc = wolfTPM2_VerifyHash(&dev, &eccKey, cipher.buffer, cipher.size,
            message.buffer, message.size);
        if (rc != 0) break;
    } while (bench_stats_check(start, &count, maxDuration));
    rc = bench_asym_done("ECDSA", 256, "verify", count, start, rc);
    if (rc != 0) goto exit;

    rc = wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    if (rc != 0) goto exit;


    /* Create an ECC key for ECDH */
    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA,
        TPM_ECC_NIST_P256, TPM_ALG_ECDH);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreateAndLoadKey(&dev, &eccKey, &storageKey.handle,
        &publicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
    if (rc != 0) goto exit;

    /* Create ephemeral ECC key and generate a shared secret */
    bench_stats_start(&count, &start);
    do {
        cipher.size = sizeof(cipher.buffer);
        rc = wolfTPM2_ECDHGen(&dev, &eccKey, &pubPoint,
            cipher.buffer, &cipher.size);
        if (rc != 0) break;
    } while (bench_stats_check(start, &count, maxDuration));
    rc = bench_asym_done("ECDHE", 256, "agree", count, start, rc);
    if (rc != 0) goto exit;

    rc = wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    if (rc != 0) goto exit;

#if defined(WOLFTPM_MLDSA) || defined(WOLFTPM_MLKEM) || \
    defined(WOLFTPM_HASH_MLDSA)
    /* Post-quantum (TPM 2.0 v1.85). Skipped under parameter encryption: the
     * large PQC public-key responses exceed the parameter-decryption buffer
     * (TPM_RC_... BUFFER_E). Free the storage key first so the larger PQC keys
     * fit within the TPM's transient object slots. */
    if (paramEncAlg == TPM_ALG_NULL) {
        wolfTPM2_UnloadHandle(&dev, &storageKey.handle);
    #ifdef WOLFTPM_MLDSA
        for (i = 0; i < 3; i++) {
            if ((mldsaMask & (1 << i)) == 0) continue;
            rc = bench_pqc_mldsa(&dev, maxDuration, maxKeyGenDurSec,
                mldsaSets[i]);
            if (rc != 0)
                rc = bench_pqc_failed("ML-DSA", mldsaLvls[i], rc);
            if (rc != 0) goto exit;
        }
    #endif
    #ifdef WOLFTPM_HASH_MLDSA
        for (i = 0; i < 3; i++) {
            if ((hashMldsaMask & (1 << i)) == 0) continue;
            rc = bench_pqc_hash_mldsa(&dev, maxDuration, maxKeyGenDurSec,
                mldsaSets[i]);
            if (rc != 0)
                rc = bench_pqc_failed("HMLDSA", mldsaLvls[i], rc);
            if (rc != 0) goto exit;
        }
    #endif
    #ifdef WOLFTPM_MLKEM
        for (i = 0; i < 3; i++) {
            if ((mlkemMask & (1 << i)) == 0) continue;
            rc = bench_pqc_mlkem(&dev, maxDuration, maxKeyGenDurSec,
                mlkemSets[i]);
            if (rc != 0)
                rc = bench_pqc_failed("ML-KEM", mlkemLvls[i], rc);
            if (rc != 0) goto exit;
        }
    #endif
    }
#endif

exit:
    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Cleanup all handles */
    wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    wolfTPM2_UnloadHandle(&dev, &storageKey.handle);

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END Bench Wrapper -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER && !NO_TPM_BENCH */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(NO_TPM_BENCH)
    rc = TPM2_Wrapper_BenchArgs(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
