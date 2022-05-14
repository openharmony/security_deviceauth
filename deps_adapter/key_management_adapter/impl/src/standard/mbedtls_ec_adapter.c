/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mbedtls_ec_adapter.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509.h>

#include "hal_error.h"
#include "hc_log.h"
#include "huks_adapter.h"

#define LOG_AND_RETURN_IF_MBED_FAIL(ret, fmt, ...) \
do { \
    if ((ret) != 0) { \
        LOGE(fmt, ##__VA_ARGS__); \
        return HAL_ERR_MBEDTLS; \
    } \
} while (0)

#define LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, fmt, ...) \
do { \
    if ((ret) != 0) { \
        LOGE(fmt, ##__VA_ARGS__); \
        goto CLEAN_UP; \
    } \
} while (0)

#define BITS_PER_BYTE 8
#define EC_LEN 64
#define SHA256_HASH_LEN 32
#define P256_KEY_SIZE 32
#define P256_PUBLIC_SIZE 64 // P256_KEY_SIZE * 2

typedef struct Blob {
    uint32_t dataSize;
    uint8_t *data;
} Blob;

static const uint8_t g_pointA[] = {
    0x04, 0x53, 0xf9, 0xe4, 0xf4, 0xbc, 0x3a, 0xb5, 0x9d, 0x44, 0x78, 0x45, 0x21, 0x13, 0x8b, 0x49,
    0xba, 0xa3, 0x1c, 0xe2, 0xa8, 0xdb, 0xbd, 0xb8, 0xd6, 0x73, 0x31, 0x46, 0x3a, 0x69, 0x53, 0xf1,
    0xed, 0xef, 0x96, 0x1e, 0xdb, 0x42, 0xbe, 0x3a, 0x24, 0x43, 0xc4, 0x08, 0x23, 0xfb, 0x58, 0xee,
    0x61, 0x24, 0x8b, 0x59, 0x64, 0x65, 0x2d, 0xbc, 0x6b, 0xa5, 0x1d, 0x6e, 0x04, 0x22, 0x53, 0xae,
    0x27
};
static const uint8_t g_pointB[] = {
    0x04, 0x03, 0x4d, 0x11, 0x11, 0xa6, 0x3f, 0x5f, 0x72, 0x43, 0x59, 0x73, 0x8b, 0x46, 0xc3, 0xfd,
    0x70, 0x58, 0xb0, 0xb6, 0x11, 0xd3, 0x4f, 0xf3, 0x49, 0xa0, 0xd2, 0x86, 0xd7, 0x35, 0x33, 0xc5,
    0x36, 0xe4, 0x99, 0xcc, 0x13, 0x47, 0xe4, 0xab, 0xde, 0x8f, 0x3a, 0xd6, 0x65, 0x1a, 0x77, 0x0b,
    0xc4, 0x82, 0xd5, 0xac, 0x4b, 0x5d, 0xe4, 0xcc, 0x48, 0xb0, 0x54, 0x6c, 0x9b, 0x76, 0x76, 0x1a,
    0xba
};

static const uint8_t g_randomSeedCustom[] = { 0x4C, 0x54, 0x4B, 0x53 }; // LTKS means LiteKeystore

static bool IsInvalidBlob(const Blob *blob)
{
    return (blob == NULL) || (blob->data == NULL) || (blob->dataSize == 0);
}

static void InitPointParams(mbedtls_mpi *scalarA, mbedtls_mpi *scalarB, mbedtls_ecp_point *pointA,
    mbedtls_ecp_point *pointB, mbedtls_ecp_point *result)
{
    mbedtls_mpi_init(scalarA);
    mbedtls_mpi_init(scalarB);
    mbedtls_ecp_point_init(pointA);
    mbedtls_ecp_point_init(pointB);
    mbedtls_ecp_point_init(result);
}

static void FreePointParams(mbedtls_mpi *scalarA, mbedtls_mpi *scalarB, mbedtls_ecp_point *pointA,
    mbedtls_ecp_point *pointB, mbedtls_ecp_point *result)
{
    mbedtls_mpi_free(scalarA);
    mbedtls_mpi_free(scalarB);
    mbedtls_ecp_point_free(pointA);
    mbedtls_ecp_point_free(pointB);
    mbedtls_ecp_point_free(result);
}

static int32_t CalculateMessageDigest(mbedtls_md_type_t type, const Blob *input, Blob *output)
{
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(type);
    if (info == NULL) {
        return HAL_ERR_NOT_SUPPORTED;
    }

    uint32_t outSize = mbedtls_md_get_size(info);
    if (output->dataSize < outSize) {
        return HAL_ERR_SHORT_BUFFER;
    }

    int32_t ret = mbedtls_md(info, input->data, input->dataSize, output->data);
    LOG_AND_RETURN_IF_MBED_FAIL(ret, "Calculate message digest failed.\n");

    output->dataSize = outSize;
    return HAL_SUCCESS;
}

static int32_t Sha256(const Blob *input, Blob *output)
{
    if (IsInvalidBlob(input) || IsInvalidBlob(output)) {
        LOGE("Input params for sha256 is invalid.");
        return HAL_ERR_INVALID_PARAM;
    }
    return CalculateMessageDigest(MBEDTLS_MD_SHA256, input, output);
}

static int32_t ReadBigNums(mbedtls_mpi *x, mbedtls_mpi *y, const Blob *blob)
{
    int32_t ret = mbedtls_mpi_read_binary(x, blob->data, P256_KEY_SIZE);
    LOG_AND_RETURN_IF_MBED_FAIL(ret, "Read x coordinate of public key failed.");
    ret = mbedtls_mpi_read_binary(y, blob->data + P256_KEY_SIZE, P256_KEY_SIZE);
    LOG_AND_RETURN_IF_MBED_FAIL(ret, "Read y coordinate of public key failed.");
    return HAL_SUCCESS;
}

static int32_t ReadEcPublicKey(mbedtls_ecp_point *point, const Blob *publicKey)
{
    int32_t ret = ReadBigNums(&point->X, &point->Y, publicKey);
    LOG_AND_RETURN_IF_MBED_FAIL(ret, "Read coordinate of public key failed.");
    ret = mbedtls_mpi_lset(&point->Z, 1);
    LOG_AND_RETURN_IF_MBED_FAIL(ret, "Lset point z failed.");
    return HAL_SUCCESS;
}

static int32_t WriteOutBigNums(const mbedtls_mpi *x, const mbedtls_mpi *y, Blob *out)
{
    int32_t ret = mbedtls_mpi_write_binary(x, out->data, P256_KEY_SIZE);
    LOG_AND_RETURN_IF_MBED_FAIL(ret, "Write x coordinate of public key failed.");

    ret = mbedtls_mpi_write_binary(y, out->data + P256_KEY_SIZE, P256_KEY_SIZE);
    LOG_AND_RETURN_IF_MBED_FAIL(ret, "Write y coordinate of public key failed.");

    out->dataSize = P256_PUBLIC_SIZE;
    return HAL_SUCCESS;
}

static int32_t WriteOutEcPublicKey(const mbedtls_ecp_point *point, Blob *publicKey)
{
    return WriteOutBigNums(&point->X, &point->Y, publicKey);
}

static int32_t EcKeyAgreement(const Blob *privateKey, const Blob *publicKey, Blob *secretKey)
{
    if (IsInvalidBlob(publicKey) || publicKey->dataSize != P256_PUBLIC_SIZE || IsInvalidBlob(secretKey) ||
        secretKey->dataSize != P256_PUBLIC_SIZE || IsInvalidBlob(privateKey)) {
        LOGE("Input params for ec key agree is invalid.");
        return HAL_ERR_INVALID_PARAM;
    }
    mbedtls_mpi *secret = HcMalloc(sizeof(mbedtls_mpi), 0);
    mbedtls_ecp_keypair *keyPair = HcMalloc(sizeof(mbedtls_ecp_keypair), 0);
    mbedtls_entropy_context *entropy = HcMalloc(sizeof(mbedtls_entropy_context), 0);
    mbedtls_ctr_drbg_context *ctrDrbg = HcMalloc(sizeof(mbedtls_ctr_drbg_context), 0);
    if ((secret == NULL) || (keyPair == NULL) || (entropy == NULL) || (ctrDrbg == NULL)) {
        LOGE("Malloc for mbedtls ec key param failed.");
        HcFree(secret);
        HcFree(keyPair);
        HcFree(entropy);
        HcFree(ctrDrbg);
        return HAL_ERR_BAD_ALLOC;
    }
    mbedtls_mpi_init(secret);
    mbedtls_ecp_keypair_init(keyPair);
    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(ctrDrbg);
    mbedtls_ecp_point P;
    mbedtls_ecp_point_init(&P);
    int32_t ret = ReadEcPublicKey(&keyPair->Q, publicKey);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Read the public key failed.\n");
    ret = mbedtls_ecp_group_load(&keyPair->grp, MBEDTLS_ECP_DP_SECP256R1);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Load the ecp group failed.\n");
    ret = mbedtls_mpi_read_binary(&keyPair->d, privateKey->data, privateKey->dataSize);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Read the private key failed.\n");
    ret = mbedtls_ctr_drbg_seed(ctrDrbg, mbedtls_entropy_func, entropy,
        g_randomSeedCustom, sizeof(g_randomSeedCustom));
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Set custom string failed.\n");
    LOG_AND_GOTO_CLEANUP_IF_FAIL(mbedtls_ecp_mul_restartable(&keyPair->grp, &P, &keyPair->d, &keyPair->Q,
        mbedtls_ctr_drbg_random, ctrDrbg, NULL), "Compute secret key failed.\n");
    LOG_AND_GOTO_CLEANUP_IF_FAIL(mbedtls_mpi_copy(secret, &P.X), "Copy secret failed.\n");
    LOG_AND_GOTO_CLEANUP_IF_FAIL(WriteOutEcPublicKey(&P, secretKey), "Write out ec public key failed.\n");
CLEAN_UP:
    mbedtls_mpi_free(secret);
    mbedtls_ecp_keypair_free(keyPair);
    mbedtls_entropy_free(entropy);
    mbedtls_ctr_drbg_free(ctrDrbg);
    mbedtls_ecp_point_free(&P);
    HcFree(secret);
    HcFree(keyPair);
    HcFree(entropy);
    HcFree(ctrDrbg);
    LOG_AND_RETURN_IF_MBED_FAIL(ret, "Ec key agree failed.");
    return HAL_SUCCESS;
}

static int32_t EcHashToPoint(const Blob *hash, Blob *point)
{
    if (IsInvalidBlob(hash) || IsInvalidBlob(point)) {
        return HAL_ERR_INVALID_PARAM;
    }

    if (point->dataSize < P256_PUBLIC_SIZE) {
        return HAL_ERR_SHORT_BUFFER;
    }

    mbedtls_mpi scalarA;
    mbedtls_mpi scalarB;
    mbedtls_ecp_point pointA;
    mbedtls_ecp_point pointB;
    mbedtls_ecp_point result;
    InitPointParams(&scalarA, &scalarB, &pointA, &pointB, &result);

    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    uint8_t digest[SHA256_HASH_LEN] = { 0 };
    Blob digestBlob = { sizeof(digest), digest };

    int32_t ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Load ecp group failed.\n");
    ret = mbedtls_ecp_point_read_binary(&grp, &pointA, g_pointA, sizeof(g_pointA));
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Read point A failed.\n");
    ret = mbedtls_ecp_point_read_binary(&grp, &pointB, g_pointB, sizeof(g_pointB));
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Read point B failed.\n");
    ret = Sha256(hash, &digestBlob);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Compute message digest failed.\n");
    ret = mbedtls_mpi_lset(&scalarA, 1);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Set number one failed.\n");
    ret = mbedtls_mpi_read_binary(&scalarB, digest, SHA256_HASH_LEN);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Read digest failed.\n");
    ret = mbedtls_ecp_muladd(&grp, &result, &scalarA, &pointA, &scalarB, &pointB);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Double-scalar multiplication failed.\n");
    ret = mbedtls_ecp_check_pubkey(&grp, &result);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Invalid point on P256 is returned.\n");
    ret = WriteOutEcPublicKey(&result, point);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Write out public key failed.\n");
CLEAN_UP:
    FreePointParams(&scalarA, &scalarB, &pointA, &pointB, &result);
    mbedtls_ecp_group_free(&grp);
    LOG_AND_RETURN_IF_MBED_FAIL(ret, "Ec hash to point failed.");
    return HAL_SUCCESS;
}

// only support P256 HashToPoint for standard system
int32_t MbedtlsHashToPoint(const Uint8Buff *hash, Uint8Buff *outEcPoint)
{
    CHECK_PTR_RETURN_HAL_ERROR_CODE(hash, "hash");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(hash->val, "hash->val");
    CHECK_LEN_EQUAL_RETURN(hash->length, SHA256_LEN, "hash->length");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(outEcPoint, "outEcPoint");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(outEcPoint->val, "outEcPoint->val");
    CHECK_LEN_EQUAL_RETURN(outEcPoint->length, EC_LEN, "outEcPoint->length");

    struct Blob hashBlob = {
        .dataSize = hash->length,
        .data = hash->val
    };
    struct Blob pointBlob = {
        .dataSize = outEcPoint->length,
        .data = outEcPoint->val
    };

    int32_t ret = EcHashToPoint(&hashBlob, &pointBlob);
    if (ret != 0 || pointBlob.dataSize != EC_LEN) {
        LOGE("HashToPoint with mbedtls for P256 failed, ret: %d", ret);
        return HAL_FAILED;
    }

    return HAL_SUCCESS;
}

// only support P256 AgreeSharedSecret for standard system
int32_t MbedtlsAgreeSharedSecret(const KeyBuff *priKey, const KeyBuff *pubKey, Uint8Buff *sharedKey)
{
    CHECK_PTR_RETURN_HAL_ERROR_CODE(priKey, "priKey");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(priKey->key, "priKey->key");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(priKey->keyLen, "priKey->keyLen");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(pubKey, "devicePk");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(pubKey->key, "devicePk->key");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(pubKey->keyLen, "devicePk->keyLen");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(sharedKey, "sharedKey");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(sharedKey->val, "sharedKey->val");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(sharedKey->length, "sharedKey->length");

    struct Blob priKeyBlob = {
        .dataSize = priKey->keyLen,
        .data = priKey->key
    };
    struct Blob pubKeyBlob = {
        .dataSize = pubKey->keyLen,
        .data = pubKey->key
    };
    struct Blob sharedKeyBlob = {
        .dataSize = sharedKey->length,
        .data = sharedKey->val
    };
    int32_t ret = EcKeyAgreement(&priKeyBlob, &pubKeyBlob, &sharedKeyBlob);
    if (ret != 0) {
        LOGE("Agree key failed, ret = %d", ret);
        return HAL_FAILED;
    }
    return HAL_SUCCESS;
}
