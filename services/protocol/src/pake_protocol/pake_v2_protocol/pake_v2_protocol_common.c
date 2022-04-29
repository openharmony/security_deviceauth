/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "pake_v2_protocol_common.h"
#include "alg_loader.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_types.h"
#include "pake_defs.h"
#include "pake_protocol_dl_common.h"
#include "pake_protocol_ec_common.h"
#include "protocol_common.h"
#include "string_util.h"

#define KCF_CODE_LEN 1
#define PAKE_SESSION_KEY_LEN 32

static const uint8_t g_kcfCodeClient[KCF_CODE_LEN] = { 0x04 };
static const uint8_t g_kcfCodeServer[KCF_CODE_LEN] = { 0x03 };

void DestroyPakeV2BaseParams(PakeBaseParams *params)
{
    if (params == NULL) {
        return;
    }

    CleanPakeSensitiveKeys(params);

    HcFree(params->salt.val);
    params->salt.val = NULL;

    HcFree(params->challengeSelf.val);
    params->challengeSelf.val = NULL;

    HcFree(params->challengePeer.val);
    params->challengePeer.val = NULL;

    HcFree(params->epkSelf.val);
    params->epkSelf.val = NULL;

    HcFree(params->epkPeer.val);
    params->epkPeer.val = NULL;

    HcFree(params->idSelf.val);
    params->idSelf.val = NULL;

    HcFree(params->idPeer.val);
    params->idPeer.val = NULL;

    HcFree(params->kcfData.val);
    params->kcfData.val = NULL;

    HcFree(params->kcfDataPeer.val);
    params->kcfDataPeer.val = NULL;
}

static int32_t AllocDefaultParams(PakeBaseParams *params)
{
    params->salt.length = PAKE_SALT_LEN;
    params->salt.val = (uint8_t *)HcMalloc(params->salt.length, 0);
    if (params->salt.val == NULL) {
        LOGE("Malloc for salt failed.");
        return HC_ERR_ALLOC_MEMORY;
    }

    params->sharedSecret.length = SHA256_LEN;
    params->sharedSecret.val = (uint8_t *)HcMalloc(params->sharedSecret.length, 0);
    if (params->sharedSecret.val == NULL) {
        LOGE("Malloc for sharedSecret failed.");
        return HC_ERR_ALLOC_MEMORY;
    }

    params->sessionKey.length = PAKE_SESSION_KEY_LEN;
    params->sessionKey.val = (uint8_t *)HcMalloc(params->sessionKey.length, 0);
    if (params->sessionKey.val == NULL) {
        LOGE("Malloc for sessionKey failed.");
        return HC_ERR_ALLOC_MEMORY;
    }

    params->kcfData.length = HMAC_LEN;
    params->kcfData.val = (uint8_t *)HcMalloc(params->kcfData.length, 0);
    if (params->kcfData.val == NULL) {
        LOGE("Malloc for kcfData failed.");
        return HC_ERR_ALLOC_MEMORY;
    }

    params->kcfDataPeer.length = HMAC_LEN;
    params->kcfDataPeer.val = (uint8_t *)HcMalloc(params->kcfDataPeer.length, 0);
    if (params->kcfDataPeer.val == NULL) {
        LOGE("Malloc for kcfDataPeer failed.");
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static void FillDefaultValue(PakeBaseParams *params)
{
    params->psk.val = NULL;
    params->psk.length = 0;
    params->challengeSelf.val = NULL;
    params->challengeSelf.length = 0;
    params->challengePeer.val = NULL;
    params->challengePeer.length = 0;
    params->eskSelf.val = NULL;
    params->eskSelf.length = 0;
    params->epkSelf.val = NULL;
    params->epkSelf.length = 0;
    params->epkPeer.val = NULL;
    params->epkPeer.length = 0;
    params->base.val = NULL;
    params->base.length = 0;
    params->idSelf.val = NULL;
    params->idSelf.length = 0;
    params->idPeer.val = NULL;
    params->idPeer.length = 0;
    params->hmacKey.val = NULL;
    params->hmacKey.length = 0;
    params->supportedDlPrimeMod = DL_PRIME_MOD_NONE;
    params->largePrimeNumHex = NULL;
    params->innerKeyLen = 0;
    params->supportedPakeAlg = PAKE_ALG_NONE;
    params->curveType = CURVE_NONE;
    params->isClient = true;
}

int32_t InitPakeV2BaseParams(PakeBaseParams *params)
{
    if (params == NULL) {
        LOGE("Params is null.");
        return HC_ERR_NULL_PTR;
    }

    int32_t res = AllocDefaultParams(params);
    if (res != HC_SUCCESS) {
        goto CLEAN_UP;
    }

    FillDefaultValue(params);

    params->loader = GetLoaderInstance();
    if (params->loader == NULL) {
        res = HC_ERROR;
        goto CLEAN_UP;
    }

    return HC_SUCCESS;
CLEAN_UP:
    DestroyPakeV2BaseParams(params);
    return res;
}

static int32_t GeneratePakeParams(PakeBaseParams *params)
{
    int32_t res;
    uint8_t secretVal[PAKE_SECRET_LEN] = { 0 };
    Uint8Buff secret = { secretVal, PAKE_SECRET_LEN };
    if (!params->isClient) {
        res = params->loader->generateRandom(&(params->salt));
        if (res != HC_SUCCESS) {
            LOGE("Generate salt failed, res: %x.", res);
            goto CLEAN_UP;
        }
    }

    Uint8Buff keyInfo = { (uint8_t *)HICHAIN_SPEKE_BASE_INFO, HcStrlen(HICHAIN_SPEKE_BASE_INFO) };
    res = params->loader->computeHkdf(&(params->psk), &(params->salt), &keyInfo, &secret, false);
    if (res != HC_SUCCESS) {
        LOGE("Derive secret from psk failed, res: %x.", res);
        goto CLEAN_UP;
    }
    FreeAndCleanKey(&params->psk);

    if (((uint32_t)params->supportedPakeAlg & PAKE_ALG_EC) != 0) {
        res = GenerateEcPakeParams(params, &secret);
    } else if (((uint32_t)params->supportedPakeAlg & PAKE_ALG_DL) != 0) {
        res = GenerateDlPakeParams(params, &secret);
    } else {
        res = HC_ERR_INVALID_ALG;
    }
    if (res != HC_SUCCESS) {
        LOGE("GeneratePakeParams failed, pakeAlgType: 0x%x, res: 0x%x.", params->supportedPakeAlg, res);
        goto CLEAN_UP;
    }
    (void)memset_s(secret.val, secret.length, 0, secret.length);
    return res;
CLEAN_UP:
    (void)memset_s(secret.val, secret.length, 0, secret.length);
    CleanPakeSensitiveKeys(params);
    return res;
}

static int32_t ComputeSidSelf(const PakeBaseParams *params, Uint8Buff *sidSelf)
{
    int res;
    Uint8Buff idSelfMsg = { NULL, params->idSelf.length + params->innerKeyLen };
    idSelfMsg.val = (uint8_t *)HcMalloc(idSelfMsg.length, 0);
    if (idSelfMsg.val == NULL) {
        LOGE("Malloc for idSelfMsg failed.");
        res = HC_ERR_ALLOC_MEMORY;
        goto CLEAN_UP;
    }

    if (memcpy_s(idSelfMsg.val, idSelfMsg.length, params->idSelf.val, params->idSelf.length) != EOK) {
        LOGE("Memcpy for idSelf failed.");
        res = HC_ERR_MEMORY_COPY;
        goto CLEAN_UP;
    }
    if (memcpy_s(idSelfMsg.val + params->idSelf.length, idSelfMsg.length - params->idSelf.length,
        params->epkSelf.val, params->innerKeyLen) != EOK) { // only need x-coordinate
        LOGE("Memcpy for epkSelf failed.");
        res = HC_ERR_MEMORY_COPY;
        goto CLEAN_UP;
    }
    res = params->loader->sha256(&idSelfMsg, sidSelf);
    if (res != HC_SUCCESS) {
        LOGE("Sha256 for idSelfMsg failed, res: %x.", res);
        goto CLEAN_UP;
    }
CLEAN_UP:
    HcFree(idSelfMsg.val);
    return res;
}

static int32_t ComputeSidPeer(const PakeBaseParams *params, Uint8Buff *sidPeer)
{
    int res;
    Uint8Buff idPeerMsg = { NULL, params->idPeer.length + params->innerKeyLen };
    idPeerMsg.val = (uint8_t *)HcMalloc(idPeerMsg.length, 0);
    if (idPeerMsg.val == NULL) {
        LOGE("Malloc for idPeerMsg failed.");
        res = HC_ERR_ALLOC_MEMORY;
        goto CLEAN_UP;
    }

    if (memcpy_s(idPeerMsg.val, idPeerMsg.length, params->idPeer.val, params->idPeer.length) != EOK) {
        LOGE("Memcpy for idPeer failed.");
        res = HC_ERR_MEMORY_COPY;
        goto CLEAN_UP;
    }
    if (memcpy_s(idPeerMsg.val + params->idPeer.length, idPeerMsg.length - params->idPeer.length,
        params->epkPeer.val, params->innerKeyLen) != EOK) { // only need x-coordinate
        LOGE("Memcpy for epkPeer failed.");
        res = HC_ERR_MEMORY_COPY;
        goto CLEAN_UP;
    }
    res = params->loader->sha256(&idPeerMsg, sidPeer);
    if (res != HC_SUCCESS) {
        LOGE("Sha256 for idPeerMsg failed, res: %x.", res);
        goto CLEAN_UP;
    }
CLEAN_UP:
    HcFree(idPeerMsg.val);
    return res;
}

static int32_t ComputeSid(const PakeBaseParams *params, Uint8Buff *sid)
{
    int32_t res = HC_SUCCESS;
    Uint8Buff sidSelf = { NULL, SHA256_LEN };
    Uint8Buff sidPeer = { NULL, SHA256_LEN };

    sidSelf.val = (uint8_t *)HcMalloc(sidSelf.length, 0);
    if (sidSelf.val == NULL) {
        LOGE("Malloc for sidSelf failed.");
        res = HC_ERR_ALLOC_MEMORY;
        goto CLEAN_UP;
    }
    sidPeer.val = (uint8_t *)HcMalloc(sidPeer.length, 0);
    if (sidPeer.val == NULL) {
        LOGE("Malloc for sidPeer failed.");
        res = HC_ERR_ALLOC_MEMORY;
        goto CLEAN_UP;
    }

    res = ComputeSidSelf(params, &sidSelf);
    if (res != HC_SUCCESS) {
        LOGE("ComputeSidSelf failed, res: %x", res);
        goto CLEAN_UP;
    }

    res = ComputeSidPeer(params, &sidPeer);
    if (res != HC_SUCCESS) {
        LOGE("ComputeSidPeer failed, res: %x", res);
        goto CLEAN_UP;
    }

    Uint8Buff *maxId = NULL;
    Uint8Buff *minId = NULL;
    int result = params->loader->bigNumCompare(&sidSelf, &sidPeer);
    if (result <= 0) {
        maxId = &sidSelf;
        minId = &sidPeer;
    } else {
        maxId = &sidPeer;
        minId = &sidSelf;
    }

    if (memcpy_s(sid->val, sid->length, maxId->val, maxId->length) != EOK) {
        LOGE("Memcpy for maxId failed.");
        res = HC_ERR_MEMORY_COPY;
        goto CLEAN_UP;
    }
    if (memcpy_s(sid->val + maxId->length, sid->length - maxId->length, minId->val, minId->length) != EOK) {
        LOGE("Memcpy for minId failed.");
        res = HC_ERR_MEMORY_COPY;
        goto CLEAN_UP;
    }
CLEAN_UP:
    HcFree(sidSelf.val);
    HcFree(sidPeer.val);
    return res;
}

static int32_t ComputeSharedSecret(PakeBaseParams *params, const Uint8Buff *sid, const Uint8Buff *tmpSharedSecret)
{
    int32_t res;
    Uint8Buff sharedSecretMsg = { NULL, 0 };
    sharedSecretMsg.length = sid->length + params->innerKeyLen + HcStrlen(SHARED_SECRET_DERIVED_FACTOR);
    sharedSecretMsg.val = (uint8_t *)HcMalloc(sharedSecretMsg.length, 0);
    if (sharedSecretMsg.val == NULL) {
        LOGE("Malloc for sharedSecretMsg failed.");
        return HC_ERR_ALLOC_MEMORY;
    }

    uint32_t usedLen = 0;
    if (memcpy_s(sharedSecretMsg.val, sharedSecretMsg.length, sid->val, sid->length) != EOK) {
        LOGE("Memcpy for sidHex failed.");
        res = HC_ERR_MEMORY_COPY;
        goto CLEAN_UP;
    }
    usedLen += sid->length;
    if (memcpy_s(sharedSecretMsg.val + usedLen, sharedSecretMsg.length - usedLen,
        tmpSharedSecret->val, params->innerKeyLen) != EOK) { // Only need x-coordinate
        LOGE("Memcpy for tmpSharedSecret failed.");
        res = HC_ERR_MEMORY_COPY;
        goto CLEAN_UP;
    }
    usedLen += params->innerKeyLen;
    if (memcpy_s(sharedSecretMsg.val + usedLen, sharedSecretMsg.length - usedLen,
        SHARED_SECRET_DERIVED_FACTOR, HcStrlen(SHARED_SECRET_DERIVED_FACTOR)) != EOK) {
        LOGE("Memcpy for sharedSecret derived factor failed.");
        res = HC_ERR_MEMORY_COPY;
        goto CLEAN_UP;
    }

    res = params->loader->sha256(&sharedSecretMsg, &params->sharedSecret);
    if (res != HC_SUCCESS) {
        LOGE("Sha256 for sharedSecretMsg failed, res: %x.", res);
        goto CLEAN_UP;
    }
CLEAN_UP:
    FreeAndCleanKey(&sharedSecretMsg);
    return res;
}

/*
 * '|' means joint
 * Z = epkB . eskA
 * A = hash(idA | epkA_X)
 * B = hash(idB | epkB_X)
 * sid = MAX(A, B) | MIN(A, B)
 * sharedSecret = hash(hex(sid) | Z_X | derivedFactor)
 */
static int32_t GenerateSharedSecret(PakeBaseParams *params)
{
    int32_t res;
    Uint8Buff tmpSharedSecret = { NULL, 0 };
    Uint8Buff sid = { NULL, SHA256_LEN * 2 }; // sid is composed of client sid and server sid, so need twice SHA256_LEN
    /* The key of P256 requires both X and Y coordinates values to represent it. */
    tmpSharedSecret.length = (params->curveType == CURVE_256) ? (params->innerKeyLen * 2) : (params->innerKeyLen);
    tmpSharedSecret.val = (uint8_t *)HcMalloc(tmpSharedSecret.length, 0);
    if (tmpSharedSecret.val == NULL) {
        LOGE("Malloc for tmpSharedSecret failed.");
        res = HC_ERR_ALLOC_MEMORY;
        goto CLEAN_UP;
    }
    if (((uint32_t)params->supportedPakeAlg & PAKE_ALG_EC) != 0) {
        res = AgreeEcSharedSecret(params, &tmpSharedSecret);
    } else if (((uint32_t)params->supportedPakeAlg & PAKE_ALG_DL) != 0) {
        res = AgreeDlSharedSecret(params, &tmpSharedSecret);
    } else {
        res = HC_ERR_INVALID_ALG;
    }
    if (res != HC_SUCCESS) {
        LOGE("Agree intermediate sharedSecret failed, pakeAlgType: 0x%x, res: %x.", params->supportedPakeAlg, res);
        goto CLEAN_UP;
    }
    FreeAndCleanKey(&params->eskSelf);
    sid.val = (uint8_t *)HcMalloc(sid.length, 0);
    if (sid.val == NULL) {
        LOGE("Malloc for sid failed.");
        res = HC_ERR_ALLOC_MEMORY;
        goto CLEAN_UP;
    }
    res = ComputeSid(params, &sid);
    if (res != HC_SUCCESS) {
        LOGE("Compute sid failed, res: %x.", res);
        goto CLEAN_UP;
    }
    res = ComputeSharedSecret(params, &sid, &tmpSharedSecret);
    if (res != HC_SUCCESS) {
        LOGE("ComputeSharedSecret failed, res: %x.", res);
        goto CLEAN_UP;
    }
    goto OUT;
CLEAN_UP:
    CleanPakeSensitiveKeys(params);
OUT:
    FreeAndCleanKey(&sid);
    FreeAndCleanKey(&tmpSharedSecret);
    return res;
}

static int32_t CombineEpk(const Uint8Buff *epkClient, const Uint8Buff *epkServer, uint32_t epkLenX,
    Uint8Buff *proofMsg, uint32_t *usedLen)
{
    if (memcpy_s(proofMsg->val + *usedLen, proofMsg->length - *usedLen,
        epkClient->val, epkLenX) != EOK) { // Only the x-coordinate of epk is required
        LOGE("Memcpy for epkClient failed.");
        return HC_ERR_MEMORY_COPY;
    }
    *usedLen += epkLenX;
    if (memcpy_s(proofMsg->val + *usedLen, proofMsg->length - *usedLen,
        epkServer->val, epkLenX) != EOK) { // Only the x-coordinate of epk is required
        LOGE("Memcpy for epkServer failed.");
        return HC_ERR_MEMORY_COPY;
    }
    *usedLen += epkLenX;
    return HC_SUCCESS;
}

static int32_t CombineProofMsg(const PakeBaseParams *params, Uint8Buff *proofMsg, bool isVerify)
{
    int32_t res;
    uint32_t usedLen = 0;
    const uint8_t *kcfCode = NULL;

    if ((params->isClient && !isVerify) || (!params->isClient && isVerify)) {
        kcfCode = g_kcfCodeClient;
    } else {
        kcfCode = g_kcfCodeServer;
    }
    if (memcpy_s(proofMsg->val, proofMsg->length, kcfCode, KCF_CODE_LEN) != HC_SUCCESS) {
        LOGE("Memcpy for g_kcfCode failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += KCF_CODE_LEN;
    if (params->isClient) {
        res = CombineEpk(&params->epkSelf, &params->epkPeer, params->innerKeyLen, proofMsg, &usedLen);
    } else {
        res = CombineEpk(&params->epkPeer, &params->epkSelf, params->innerKeyLen, proofMsg, &usedLen);
    }
    if (res != HC_SUCCESS) {
        LOGE("CombineEpk failed, res: %x.", res);
        return res;
    }
    if (memcpy_s(proofMsg->val + usedLen, proofMsg->length - usedLen,
        params->sharedSecret.val, params->sharedSecret.length) != EOK) {
        LOGE("Memcpy for sharedSecret failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += params->sharedSecret.length;
    /* base only need x-coordinate */
    if (memcpy_s(proofMsg->val + usedLen, proofMsg->length - usedLen, params->base.val, params->innerKeyLen) != EOK) {
        LOGE("Memcpy for base failed.");
        return HC_ERR_MEMORY_COPY;
    }
    return res;
}

/*
 * msg = challenge_self + challenge_peer
 * kcfdata = SHA256(byte(code), PK_CLIENT_X, PK_SERVER_X, sharedSecret, base_X)
 */
static int32_t GenerateProof(PakeBaseParams *params)
{
    int res;
    Uint8Buff proofMsg = { NULL, 0 };
    proofMsg.length = KCF_CODE_LEN + params->innerKeyLen + params->innerKeyLen +
        params->sharedSecret.length + params->innerKeyLen;
    proofMsg.val = (uint8_t *)HcMalloc(proofMsg.length, 0);
    if (proofMsg.val == NULL) {
        LOGE("Malloc for proofMsg failed.");
        res = HC_ERR_ALLOC_MEMORY;
        goto CLEAN_UP;
    }
    res = CombineProofMsg(params, &proofMsg, false);
    if (res != HC_SUCCESS) {
        LOGE("CombineProofMsg failed, res: %x.", res);
        goto CLEAN_UP;
    }
    res = params->loader->sha256(&proofMsg, &params->kcfData);
    if (res != HC_SUCCESS) {
        LOGE("Sha256 for proofMsg failed, res: %x.", res);
        goto CLEAN_UP;
    }
    goto OUT;
CLEAN_UP:
    CleanPakeSensitiveKeys(params);
OUT:
    FreeAndCleanKey(&proofMsg);
    return res;
}

static int32_t VerifyProof(PakeBaseParams *params)
{
    int res;
    Uint8Buff proofMsg = { NULL, 0 };
    proofMsg.length = KCF_CODE_LEN + params->innerKeyLen + params->innerKeyLen +
        params->sharedSecret.length + params->innerKeyLen;
    proofMsg.val = (uint8_t *)HcMalloc(proofMsg.length, 0);
    if (proofMsg.val == NULL) {
        LOGE("Malloc for proofMsg failed.");
        res = HC_ERR_ALLOC_MEMORY;
        goto CLEAN_UP;
    }
    res = CombineProofMsg(params, &proofMsg, true);
    if (res != HC_SUCCESS) {
        LOGE("CombineProofMsg failed, res: %x.", res);
        goto CLEAN_UP;
    }

    uint8_t tmpKcfDataVal[SHA256_LEN] = { 0 };
    Uint8Buff tmpKcfData = { tmpKcfDataVal, SHA256_LEN };
    res = params->loader->sha256(&proofMsg, &tmpKcfData);
    if (res != HC_SUCCESS) {
        LOGE("Sha256 for proofMsg failed, res: %x.", res);
        goto CLEAN_UP;
    }
    if (memcmp(tmpKcfData.val, params->kcfDataPeer.val, tmpKcfData.length) != EOK) {
        LOGE("Compare kcfData failed.");
        res = HC_ERR_PROOF_NOT_MATCH;
        goto CLEAN_UP;
    }
    goto OUT;
CLEAN_UP:
    CleanPakeSensitiveKeys(params);
OUT:
    FreeAndCleanKey(&proofMsg);
    return res;
}

static int32_t GenerateSessionKey(PakeBaseParams *params)
{
    Uint8Buff keyInfo = { (uint8_t *)HICHAIN_SPEKE_SESSIONKEY_INFO, HcStrlen(HICHAIN_SPEKE_SESSIONKEY_INFO) };
    int res = params->loader->computeHkdf(&params->sharedSecret, &params->salt, &keyInfo, &params->sessionKey, false);
    if (res != HC_SUCCESS) {
        LOGE("ComputeHkdf for sessionKey failed, res: %x.", res);
        CleanPakeSensitiveKeys(params);
    }
    FreeAndCleanKey(&params->base);
    FreeAndCleanKey(&params->sharedSecret);
    return res;
}

int32_t ClientConfirmPakeV2Protocol(PakeBaseParams *params)
{
    if (params == NULL) {
        LOGE("Params is null.");
        return HC_ERR_NULL_PTR;
    }
    int32_t res = GeneratePakeParams(params);
    if (res != HC_SUCCESS) {
        LOGE("GeneratePakeParams failed, res: %x.", res);
        goto CLEAN_UP;
    }
    res = GenerateSharedSecret(params);
    if (res != HC_SUCCESS) {
        LOGE("GenerateSharedSecret failed, res: %x.", res);
        goto CLEAN_UP;
    }
    res = GenerateProof(params);
    if (res != HC_SUCCESS) {
        LOGE("GenerateProof failed, res: %x.", res);
        goto CLEAN_UP;
    }
    return res;
CLEAN_UP:
    CleanPakeSensitiveKeys(params);
    return res;
}

int32_t ClientVerifyConfirmPakeV2Protocol(PakeBaseParams *params)
{
    if (params == NULL) {
        LOGE("Params is null.");
        return HC_ERR_NULL_PTR;
    }
    int32_t res = VerifyProof(params);
    if (res != HC_SUCCESS) {
        LOGE("VerifyProof failed, res: %x.", res);
        goto CLEAN_UP;
    }

    res = GenerateSessionKey(params);
    if (res != HC_SUCCESS) {
        LOGE("GenerateSessionKey failed, res: %x.", res);
        goto CLEAN_UP;
    }
    return res;
CLEAN_UP:
    CleanPakeSensitiveKeys(params);
    return res;
}

int32_t ServerResponsePakeV2Protocol(PakeBaseParams *params)
{
    if (params == NULL) {
        LOGE("Params is null.");
        return HC_ERR_NULL_PTR;
    }
    int32_t res = GeneratePakeParams(params);
    if (res != HC_SUCCESS) {
        LOGE("GeneratePakeParams failed, res: %x.", res);
        CleanPakeSensitiveKeys(params);
    }
    return res;
}

int32_t ServerConfirmPakeV2Protocol(PakeBaseParams *params)
{
    if (params == NULL) {
        LOGE("Params is null.");
        return HC_ERR_NULL_PTR;
    }
    int32_t res = GenerateSharedSecret(params);
    if (res != HC_SUCCESS) {
        LOGE("GenerateSharedSecret failed, res: %x.", res);
        goto CLEAN_UP;
    }
    res = VerifyProof(params);
    if (res != HC_SUCCESS) {
        LOGE("VerifyProof failed, res: %x.", res);
        goto CLEAN_UP;
    }
    res = GenerateProof(params);
    if (res != HC_SUCCESS) {
        LOGE("GenerateProof failed, res: %x.", res);
        goto CLEAN_UP;
    }
    res = GenerateSessionKey(params);
    if (res != HC_SUCCESS) {
        LOGE("GenerateSessionKey failed, res: %x.", res);
        goto CLEAN_UP;
    }
    return res;
CLEAN_UP:
    CleanPakeSensitiveKeys(params);
    return res;
}
