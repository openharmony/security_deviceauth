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

#include "pake_v2_auth_task_common.h"

#include <ctype.h>
#include "account_module.h"
#include "asy_token_manager.h"
#include "common_defs.h"
#include "device_auth_defines.h"
#include "hc_dev_info.h"
#include "hal_error.h"
#include "hc_log.h"
#include "hc_types.h"
#include "pake_v2_protocol_common.h"
#include "pake_v2_auth_client_task.h"
#include "pake_v2_auth_server_task.h"
#include "protocol_common.h"
#include "string_util.h"

#define P256_SHARED_SECRET_KEY_SIZE 32
#define P256_PUBLIC_SIZE 64
#define P256_KEY_SIZE 32

#define SHARED_KEY_ALIAS "sharedKeyAlias"

bool IsPakeV2AuthTaskSupported(void)
{
    return true;
}

TaskBase *CreatePakeV2AuthTask(const CJson *in, CJson *out, const AccountVersionInfo *verInfo)
{
    bool isClient = false;
    if (GetBoolFromJson(in, FIELD_IS_CLIENT, &isClient) != HC_SUCCESS) {
        LOGD("Get isClient from json failed.");
        isClient = false;
    }
    if (isClient) {
        return CreatePakeV2AuthClientTask(in, out, verInfo);
    }
    return CreatePakeV2AuthServerTask(in, out, verInfo);
}

int32_t VerifyPkSignPeer(const PakeAuthParams *params)
{
    uint8_t *serverPkAlias = (uint8_t *)HcMalloc(SHA256_LEN, 0);
    if (serverPkAlias == NULL) {
        LOGE("Failed to malloc for serverPk key alias.");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff serverPkAliasBuff = {
        .val = serverPkAlias,
        .length = SHA256_LEN
    };

    int32_t res = GetAccountAuthTokenManager()->generateKeyAlias((const char *)(params->userIdSelf),
        (const char *)params->devIdSelf.val, &serverPkAliasBuff, true);
    if (res != HC_SUCCESS) {
        HcFree(serverPkAlias);
        return res;
    }

    Uint8Buff messageBuff = {
        .val = params->pkInfoPeer.val,
        .length = params->pkInfoPeer.length
    };
    Uint8Buff peerSignBuff = {
        .val = params->pkInfoSignPeer.val,
        .length = params->pkInfoSignPeer.length
    };
    res = params->pakeParams.loader->verify(&serverPkAliasBuff, &messageBuff, P256, &peerSignBuff, true);
    HcFree(serverPkAlias);
    if (res != HC_SUCCESS) {
        LOGE("Verify pk sign failed.");
        return HC_ERR_VERIFY_FAILED;
    }
    return HC_SUCCESS;
}

int32_t GenerateEcdhSharedKey(PakeAuthParams *params)
{
    uint8_t *priAliasVal = (uint8_t *)HcMalloc(SHA256_LEN, 0);
    if (priAliasVal == NULL) {
        LOGE("Failed to malloc for self key alias.");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff aliasBuff = {
        .val = priAliasVal,
        .length = SHA256_LEN
    };
    int32_t res = GetAccountAuthTokenManager()->generateKeyAlias((const char *)(params->userIdSelf),
        (const char *)params->devIdSelf.val, &aliasBuff, false);
    if (res != HC_SUCCESS) {
        HcFree(priAliasVal);
        return res;
    }
    KeyBuff priAliasKeyBuff = {
        .key = aliasBuff.val,
        .keyLen = aliasBuff.length,
        .isAlias = true
    };
    KeyBuff publicKeyBuff = {
        .key = params->pkPeer,
        .keyLen = sizeof(params->pkPeer),
        .isAlias = false
    };
    uint32_t sharedKeyAliasLen = HcStrlen(SHARED_KEY_ALIAS) + 1;
    params->pakeParams.psk.val = (uint8_t *)HcMalloc(sharedKeyAliasLen, 0);
    if (params->pakeParams.psk.val == NULL) {
        LOGE("Failed to malloc for psk alias.");
        HcFree(priAliasVal);
        return HC_ERR_ALLOC_MEMORY;
    }
    params->pakeParams.psk.length = sharedKeyAliasLen;
    (void)memcpy_s(params->pakeParams.psk.val, sharedKeyAliasLen, SHARED_KEY_ALIAS, sharedKeyAliasLen);
    res = params->pakeParams.loader->agreeSharedSecretWithStorage(&priAliasKeyBuff, &publicKeyBuff,
        P256, P256_SHARED_SECRET_KEY_SIZE, &(params->pakeParams.psk));
    HcFree(priAliasVal);
    return res;
}

static int32_t InitCharStringBuff(Uint8Buff *param, uint32_t len)
{
    if (param == NULL || len <= 0) {
        LOGE("param is invalid for init.");
        return HC_ERR_NULL_PTR;
    }
    if (InitSingleParam(param, len + 1) != HC_SUCCESS) {
        return HC_ERR_ALLOC_MEMORY;
    }
    param->length = len;
    return HC_SUCCESS;
}

int32_t ExtractPakePeerId(PakeAuthParams *params, const CJson *in)
{
    if (params == NULL || in == NULL) {
        LOGE("Input params is invalid.");
        return HC_ERR_INVALID_PARAMS;
    }
    uint32_t deviceIdPeerLen = HcStrlen((const char *)params->deviceIdPeer.val);
    if (InitCharStringBuff(&params->pakeParams.idPeer,
        params->devIdPeer.length + deviceIdPeerLen) != HC_SUCCESS) {
        LOGE("InitCharStringBuff: idPeer failed.");
        return HC_ERR_AUTH_INTERNAL;
    }
    (void)memcpy_s(params->pakeParams.idPeer.val, params->pakeParams.idPeer.length, params->devIdPeer.val,
        params->devIdPeer.length);
    (void)memcpy_s(params->pakeParams.idPeer.val + params->devIdPeer.length,
        params->pakeParams.idPeer.length - params->devIdPeer.length, params->deviceIdPeer.val, deviceIdPeerLen);
    return HC_SUCCESS;
}

int32_t ExtractPakeSelfId(PakeAuthParams *params)
{
    if (params == NULL) {
        LOGE("Input params NULL.");
        return HC_ERR_INVALID_PARAMS;
    }
    uint32_t deviceIdSelfLen = HcStrlen((const char *)params->deviceIdSelf.val);
    if (InitCharStringBuff(&params->pakeParams.idSelf,
        params->devIdSelf.length + deviceIdSelfLen) != HC_SUCCESS) {
        LOGE("InitCharStringBuff: idSelf failed.");
        return HC_ERR_AUTH_INTERNAL;
    }

    (void)memcpy_s(params->pakeParams.idSelf.val, params->pakeParams.idSelf.length, params->devIdSelf.val,
        params->devIdSelf.length);
    (void)memcpy_s(params->pakeParams.idSelf.val + params->devIdSelf.length,
        params->pakeParams.idSelf.length - params->devIdSelf.length, params->deviceIdSelf.val, deviceIdSelfLen);
    return HC_SUCCESS;
}

int32_t ExtractSelfDeviceId(PakeAuthParams *params, const CJson *in, bool useSelfPrefix)
{
    if (params == NULL || in == NULL) {
        LOGE("Input params NULL.");
        return HC_ERR_INVALID_PARAMS;
    }
    const char *deviceId = NULL;
    if (useSelfPrefix) {
        deviceId = GetStringFromJson(in, FIELD_SELF_DEVICE_ID);
    } else {
        deviceId = GetStringFromJson(in, FIELD_DEVICE_ID);
    }
    if (deviceId == NULL) {
        LOGE("Get selfDeviceId from json failed.");
        return HC_ERR_JSON_GET;
    }
    params->deviceIdSelf.length = HcStrlen(deviceId);
    params->deviceIdSelf.val = (uint8_t *)HcMalloc(params->deviceIdSelf.length + 1, 0);
    if (params->deviceIdSelf.val == NULL) {
        LOGE("Failed to malloc for deviceIdSelf.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(params->deviceIdSelf.val, params->deviceIdSelf.length + 1,
        deviceId, params->deviceIdSelf.length) != EOK) {
        LOGE("Memcpy_s for deviceIdSelf failed.");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t ExtractPeerDeviceId(PakeAuthParams *params, const CJson *in)
{
    if (params == NULL || in == NULL) {
        LOGE("Input params NULL.");
        return HC_ERR_INVALID_PARAMS;
    }
    const char *deviceId = GetStringFromJson(in, FIELD_DEVICE_ID);
    if (deviceId == NULL) {
        LOGE("Get peer deviceId failed.");
        return HC_ERR_JSON_GET;
    }
    uint32_t len = HcStrlen(deviceId);
    if (InitCharStringBuff(&params->deviceIdPeer, len) != HC_SUCCESS) {
        LOGE("InitCharStringBuff: deviceIdPeer failed.");
        return HC_ERR_AUTH_INTERNAL;
    }
    if (memcpy_s(params->deviceIdPeer.val, params->deviceIdPeer.length + 1, deviceId, len) != EOK) {
        LOGE("memcpy_s deviceId failed.");
        return HC_ERR_MEMORY_COPY;
    }
    for (uint32_t i = 0; i < params->deviceIdPeer.length; i++) {
        // Change a - f charactor to upper charactor.
        if (params->deviceIdPeer.val[i] >= 'a' && params->deviceIdPeer.val[i] <= 'f') {
            params->deviceIdPeer.val[i] = (uint8_t)toupper(params->deviceIdPeer.val[i]);
        }
    }
    return HC_SUCCESS;
}

int32_t ExtractSelfDevId(PakeAuthParams *params, const CJson *in)
{
    if (params == NULL || in == NULL) {
        LOGE("Input params is invalid.");
        return HC_ERR_INVALID_PARAMS;
    }
    const char *devIdSelf = GetStringFromJson(in, FIELD_SELF_DEV_ID);
    if (devIdSelf == NULL) {
        LOGE("Get devIdSelf failed.");
        return HC_ERR_JSON_GET;
    }
    params->devIdSelf.length = HcStrlen(devIdSelf);
    params->devIdSelf.val = (uint8_t *)HcMalloc(params->devIdSelf.length + 1, 0);
    if (params->devIdSelf.val == NULL) {
        LOGE("Malloc for devIdSelf failed.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(params->devIdSelf.val, params->devIdSelf.length, devIdSelf,
        params->devIdSelf.length) != EOK) {
        LOGE("Copy for self devId failed.");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t ExtractPeerDevId(PakeAuthParams *params, const CJson *in)
{
    if (params == NULL || in == NULL) {
        LOGE("Input params is invalid.");
        return HC_ERR_INVALID_PARAMS;
    }
    const char *devId = GetStringFromJson(in, FIELD_DEV_ID);
    if (devId == NULL) {
        LOGE("Get PeerDevId failed.");
        return HC_ERR_JSON_GET;
    }
    uint32_t len = HcStrlen(devId);
    // Peer devId type is hex string, no need to transfer.
    if (InitCharStringBuff(&params->devIdPeer, len) != HC_SUCCESS) {
        LOGE("InitCharStringBuff: idPeer failed.");
        return HC_ERR_AUTH_INTERNAL;
    }
    if (memcpy_s(params->devIdPeer.val, params->devIdPeer.length, devId, len) != EOK) {
        LOGE("Failed to copy devId.");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t GetPkInfoPeer(PakeAuthParams *params, const CJson *in)
{
    if (params == NULL || in == NULL) {
        LOGE("Input params is invalid.");
        return HC_ERR_INVALID_PARAMS;
    }

    const char *pkInfoPeerStr = GetStringFromJson(in, FIELD_AUTH_PK_INFO);
    if (pkInfoPeerStr == NULL) {
        LOGE("Failed to get peer pkInfo string.");
        return HC_ERR_JSON_GET;
    }
    uint32_t len = HcStrlen(pkInfoPeerStr) + 1;
    if (InitSingleParam(&params->pkInfoPeer, len) != HC_SUCCESS) {
        LOGE("Failed to malloc for peer pkInfo.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(params->pkInfoPeer.val, len, pkInfoPeerStr, len) != EOK) {
        LOGE("GetPkInfoPeer: copy pkInfoPeer failed.");
        HcFree(params->pkInfoPeer.val);
        params->pkInfoPeer.val = NULL;
        return HC_ERR_ALLOC_MEMORY;
    }
    CJson *info = CreateJsonFromString(pkInfoPeerStr);
    if (info == NULL) {
        LOGE("Failed to create json for peer pkInfo.");
        HcFree(params->pkInfoPeer.val);
        params->pkInfoPeer.val = NULL;
        return HC_ERR_JSON_CREATE;
    }
    if (GetByteFromJson(info, FIELD_DEVICE_PK, params->pkPeer, PK_SIZE) != HC_SUCCESS) {
        LOGE("Failed to get devicePk.");
        FreeJson(info);
        HcFree(params->pkInfoPeer.val);
        params->pkInfoPeer.val = NULL;
        return HC_ERR_JSON_GET;
    }
    FreeJson(info);
    return HC_SUCCESS;
}

static int32_t GetAsyPubKeyInfo(PakeAuthParams *params)
{
    AccountToken *token = CreateAccountToken();
    if (token == NULL) {
        LOGE("Failed to create token.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = HC_ERR_GET_PK_INFO;
    do {
        if (GetAccountAuthTokenManager()->getToken(params->osAccountId, token,
            (const char *)params->userIdSelf) != HC_SUCCESS) {
            LOGE("Get token from local error.");
            break;
        }
        uint32_t pkInfoLen = token->pkInfoStr.length;
        if (pkInfoLen >= PUBLIC_KEY_INFO_SIZE) {
            LOGE("Length of pkInfo from local is error.");
            break;
        }
        if (InitSingleParam(&params->pkInfoSelf, pkInfoLen) != HC_SUCCESS) {
            LOGE("InitSingleParam: pkInfoSelf failed.");
            break;
        }
        if (memcpy_s(params->pkInfoSelf.val, params->pkInfoSelf.length, token->pkInfoStr.val, pkInfoLen) != EOK) {
            LOGE("Copy pkInfoSelf failed.");
            break;
        }
        if (memcpy_s(params->pkSelf, PK_SIZE, token->pkInfo.devicePk.val, token->pkInfo.devicePk.length) != EOK) {
            LOGE("Copy pkSelf failed.");
            break;
        }
        if (memcpy_s(params->pkInfoSignSelf.val, params->pkInfoSignSelf.length, token->pkInfoSignature.val,
            token->pkInfoSignature.length) != EOK) {
            LOGE("Copy pkInfoSignSelf failed.");
            break;
        }
        params->pkInfoSignSelf.length = token->pkInfoSignature.length;
        Uint8Buff serverPk = {
            .val = params->pkCloud,
            .length = sizeof(params->pkCloud)
        };
        if (GetAccountAuthTokenManager()->getServerPublicKey(params->osAccountId,
            (const char *)params->userIdSelf, &serverPk) != HC_SUCCESS) {
            LOGE("Get local server pk error.");
            break;
        }
        res = HC_SUCCESS;
    } while (0);
    DestroyAccountToken(token);
    return res;
}

static int32_t FillUserIdForAuth(const CJson *in, PakeAuthParams *params)
{
    const char *userIdSelf = GetStringFromJson(in, FIELD_SELF_USER_ID);
    if (userIdSelf == NULL) {
        LOGE("Failed to get self userId from input data.");
        return HC_ERR_JSON_GET;
    }
    if (memcpy_s(params->userIdSelf, sizeof(params->userIdSelf), userIdSelf,
        sizeof(params->userIdSelf)) != EOK) {
        LOGE("Copy for userIdSelf failed.");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t InitPakeAuthParams(const CJson *in, PakeAuthParams *params, const AccountVersionInfo *verInfo)
{
    if (in == NULL || params == NULL || verInfo == NULL) {
        LOGE("Input params is NULL.");
        return HC_ERR_INVALID_PARAMS;
    }
    const char *deviceId = GetStringFromJson(in, FIELD_SELF_DEVICE_ID);
    if (deviceId == NULL) {
        LOGE("Self deviceId is NULL.");
        return HC_ERR_INVALID_PARAMS;
    }
    uint32_t deviceIdLen = HcStrlen(deviceId);
    GOTO_IF_ERR(GetIntFromJson(in, FIELD_OS_ACCOUNT_ID, &params->osAccountId));
    GOTO_IF_ERR(InitPakeV2BaseParams(&params->pakeParams));
    GOTO_IF_ERR(InitSingleParam(&params->pakeParams.epkPeer, P256_PUBLIC_SIZE));
    GOTO_IF_ERR(InitSingleParam(&params->pkInfoSignSelf, SIGNATURE_SIZE));
    GOTO_IF_ERR(InitSingleParam(&params->pkInfoSignPeer, SIGNATURE_SIZE));
    GOTO_IF_ERR(InitSingleParam(&params->pakeParams.idSelf, deviceIdLen + 1));
    (void)memcpy_s(params->pakeParams.idSelf.val, deviceIdLen, deviceId, deviceIdLen);
    params->pakeParams.idSelf.length = deviceIdLen;
    GOTO_IF_ERR(FillUserIdForAuth(in, params));
    GOTO_IF_ERR(GetBoolFromJson(in, FIELD_IS_CLIENT, &params->pakeParams.isClient));
    GOTO_IF_ERR(GetAsyPubKeyInfo(params));

    params->pakeParams.supportedPakeAlg = verInfo->pakeAlgType;
    params->pakeParams.curveType = verInfo->curveType;
    params->versionNo = verInfo->versionNo;
#ifdef ACCOUNT_PAKE_DL_PRIME_LEN_384
    params->pakeParams.supportedDlPrimeMod = (uint32_t)params->pakeParams.supportedDlPrimeMod | DL_PRIME_MOD_384;
#endif
#ifdef ACCOUNT_PAKE_DL_PRIME_LEN_256
    params->pakeParams.supportedDlPrimeMod = (uint32_t)params->pakeParams.supportedDlPrimeMod | DL_PRIME_MOD_256;
#endif
    return HC_SUCCESS;
ERR:
    LOGE("InitPakeAuthParams failed.");
    return HC_ERR_AUTH_INTERNAL;
}

static void FreeUint8Buff(Uint8Buff *buff)
{
    if (buff == NULL) {
        return;
    }
    if (buff->val != NULL) {
        HcFree(buff->val);
        buff->val = NULL;
    }
    buff->length = 0;
}

void DestroyPakeAuthParams(PakeAuthParams *params)
{
    if (params == NULL) {
        LOGE("Pointer is NULL.");
        return;
    }

    (void)memset_s(params->pkCloud, sizeof(params->pkCloud), 0, sizeof(params->pkCloud));
    (void)memset_s(params->userIdSelf, sizeof(params->userIdSelf), 0, sizeof(params->userIdSelf));
    (void)memset_s(params->userIdPeer, sizeof(params->userIdPeer), 0, sizeof(params->userIdPeer));
    (void)memset_s(params->pkSelf, sizeof(params->pkSelf), 0, sizeof(params->pkSelf));
    (void)memset_s(params->pkPeer, sizeof(params->pkPeer), 0, sizeof(params->pkPeer));
    (void)memset_s(params->pkInfoPeer.val, params->pkInfoPeer.length, 0, params->pkInfoPeer.length);
    FreeUint8Buff(&params->pkInfoPeer);
    FreeUint8Buff(&params->deviceIdPeer);
    FreeUint8Buff(&params->devIdSelf);
    FreeUint8Buff(&params->devIdPeer);
    FreeUint8Buff(&params->pkInfoSelf);
    FreeUint8Buff(&params->pkInfoSignPeer);
    FreeUint8Buff(&params->pkInfoSignSelf);
    DestroyPakeV2BaseParams(&params->pakeParams);
    HcFree(params->deviceIdSelf.val);
    params->deviceIdSelf.val = NULL;
}