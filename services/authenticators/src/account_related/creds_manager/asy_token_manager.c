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

#include "asy_token_manager.h"
#include "account_module_defines.h"
#include "alg_loader.h"
#include "common_defs.h"
#include "hc_dev_info.h"
#include "hal_error.h"
#include "hc_file.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "hc_types.h"
#include "string_util.h"

IMPLEMENT_HC_VECTOR(AccountTokenVec, AccountToken*, 1)

typedef struct {
    int32_t osAccountId;
    AccountTokenVec tokens;
} OsAccountTokenInfo;

DECLARE_HC_VECTOR(AccountTokenDb, OsAccountTokenInfo)
IMPLEMENT_HC_VECTOR(AccountTokenDb, OsAccountTokenInfo, 1)

#define MAX_DB_PATH_LEN 256
#define SELF_ECC_KEY_LEN 32

AccountAuthTokenManager g_asyTokenManager;

static const AlgLoader *g_algLoader = NULL;
static bool g_isInitial = false;
static AccountTokenDb g_accountTokenDb;
static HcMutex *g_accountDbMutex;

static int32_t GeneratePkInfoFromJson(PkInfo *info, const CJson *pkInfoJson)
{
    if (GetByteFromJson(pkInfoJson, FIELD_DEVICE_PK, info->devicePk.val, info->devicePk.length) != HC_SUCCESS) {
        LOGE("get devicePk failed");
        return HC_ERR_JSON_GET;
    }
    const char *devicePk = GetStringFromJson(pkInfoJson, FIELD_DEVICE_PK);
    info->devicePk.length = HcStrlen(devicePk) / BYTE_TO_HEX_OPER_LENGTH;
    const char *version = GetStringFromJson(pkInfoJson, FIELD_VERSION);
    if (version == NULL) {
        LOGE("get version failed");
        return HC_ERR_JSON_GET;
    }
    if (memcpy_s(info->version.val, info->version.length, version, HcStrlen(version) + 1) != EOK) {
        LOGE("memcpy_s version failed");
        return HC_ERR_MEMORY_COPY;
    }
    info->version.length = HcStrlen(version) + 1;
    const char *deviceId = GetStringFromJson(pkInfoJson, FIELD_DEVICE_ID);
    if (deviceId == NULL) {
        LOGE("get deviceId failed");
        return HC_ERR_JSON_GET;
    }
    if (memcpy_s(info->deviceId.val, info->deviceId.length, deviceId, HcStrlen(deviceId) + 1) != EOK) {
        LOGE("memcpy_s deviceId failed");
        return HC_ERR_MEMORY_COPY;
    }
    info->deviceId.length = HcStrlen(deviceId) + 1;
    const char *userId = GetStringFromJson(pkInfoJson, FIELD_USER_ID);
    if (userId == NULL) {
        LOGE("get userId failed");
        return HC_ERR_JSON_GET;
    }
    if (memcpy_s(info->userId.val, info->userId.length, userId, HcStrlen(userId) + 1) != EOK) {
        LOGE("memcpy_s userId failed");
        return HC_ERR_MEMORY_COPY;
    }
    info->userId.length = HcStrlen(userId) + 1;
    return HC_SUCCESS;
}

static bool GetTokenPath(int32_t osAccountId, char *tokenPath, uint32_t pathBufferLen)
{
    const char *beginPath = GetAccountStoragePath();
    if (beginPath == NULL) {
        LOGE("Failed to get the account storage path!");
        return false;
    }
    int32_t writeByteNum;
    if (osAccountId == DEFAULT_OS_ACCOUNT) {
        writeByteNum = sprintf_s(tokenPath, pathBufferLen, "%s/account_data_asy.dat", beginPath);
    } else {
        writeByteNum = sprintf_s(tokenPath, pathBufferLen, "%s/account_data_asy%d.dat", beginPath, osAccountId);
    }
    if (writeByteNum <= 0) {
        LOGE("sprintf_s fail!");
        return false;
    }
    return true;
}

static int32_t GenerateTokenFromJson(const CJson *tokenJson, AccountToken *token)
{
    CJson *pkInfoJson = GetObjFromJson(tokenJson, FIELD_PK_INFO);
    if (pkInfoJson == NULL) {
        LOGE("Failed to get pkInfoJson");
        return HC_ERR_JSON_GET;
    }
    char *pkInfoStr = PackJsonToString(pkInfoJson);
    if (pkInfoStr == NULL) {
        LOGE("Pack pkInfoStr failed");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    if (memcpy_s(token->pkInfoStr.val, token->pkInfoStr.length, pkInfoStr, HcStrlen(pkInfoStr) + 1) != EOK) {
        LOGE("Memcpy failed for pkInfoStr");
        FreeJsonString(pkInfoStr);
        return HC_ERR_MEMORY_COPY;
    }
    token->pkInfoStr.length = HcStrlen(pkInfoStr) + 1;
    FreeJsonString(pkInfoStr);
    if (GetByteFromJson(tokenJson, FIELD_PK_INFO_SIGNATURE, token->pkInfoSignature.val,
        token->pkInfoSignature.length) != HC_SUCCESS) {
        LOGE("Get pkInfoSignature failed");
        return HC_ERR_JSON_GET;
    }
    const char *signatureStr = GetStringFromJson(tokenJson, FIELD_PK_INFO_SIGNATURE);
    token->pkInfoSignature.length = HcStrlen(signatureStr) / BYTE_TO_HEX_OPER_LENGTH;
    if (GetByteFromJson(tokenJson, FIELD_SERVER_PK, token->serverPk.val,
        token->serverPk.length) != HC_SUCCESS) {
        LOGE("Get serverPk failed");
        return HC_ERR_JSON_GET;
    }
    const char *serverPkStr = GetStringFromJson(tokenJson, FIELD_SERVER_PK);
    token->serverPk.length = HcStrlen(serverPkStr) / BYTE_TO_HEX_OPER_LENGTH;
    int32_t ret = GeneratePkInfoFromJson(&token->pkInfo, pkInfoJson);
    if (ret != HC_SUCCESS) {
        LOGE("Generate pkInfo failed");
        return ret;
    }
    return HC_SUCCESS;
}

static int32_t CreateTokensFromJson(CJson *tokensJson, AccountTokenVec *vec)
{
    int32_t tokenNum = GetItemNum(tokensJson);
    if (tokenNum <= 0) {
        LOGE("No token found.");
        return HC_ERR_JSON_GET;
    }
    int32_t ret;
    for (int32_t i = 0; i < tokenNum; i++) {
        CJson *tokenJson = GetItemFromArray(tokensJson, i);
        if (tokenJson == NULL) {
            LOGE("Token json is null");
            ClearAccountTokenVec(vec);
            return HC_ERR_JSON_GET;
        }
        AccountToken *token = CreateAccountToken();
        if (token == NULL) {
            LOGE("Failed to create token");
            ClearAccountTokenVec(vec);
            return HC_ERR_ALLOC_MEMORY;
        }
        ret = GenerateTokenFromJson(tokenJson, token);
        if (ret != HC_SUCCESS) {
            LOGE("Generate token failed");
            DestroyAccountToken(token);
            ClearAccountTokenVec(vec);
            return ret;
        }
        if (vec->pushBackT(vec, token) == NULL) {
            LOGE("Failed to push token to vec");
            DestroyAccountToken(token);
            ClearAccountTokenVec(vec);
            return HC_ERR_MEMORY_COPY;
        }
    }
    return HC_SUCCESS;
}

static int32_t OpenTokenFile(int32_t osAccountId, FileHandle *file, int32_t mode)
{
    char *tokenPath = (char *)HcMalloc(MAX_DB_PATH_LEN, 0);
    if (tokenPath == NULL) {
        LOGE("Malloc tokenPath failed");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (!GetTokenPath(osAccountId, tokenPath, MAX_DB_PATH_LEN)) {
        LOGE("Get token path failed");
        HcFree(tokenPath);
        return HC_ERROR;
    }
    int32_t ret = HcFileOpen(tokenPath, mode, file);
    HcFree(tokenPath);
    return ret;
}

static int32_t ReadTokensFromFile(int32_t osAccountId, AccountTokenVec *vec)
{
    if (vec == NULL) {
        LOGE("Input token vec is null.");
        return HC_ERR_NULL_PTR;
    }
    FileHandle file = { 0 };
    int32_t ret = OpenTokenFile(osAccountId, &file, MODE_FILE_READ);
    if (ret != HC_SUCCESS) {
        LOGE("Open token file failed");
        return ret;
    }
    int32_t fileSize = HcFileSize(file);
    if (fileSize <= 0) {
        LOGE("file size stat failed");
        HcFileClose(file);
        return HC_ERROR;
    }
    char *fileData = (char *)HcMalloc(fileSize, 0);
    if (fileData == NULL) {
        LOGE("Malloc file data failed");
        HcFileClose(file);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (HcFileRead(file, fileData, fileSize) != fileSize) {
        LOGE("fileData read failed");
        HcFileClose(file);
        HcFree(fileData);
        return HC_ERROR;
    }
    HcFileClose(file);
    CJson *readJsonFile = CreateJsonFromString(fileData);
    HcFree(fileData);
    if (readJsonFile == NULL) {
        LOGE("fileData parse failed");
        return HC_ERR_JSON_CREATE;
    }
    ret = CreateTokensFromJson(readJsonFile, vec);
    FreeJson(readJsonFile);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to create tokens from json");
    }
    return ret;
}

static int32_t WriteTokensJsonToFile(int32_t osAccountId, CJson *tokensJson)
{
    char *storeJsonString = PackJsonToString(tokensJson);
    if (storeJsonString == NULL) {
        LOGE("Pack stored json to string failed.");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    FileHandle file = { 0 };
    int32_t ret = OpenTokenFile(osAccountId, &file, MODE_FILE_WRITE);
    if (ret != HC_SUCCESS) {
        LOGE("Open token file failed.");
        FreeJsonString(storeJsonString);
        return ret;
    }
    int32_t fileSize = (int32_t)(HcStrlen(storeJsonString) + 1);
    if (HcFileWrite(file, storeJsonString, fileSize) != fileSize) {
        LOGE("Failed to write token array to file.");
        ret = HC_ERR_FILE;
    }
    FreeJsonString(storeJsonString);
    HcFileClose(file);
    return ret;
}

static int32_t GenerateJsonFromToken(AccountToken *token, CJson *tokenJson)
{
    CJson *pkInfoJson = CreateJsonFromString((const char *)token->pkInfoStr.val);
    if (pkInfoJson == NULL) {
        LOGE("Failed to create pkInfoJson");
        return HC_ERR_JSON_CREATE;
    }
    if (AddObjToJson(tokenJson, FIELD_PK_INFO, pkInfoJson) != HC_SUCCESS) {
        LOGE("Add pkInfoJson to json failed");
        FreeJson(pkInfoJson);
        return HC_ERR_JSON_ADD;
    }
    FreeJson(pkInfoJson);
    if (AddByteToJson(tokenJson, FIELD_PK_INFO_SIGNATURE, token->pkInfoSignature.val,
        token->pkInfoSignature.length) != HC_SUCCESS) {
        LOGE("Add pkInfoSignature to json failed");
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(tokenJson, FIELD_SERVER_PK, token->serverPk.val,
        token->serverPk.length) != HC_SUCCESS) {
        LOGE("Add serverPk to json failed");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t SaveTokensToFile(int32_t osAccountId, const AccountTokenVec *vec)
{
    CJson *storeJson = CreateJsonArray();
    if (storeJson == NULL) {
        LOGE("Create json failed when save tokens to file.");
        return HC_ERR_JSON_CREATE;
    }
    int32_t ret;
    uint32_t index;
    AccountToken **token;
    FOR_EACH_HC_VECTOR(*vec, index, token) {
        CJson *tokenJson = CreateJson();
        if (tokenJson == NULL) {
            LOGE("Create token json failed.");
            FreeJson(storeJson);
            return HC_ERR_JSON_CREATE;
        }
        ret = GenerateJsonFromToken(*token, tokenJson);
        if (ret != HC_SUCCESS) {
            LOGE("Generate json from token failed");
            FreeJson(tokenJson);
            FreeJson(storeJson);
            return ret;
        }
        if (AddObjToArray(storeJson, tokenJson) != HC_SUCCESS) {
            LOGE("Add token json to array failed");
            FreeJson(tokenJson);
            FreeJson(storeJson);
            return HC_ERR_JSON_ADD;
        }
    }
    ret = WriteTokensJsonToFile(osAccountId, storeJson);
    FreeJson(storeJson);
    return ret;
}

static Algorithm GetVerifyAlg(const char *version)
{
    (void)version;
    return P256;
}

static int32_t GenerateKeyAlias(const char *userId, const char *deviceId, Uint8Buff *alias,
    bool isServerPkAlias)
{
    if ((userId == NULL) || (deviceId == NULL) || (alias == NULL)) {
        LOGE("Invalid input params");
        return HC_ERR_NULL_PTR;
    }
    uint32_t userIdLen = HcStrlen(userId);
    uint32_t deviceIdLen = HcStrlen(deviceId);
    const char *serverPkTag = "serverPk";
    uint32_t serverPkTagLen = HcStrlen(serverPkTag);
    uint32_t aliasStrLen;
    if (isServerPkAlias) {
        aliasStrLen = userIdLen + deviceIdLen + serverPkTagLen;
    } else {
        aliasStrLen = userIdLen + deviceIdLen;
    }
    uint8_t *aliasStr = (uint8_t *)HcMalloc(aliasStrLen, 0);
    if (aliasStr == NULL) {
        LOGE("Failed to malloc for self key aliasStr.");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff aliasBuff = {
        aliasStr,
        aliasStrLen
    };
    if (memcpy_s(aliasBuff.val, aliasBuff.length, userId, userIdLen) != EOK) {
        LOGE("Failed to copy userId.");
        HcFree(aliasStr);
        return HC_ERR_MEMORY_COPY;
    }
    if (memcpy_s(aliasBuff.val + userIdLen, aliasBuff.length - userIdLen,
        deviceId, deviceIdLen) != EOK) {
        LOGE("Failed to copy deviceId.");
        HcFree(aliasStr);
        return HC_ERR_MEMORY_COPY;
    }
    if (isServerPkAlias && (memcpy_s(aliasBuff.val + userIdLen + deviceIdLen,
        aliasBuff.length - userIdLen - deviceIdLen, serverPkTag, serverPkTagLen) != EOK)) {
        LOGE("Failed to copy serverPkTag.");
        HcFree(aliasStr);
        return HC_ERR_MEMORY_COPY;
    }
    int32_t ret = g_algLoader->sha256(&aliasBuff, alias);
    HcFree(aliasStr);
    if (ret != HAL_SUCCESS) {
        LOGE("Compute alias failed");
    }
    return ret;
}

static int32_t GenerateServerPkAlias(CJson *pkInfoJson, Uint8Buff *alias)
{
    const char *userId = GetStringFromJson(pkInfoJson, FIELD_USER_ID);
    if (userId == NULL) {
        LOGE("Failed to get userId");
        return HC_ERR_JSON_GET;
    }
    const char *deviceId = GetStringFromJson(pkInfoJson, FIELD_DEVICE_ID);
    if (deviceId == NULL) {
        LOGE("Failed to get deviceId");
        return HC_ERR_JSON_GET;
    }
    return GenerateKeyAlias(userId, deviceId, alias, true);
}

static int32_t ImportServerPk(const CJson *credJson, Uint8Buff *keyAlias, uint8_t *serverPk, Algorithm alg)
{
    const char *serverPkStr = GetStringFromJson(credJson, FIELD_SERVER_PK);
    if (serverPkStr == NULL) {
        LOGE("Failed to get serverPkStr");
        return HC_ERR_JSON_GET;
    }
    uint32_t serverPkLen = HcStrlen(serverPkStr) / BYTE_TO_HEX_OPER_LENGTH;
    Uint8Buff keyBuff = {
        .val = serverPk,
        .length = serverPkLen
    };
    int32_t authId = 0;
    Uint8Buff authIdBuff = { (uint8_t *)&authId, sizeof(int32_t) };
    ExtraInfo extInfo = { authIdBuff, -1, -1 };
    return g_algLoader->importPublicKey(keyAlias, &keyBuff, alg, &extInfo);
}

static int32_t VerifyPkInfoSignature(const CJson *credJson, CJson *pkInfoJson, uint8_t *signature,
    Uint8Buff *keyAlias, Algorithm alg)
{
    char *pkInfoStr = PackJsonToString(pkInfoJson);
    if (pkInfoStr == NULL) {
        LOGE("Failed to pack pkInfoStr");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    Uint8Buff messageBuff = {
        .val = (uint8_t *)pkInfoStr,
        .length = HcStrlen(pkInfoStr) + 1
    };
    const char *signatureStr = GetStringFromJson(credJson, FIELD_PK_INFO_SIGNATURE);
    if (signatureStr == NULL) {
        LOGE("Failed to get signatureStr");
        FreeJsonString(pkInfoStr);
        return HC_ERR_JSON_GET;
    }
    uint32_t signatureLen = HcStrlen(signatureStr) / BYTE_TO_HEX_OPER_LENGTH;
    Uint8Buff signatureBuff = {
        .val = signature,
        .length = signatureLen
    };
    int32_t ret = g_algLoader->verify(keyAlias, &messageBuff, alg, &signatureBuff, true);
    FreeJsonString(pkInfoStr);
    return ret;
}

static int32_t DoImportServerPkAndVerify(const CJson *credJson, uint8_t *signature, uint8_t *serverPk,
    CJson *pkInfoJson)
{
    uint8_t *keyAliasValue = (uint8_t *)HcMalloc(SHA256_LEN, 0);
    if (keyAliasValue == NULL) {
        LOGE("Malloc keyAliasValue failed");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff keyAlias = {
        .val = keyAliasValue,
        .length = SHA256_LEN
    };
    g_accountDbMutex->lock(g_accountDbMutex);
    int32_t ret = GenerateServerPkAlias(pkInfoJson, &keyAlias);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate serverPk alias");
        g_accountDbMutex->unlock(g_accountDbMutex);
        HcFree(keyAliasValue);
        return ret;
    }
    const char *version = GetStringFromJson(pkInfoJson, FIELD_VERSION);
    if (version == NULL) {
        LOGE("Failed to get version from pkInfo");
        g_accountDbMutex->unlock(g_accountDbMutex);
        HcFree(keyAliasValue);
        return HC_ERR_JSON_GET;
    }
    Algorithm alg = GetVerifyAlg(version);
    ret = ImportServerPk(credJson, &keyAlias, serverPk, alg);
    if (ret != HAL_SUCCESS) {
        LOGE("Import server public key failed");
        g_accountDbMutex->unlock(g_accountDbMutex);
        HcFree(keyAliasValue);
        return ret;
    }
    LOGI("Import server public key success, start to verify");
    ret = VerifyPkInfoSignature(credJson, pkInfoJson, signature, &keyAlias, alg);
    g_accountDbMutex->unlock(g_accountDbMutex);
    HcFree(keyAliasValue);
    if (ret != HC_SUCCESS) {
        LOGE("Verify pkInfoSignature failed");
    }
    return ret;
}

static int32_t VerifySignature(const CJson *credJson)
{
    LOGI("start verify server message!");
    uint8_t *signature = (uint8_t *)HcMalloc(SIGNATURE_SIZE, 0);
    if (signature == NULL) {
        LOGE("malloc signature fail!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetByteFromJson(credJson, FIELD_PK_INFO_SIGNATURE, signature, SIGNATURE_SIZE) != EOK) {
        LOGE("get pkInfoSignature fail");
        HcFree(signature);
        return HC_ERR_JSON_GET;
    }
    uint8_t *serverPk = (uint8_t *)HcMalloc(SERVER_PK_SIZE, 0);
    if (serverPk == NULL) {
        LOGE("malloc serverPk fail!");
        HcFree(signature);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetByteFromJson(credJson, FIELD_SERVER_PK, serverPk, SERVER_PK_SIZE) != EOK) {
        LOGE("get serverPk fail!");
        HcFree(signature);
        HcFree(serverPk);
        return HC_ERR_JSON_GET;
    }
    CJson *pkInfoJson = GetObjFromJson(credJson, FIELD_PK_INFO);
    if (pkInfoJson == NULL) {
        LOGE("Failed to get pkInfoJson");
        HcFree(signature);
        HcFree(serverPk);
        return HC_ERR_JSON_GET;
    }
    int32_t ret = DoImportServerPkAndVerify(credJson, signature, serverPk, pkInfoJson);
    HcFree(signature);
    HcFree(serverPk);
    if (ret != HC_SUCCESS) {
        LOGE("Verify pkInfoSignature failed");
    } else {
        LOGI("Verify pkInfoSignature success");
    }
    return ret;
}

static OsAccountTokenInfo *GetTokenInfoByOsAccountId(int32_t osAccountId)
{
    uint32_t index = 0;
    OsAccountTokenInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_accountTokenDb, index, info) {
        if ((info != NULL) && (info->osAccountId == osAccountId)) {
            return info;
        }
    }
    LOGI("Create a new os account database cache! [Id]: %d", osAccountId);
    OsAccountTokenInfo newInfo;
    newInfo.osAccountId = osAccountId;
    newInfo.tokens = CreateAccountTokenVec();
    OsAccountTokenInfo *returnInfo = g_accountTokenDb.pushBackT(&g_accountTokenDb, newInfo);
    if (returnInfo == NULL) {
        LOGE("Failed to push OsAccountTokenInfo to database!");
        DestroyAccountTokenVec(&newInfo.tokens);
    }
    return returnInfo;
}

static int32_t GeneratePkInfoFromInfo(const PkInfo *srcInfo, PkInfo *desInfo)
{
    if (memcpy_s(desInfo->userId.val, desInfo->userId.length,
        srcInfo->userId.val, srcInfo->userId.length) != EOK) {
        LOGE("Memcpy for userId failed.");
        return HC_ERR_MEMORY_COPY;
    }
    desInfo->userId.length = srcInfo->userId.length;
    if (memcpy_s(desInfo->deviceId.val, desInfo->deviceId.length,
        srcInfo->deviceId.val, srcInfo->deviceId.length) != EOK) {
        LOGE("Memcpy for deviceId failed.");
        return HC_ERR_MEMORY_COPY;
    }
    desInfo->deviceId.length = srcInfo->deviceId.length;
    if (memcpy_s(desInfo->devicePk.val, desInfo->devicePk.length,
        srcInfo->devicePk.val, srcInfo->devicePk.length) != EOK) {
        LOGE("Memcpy for devicePk failed.");
        return HC_ERR_MEMORY_COPY;
    }
    desInfo->devicePk.length = srcInfo->devicePk.length;
    if (memcpy_s(desInfo->version.val, desInfo->version.length,
        srcInfo->version.val, srcInfo->version.length) != EOK) {
        LOGE("Memcpy for version failed.");
        return HC_ERR_MEMORY_COPY;
    }
    desInfo->version.length = srcInfo->version.length;
    return HC_SUCCESS;
}

static int32_t SaveOsAccountTokenDb(int32_t osAccountId)
{
    g_accountDbMutex->lock(g_accountDbMutex);
    OsAccountTokenInfo *info = GetTokenInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        LOGE("Get token info by os account id failed");
        g_accountDbMutex->unlock(g_accountDbMutex);
        return HC_ERROR;
    }
    int32_t ret = SaveTokensToFile(osAccountId, &info->tokens);
    if (ret != HC_SUCCESS) {
        LOGE("Save tokens to file failed");
        g_accountDbMutex->unlock(g_accountDbMutex);
        return ret;
    }
    g_accountDbMutex->unlock(g_accountDbMutex);
    LOGI("Save an os account database successfully! [Id]: %d", osAccountId);
    return HC_SUCCESS;
}

static bool GenerateAccountTokenFromToken(const AccountToken *token, AccountToken *returnToken)
{
    if (memcpy_s(returnToken->pkInfoStr.val, returnToken->pkInfoStr.length,
        token->pkInfoStr.val, token->pkInfoStr.length) != EOK) {
        LOGE("Memcpy for pkInfoStr failed.");
        return false;
    }
    returnToken->pkInfoStr.length = token->pkInfoStr.length;
    if (GeneratePkInfoFromInfo(&token->pkInfo, &returnToken->pkInfo) != HC_SUCCESS) {
        LOGE("Failed to generate pkInfo");
        return false;
    }
    if (memcpy_s(returnToken->serverPk.val, returnToken->serverPk.length,
        token->serverPk.val, token->serverPk.length) != EOK) {
        LOGE("Memcpy for serverPk failed.");
        return false;
    }
    returnToken->serverPk.length = token->serverPk.length;
    if (memcpy_s(returnToken->pkInfoSignature.val, returnToken->pkInfoSignature.length,
        token->pkInfoSignature.val, token->pkInfoSignature.length) != EOK) {
        LOGE("Memcpy for pkInfoSignature failed.");
        return false;
    }
    returnToken->pkInfoSignature.length = token->pkInfoSignature.length;
    return true;
}

static AccountToken *DeepCopyToken(const AccountToken *token)
{
    AccountToken *returnToken = CreateAccountToken();
    if (returnToken == NULL) {
        LOGE("Failed to create token");
        return NULL;
    }
    if (!GenerateAccountTokenFromToken(token, returnToken)) {
        LOGE("Generate token from exist token failed");
        DestroyAccountToken(returnToken);
        return NULL;
    }
    return returnToken;
}

static AccountToken **QueryTokenPtrIfMatch(const AccountTokenVec *vec, const char *userId)
{
    if (userId == NULL) {
        LOGE("Invalid input param.");
        return NULL;
    }
    uint32_t index;
    AccountToken **token;
    FOR_EACH_HC_VECTOR(*vec, index, token) {
        if ((token == NULL) || (*token == NULL)) {
            continue;
        }
        if (strcmp(userId, (const char *)((*token)->pkInfo.userId.val)) == 0) {
            return token;
        }
    }
    return NULL;
}

static AccountToken *GetAccountToken(int32_t osAccountId, const char *userId)
{
    g_accountDbMutex->lock(g_accountDbMutex);
    OsAccountTokenInfo *info = GetTokenInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        LOGE("Failed to get token by osAccountId");
        g_accountDbMutex->unlock(g_accountDbMutex);
        return NULL;
    }
    AccountToken **token = QueryTokenPtrIfMatch(&info->tokens, userId);
    if ((token == NULL) || (*token == NULL)) {
        LOGE("Query token failed");
        g_accountDbMutex->unlock(g_accountDbMutex);
        return NULL;
    }
    g_accountDbMutex->unlock(g_accountDbMutex);
    return *token;
}

static int32_t DeleteTokenInner(int32_t osAccountId, const char *userId, AccountTokenVec *deleteTokens)
{
    LOGI("Start to delete tokens from database!");
    g_accountDbMutex->lock(g_accountDbMutex);
    OsAccountTokenInfo *info = GetTokenInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        LOGE("Failed to get token by os account id");
        g_accountDbMutex->unlock(g_accountDbMutex);
        return HC_ERROR;
    }
    int32_t count = 0;
    uint32_t index = 0;
    AccountToken **token = NULL;
    while (index < HC_VECTOR_SIZE(&info->tokens)) {
        token = info->tokens.getp(&info->tokens, index);
        if ((token == NULL) || (*token == NULL) ||
            strcmp(userId, (const char *)((*token)->pkInfo.userId.val)) != 0) {
            index++;
            continue;
        }
        AccountToken *deleteToken = NULL;
        HC_VECTOR_POPELEMENT(&info->tokens, &deleteToken, index);
        count++;
        LOGI("Delete a token from database successfully!");
        if (deleteTokens->pushBackT(deleteTokens, deleteToken) == NULL) {
            LOGE("Failed to push deleted token to vec");
            DestroyAccountToken(deleteToken);
        }
    }
    g_accountDbMutex->unlock(g_accountDbMutex);
    if (count == 0) {
        LOGE("No token deleted");
        return HC_ERROR;
    }
    LOGI("Number of tokens deleted: %d", count);
    return HC_SUCCESS;
}

static int32_t GetToken(int32_t osAccountId, AccountToken *token, const char *userId)
{
    if ((token == NULL) || (userId == NULL)) {
        LOGE("Invalid input params");
        return HC_ERR_NULL_PTR;
    }
    AccountToken *existToken = GetAccountToken(osAccountId, userId);
    if (existToken == NULL) {
        LOGE("Token not exist");
        return HC_ERROR;
    }
    int32_t ret = GeneratePkInfoFromInfo(&existToken->pkInfo, &token->pkInfo);
    if (ret != HC_SUCCESS) {
        LOGE("Generate pkInfo failed");
        return ret;
    }
    GOTO_ERR_AND_SET_RET(memcpy_s(token->pkInfoStr.val, token->pkInfoStr.length,
        existToken->pkInfoStr.val, existToken->pkInfoStr.length), ret);
    token->pkInfoStr.length = existToken->pkInfoStr.length;
    GOTO_ERR_AND_SET_RET(memcpy_s(token->pkInfoSignature.val, token->pkInfoSignature.length,
        existToken->pkInfoSignature.val, existToken->pkInfoSignature.length), ret);
    token->pkInfoSignature.length = existToken->pkInfoSignature.length;
    GOTO_ERR_AND_SET_RET(memcpy_s(token->serverPk.val, token->serverPk.length,
        existToken->serverPk.val, existToken->serverPk.length), ret);
    token->serverPk.length = existToken->serverPk.length;

    ret = HC_SUCCESS;
    LOGI("GetToken successfully!");
ERR:
    return ret;
}

static int32_t AddTokenInner(int32_t osAccountId, const AccountToken *token)
{
    LOGI("Start to add a token to database!");
    g_accountDbMutex->lock(g_accountDbMutex);
    OsAccountTokenInfo *info = GetTokenInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        LOGE("Failed to get token by os account id");
        g_accountDbMutex->unlock(g_accountDbMutex);
        return HC_ERROR;
    }
    AccountToken *newToken = DeepCopyToken(token);
    if (newToken == NULL) {
        LOGE("Deep copy token failed");
        g_accountDbMutex->unlock(g_accountDbMutex);
        return HC_ERR_MEMORY_COPY;
    }
    AccountToken **oldTokenPtr = QueryTokenPtrIfMatch(&info->tokens, (const char *)(newToken->pkInfo.userId.val));
    if (oldTokenPtr != NULL) {
        DestroyAccountToken(*oldTokenPtr);
        *oldTokenPtr = newToken;
        g_accountDbMutex->unlock(g_accountDbMutex);
        LOGI("Replace an old token successfully!");
        return HC_SUCCESS;
    }
    if (info->tokens.pushBackT(&info->tokens, newToken) == NULL) {
        DestroyAccountToken(newToken);
        g_accountDbMutex->unlock(g_accountDbMutex);
        LOGE("Failed to push token to vec!");
        return HC_ERR_MEMORY_COPY;
    }
    g_accountDbMutex->unlock(g_accountDbMutex);
    LOGI("Add a token to database successfully!");
    return HC_SUCCESS;
}

static int32_t DoExportPkAndCompare(const char *userId, const char *deviceId,
    const char *devicePk, Uint8Buff *keyAlias)
{
    g_accountDbMutex->lock(g_accountDbMutex);
    int32_t ret = GenerateKeyAlias(userId, deviceId, keyAlias, false);
    if (ret != HC_SUCCESS) {
        LOGE("Generate key alias failed.");
        g_accountDbMutex->unlock(g_accountDbMutex);
        return ret;
    }
    ret = g_algLoader->checkKeyExist(keyAlias);
    if (ret != HAL_SUCCESS) {
        LOGE("Key pair not exist.");
        g_accountDbMutex->unlock(g_accountDbMutex);
        return ret;
    }
    uint8_t *publicKeyVal = (uint8_t *)HcMalloc(PK_SIZE, 0);
    if (publicKeyVal == NULL) {
        LOGE("Malloc publicKeyVal failed");
        g_accountDbMutex->unlock(g_accountDbMutex);
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff publicKey = {
        .val = publicKeyVal,
        .length = PK_SIZE
    };
    ret = g_algLoader->exportPublicKey(keyAlias, &publicKey);
    if (ret != HAL_SUCCESS) {
        LOGE("Failed to export public key");
        HcFree(publicKeyVal);
        g_accountDbMutex->unlock(g_accountDbMutex);
        return ret;
    }
    g_accountDbMutex->unlock(g_accountDbMutex);
    if (strcmp((const char *)devicePk, (const char *)publicKeyVal) == 0) {
        HcFree(publicKeyVal);
        return HC_SUCCESS;
    }
    HcFree(publicKeyVal);
    return HC_ERROR;
}

static int32_t CheckDevicePk(const CJson *credJson)
{
    CJson *pkInfoJson = GetObjFromJson(credJson, FIELD_PK_INFO);
    if (pkInfoJson == NULL) {
        LOGE("Failed to get pkInfoJson");
        return HC_ERR_JSON_GET;
    }
    const char *userId = GetStringFromJson(pkInfoJson, FIELD_USER_ID);
    if (userId == NULL) {
        LOGE("Failed to get userId");
        return HC_ERR_JSON_GET;
    }
    const char *deviceId = GetStringFromJson(pkInfoJson, FIELD_DEVICE_ID);
    if (deviceId == NULL) {
        LOGE("Failed to get deviceId");
        return HC_ERR_JSON_GET;
    }
    uint8_t *devicePk = (uint8_t *)HcMalloc(PK_SIZE, 0);
    if (devicePk == NULL) {
        LOGE("Malloc devicePk failed");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetByteFromJson(pkInfoJson, FIELD_DEVICE_PK, devicePk, PK_SIZE) != HC_SUCCESS) {
        LOGE("Failed to get devicePk");
        HcFree(devicePk);
        return HC_ERR_JSON_GET;
    }
    uint8_t *keyAliasValue = (uint8_t *)HcMalloc(SHA256_LEN, 0);
    if (keyAliasValue == NULL) {
        LOGE("Malloc keyAliasValue failed");
        HcFree(devicePk);
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff keyAlias = {
        .val = keyAliasValue,
        .length = SHA256_LEN
    };
    int32_t ret = DoExportPkAndCompare(userId, deviceId, (const char *)devicePk, &keyAlias);
    HcFree(devicePk);
    HcFree(keyAliasValue);
    if (ret == HC_SUCCESS) {
        LOGI("Check devicePk success");
    } else {
        LOGE("Check devicePk failed");
    }
    return ret;
}

static int32_t CheckUserId(const char *userId, const CJson *in)
{
    CJson *pkInfoJson = GetObjFromJson(in, FIELD_PK_INFO);
    if (pkInfoJson == NULL) {
        LOGE("Failed to get pkInfoJson");
        return HC_ERR_JSON_GET;
    }
    const char *userIdFromPk = GetStringFromJson(pkInfoJson, FIELD_USER_ID);
    if (userIdFromPk == NULL) {
        LOGE("Failed to get userIdFromPk");
        return HC_ERR_JSON_GET;
    }
    if (strcmp(userId, userIdFromPk) == 0) {
        return HC_SUCCESS;
    }
    return HC_ERROR;
}

static int32_t CheckCredValidity(const CJson *in)
{
    const char *userId = GetStringFromJson(in, FIELD_USER_ID);
    if (userId == NULL) {
        LOGE("Failed to get userId");
        return HC_ERR_JSON_GET;
    }
    int32_t ret = VerifySignature(in);
    if (ret != HC_SUCCESS) {
        LOGE("Verify server credential failed!");
        return ret;
    }
    ret = CheckDevicePk(in);
    if (ret != HC_SUCCESS) {
        LOGE("Check devicePk failed!");
        return ret;
    }
    ret = CheckUserId(userId, in);
    if (ret != HC_SUCCESS) {
        LOGE("Check userId failed!");
    }
    return ret;
}

static int32_t AddToken(int32_t osAccountId, const CJson *in, CJson *out)
{
    (void)out;
    if (in == NULL) {
        LOGE("Input param is null!");
        return HC_ERR_NULL_PTR;
    }
    int32_t ret = CheckCredValidity(in);
    if (ret != HC_SUCCESS) {
        LOGE("Invalid credential");
        return ret;
    }
    AccountToken *token = CreateAccountToken();
    if (token == NULL) {
        LOGE("Failed to allocate token memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    ret = GenerateTokenFromJson(in, token);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate token");
        DestroyAccountToken(token);
        return ret;
    }
    ret = AddTokenInner(osAccountId, token);
    DestroyAccountToken(token);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to add token inner");
        return ret;
    }
    ret = SaveOsAccountTokenDb(osAccountId);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to save token to db");
    }
    return ret;
}

static int32_t DoGenerateAndExportPk(const char *userId, const char *deviceId,
    Uint8Buff *keyAlias, Uint8Buff *publicKey)
{
    g_accountDbMutex->lock(g_accountDbMutex);
    int32_t ret = GenerateKeyAlias(userId, deviceId, keyAlias, false);
    if (ret != HC_SUCCESS) {
        LOGE("Generate key alias failed");
        g_accountDbMutex->unlock(g_accountDbMutex);
        return ret;
    }
    ret = g_algLoader->checkKeyExist(keyAlias);
    if (ret != HAL_SUCCESS) {
        LOGI("Key pair not exist, start to generate");
        int32_t authId = 0;
        Uint8Buff authIdBuff = { (uint8_t *)&authId, sizeof(int32_t) };
        ExtraInfo extInfo = { authIdBuff, -1, -1 };
        ret = g_algLoader->generateKeyPairWithStorage(keyAlias, SELF_ECC_KEY_LEN, P256, &extInfo);
    } else {
        LOGI("Key pair already exists");
    }
    if (ret != HAL_SUCCESS) {
        LOGE("Generate key pair failed");
        g_accountDbMutex->unlock(g_accountDbMutex);
        return ret;
    }
    ret = g_algLoader->exportPublicKey(keyAlias, publicKey);
    g_accountDbMutex->unlock(g_accountDbMutex);
    return ret;
}

static int32_t GetRegisterProof(const CJson *in, CJson *out)
{
    const char *userId = GetStringFromJson(in, FIELD_USER_ID);
    if (userId == NULL) {
        LOGE("Failed to get userId!");
        return HC_ERR_JSON_GET;
    }
    const char *version = GetStringFromJson(in, FIELD_VERSION);
    if (version == NULL) {
        LOGE("Failed to get version!");
        return HC_ERR_JSON_GET;
    }
    const char *deviceId = GetStringFromJson(in, FIELD_DEVICE_ID);
    if (deviceId == NULL) {
        LOGE("Failed to get deviceId!");
        return HC_ERR_JSON_GET;
    }
    uint8_t *keyAliasValue = (uint8_t *)HcMalloc(SHA256_LEN, 0);
    if (keyAliasValue == NULL) {
        LOGE("Malloc keyAliasValue failed");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff keyAlias = {
        .val = keyAliasValue,
        .length = SHA256_LEN
    };
    uint8_t *publicKeyVal = (uint8_t *)HcMalloc(PK_SIZE, 0);
    if (publicKeyVal == NULL) {
        LOGE("Malloc publicKeyVal failed");
        HcFree(keyAliasValue);
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff publicKey = {
        .val = publicKeyVal,
        .length = PK_SIZE
    };
    int32_t ret = DoGenerateAndExportPk(userId, deviceId, &keyAlias, &publicKey);
    HcFree(keyAliasValue);
    if (ret != HC_SUCCESS) {
        LOGE("exportPublicKey failed");
        goto ERR;
    }
    GOTO_ERR_AND_SET_RET(AddByteToJson(out, FIELD_DEVICE_PK, publicKeyVal, publicKey.length), ret);
    GOTO_ERR_AND_SET_RET(AddStringToJson(out, FIELD_USER_ID, userId), ret);
    GOTO_ERR_AND_SET_RET(AddStringToJson(out, FIELD_DEVICE_ID, deviceId), ret);
    GOTO_ERR_AND_SET_RET(AddStringToJson(out, FIELD_VERSION, version), ret);
    LOGI("Generate register proof successfully!");
ERR:
    HcFree(publicKeyVal);
    return ret;
}

static int32_t GetServerPublicKey(int32_t osAccountId, const char *userId, Uint8Buff *serverPk)
{
    if ((userId == NULL) || (serverPk == NULL)) {
        LOGE("Invalid input params");
        return HC_ERR_NULL_PTR;
    }
    AccountToken *token = GetAccountToken(osAccountId, userId);
    if (token == NULL) {
        LOGE("Token not exist");
        return HC_ERROR;
    }
    if (memcpy_s(serverPk->val, serverPk->length, token->serverPk.val, token->serverPk.length) != HC_SUCCESS) {
        LOGE("Memcpy for serverPk failed");
        return HC_ERR_MEMORY_COPY;
    }
    serverPk->length = token->serverPk.length;
    return HC_SUCCESS;
}

static Algorithm GetAlgVersion(int32_t osAccountId, const char *userId)
{
    if (userId == NULL) {
        LOGE("Invalid input params, return default alg.");
        return P256;
    }
    AccountToken *token = GetAccountToken(osAccountId, userId);
    if (token == NULL) {
        LOGE("Token not exist, return default alg.");
        return P256;
    }
    return GetVerifyAlg((const char *)token->pkInfo.version.val);
}

static void DeleteKeyPair(AccountToken *token)
{
    uint8_t *keyAliasValue = (uint8_t *)HcMalloc(SHA256_LEN, 0);
    if (keyAliasValue == NULL) {
        LOGE("Malloc keyAliasValue failed");
        return;
    }
    Uint8Buff keyAlias = {
        .val = keyAliasValue,
        .length = SHA256_LEN
    };
    g_accountDbMutex->lock(g_accountDbMutex);
    if (GenerateKeyAlias((const char *)token->pkInfo.userId.val,
        (const char *)token->pkInfo.deviceId.val, &keyAlias, false) != HC_SUCCESS) {
        LOGE("Failed to generate key alias");
        HcFree(keyAliasValue);
        g_accountDbMutex->unlock(g_accountDbMutex);
        return;
    }
    if (g_algLoader->deleteKey(&keyAlias) != HAL_SUCCESS) {
        LOGE("Failed to delete key pair");
    } else {
        LOGI("Delete key pair success");
    }
    HcFree(keyAliasValue);
    g_accountDbMutex->unlock(g_accountDbMutex);
}

static int32_t DeleteToken(int32_t osAccountId, const char *userId)
{
    if (userId == NULL) {
        LOGE("Invalid user id");
        return HC_ERR_NULL_PTR;
    }
    AccountTokenVec deleteTokens = CreateAccountTokenVec();
    int32_t ret = DeleteTokenInner(osAccountId, userId, &deleteTokens);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to delete token inner, account id is: %d", osAccountId);
        DestroyAccountTokenVec(&deleteTokens);
        return ret;
    }
    ret = SaveOsAccountTokenDb(osAccountId);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to save token to db, account id is: %d", osAccountId);
        ClearAccountTokenVec(&deleteTokens);
        return ret;
    }
    uint32_t index;
    AccountToken **token;
    FOR_EACH_HC_VECTOR(deleteTokens, index, token) {
        if ((token != NULL) && (*token != NULL)) {
            DeleteKeyPair(*token);
        }
    }
    ClearAccountTokenVec(&deleteTokens);
    return HC_SUCCESS;
}

static void LoadOsAccountTokenDb(int32_t osAccountId)
{
    OsAccountTokenInfo info;
    info.osAccountId = osAccountId;
    info.tokens = CreateAccountTokenVec();
    if (ReadTokensFromFile(osAccountId, &info.tokens) != HC_SUCCESS) {
        DestroyAccountTokenVec(&info.tokens);
        return;
    }
    if (g_accountTokenDb.pushBackT(&g_accountTokenDb, info) == NULL) {
        LOGE("Failed to push osAccountInfo to database!");
        ClearAccountTokenVec(&info.tokens);
    }
    LOGI("Load os account db successfully! [Id]: %d", osAccountId);
}

static void LoadTokenDb(void)
{
    StringVector dbNameVec = CreateStrVector();
    HcFileGetSubFileName(GetAccountStoragePath(), &dbNameVec);
    uint32_t index;
    HcString *dbName = NULL;
    FOR_EACH_HC_VECTOR(dbNameVec, index, dbName) {
        int32_t osAccountId;
        const char *name = StringGet(dbName);
        if (name == NULL) {
            continue;
        }
        if (strcmp(name, "account_data_asy.dat") == 0) {
            LoadOsAccountTokenDb(DEFAULT_OS_ACCOUNT);
        } else if (sscanf_s(name, "account_data_asy%d.dat", &osAccountId) == 1) {
            LoadOsAccountTokenDb(osAccountId);
        }
    }
    DestroyStrVector(&dbNameVec);
}

void InitTokenManager(void)
{
    if (g_accountDbMutex == NULL) {
        g_accountDbMutex = (HcMutex *)HcMalloc(sizeof(HcMutex), 0);
        if (g_accountDbMutex == NULL) {
            LOGE("Alloc account database mutex failed.");
            return;
        }
        if (InitHcMutex(g_accountDbMutex) != HC_SUCCESS) {
            LOGE("Init account mutex failed.");
            HcFree(g_accountDbMutex);
            g_accountDbMutex = NULL;
            return;
        }
    }
    g_accountDbMutex->lock(g_accountDbMutex);
    (void)memset_s(&g_asyTokenManager, sizeof(AccountAuthTokenManager), 0, sizeof(AccountAuthTokenManager));
    g_asyTokenManager.addToken = AddToken;
    g_asyTokenManager.getToken = GetToken;
    g_asyTokenManager.deleteToken = DeleteToken;
    g_asyTokenManager.getRegisterProof = GetRegisterProof;
    g_asyTokenManager.getServerPublicKey = GetServerPublicKey;
    g_asyTokenManager.generateKeyAlias = GenerateKeyAlias;
    g_asyTokenManager.getAlgVersion = GetAlgVersion;
    if (!g_isInitial) {
        g_accountTokenDb = CREATE_HC_VECTOR(AccountTokenDb);
        g_isInitial = true;
    }

    LoadTokenDb();
    g_algLoader = GetLoaderInstance();
    if (g_algLoader == NULL) {
        LOGE("Get loader failed.");
        g_accountDbMutex->unlock(g_accountDbMutex);
        return;
    }
    int32_t res = g_algLoader->initAlg();
    if (res != HAL_SUCCESS) {
        LOGE("Failed to init algorithm!");
    }
    g_accountDbMutex->unlock(g_accountDbMutex);
}

void ClearAccountTokenVec(AccountTokenVec *vec)
{
    uint32_t index;
    AccountToken **token;
    FOR_EACH_HC_VECTOR(*vec, index, token) {
        DestroyAccountToken(*token);
    }
    DESTROY_HC_VECTOR(AccountTokenVec, vec);
}

static void InitTokenData(AccountToken *token)
{
    token->pkInfoStr.val = NULL;
    token->pkInfoSignature.val = NULL;
    token->serverPk.val = NULL;
    token->pkInfo.deviceId.val = NULL;
    token->pkInfo.userId.val = NULL;
    token->pkInfo.version.val = NULL;
    token->pkInfo.devicePk.val = NULL;
}

AccountToken *CreateAccountToken(void)
{
    AccountToken *token = (AccountToken *)HcMalloc(sizeof(AccountToken), 0);
    if (token == NULL) {
        LOGE("Failed to allocate accountToken memory!");
        return NULL;
    }
    InitTokenData(token);
    token->pkInfoStr.val = (uint8_t *)HcMalloc(PUBLIC_KEY_INFO_SIZE, 0);
    GOTO_IF_CHECK_NULL(token->pkInfoStr.val, "pkInfoStr");
    token->pkInfoStr.length = PUBLIC_KEY_INFO_SIZE;
    token->pkInfoSignature.val = (uint8_t *)HcMalloc(SIGNATURE_SIZE, 0);
    GOTO_IF_CHECK_NULL(token->pkInfoSignature.val, "pkInfoSignature");
    token->pkInfoSignature.length = SIGNATURE_SIZE;
    token->serverPk.val = (uint8_t *)HcMalloc(SERVER_PK_SIZE, 0);
    GOTO_IF_CHECK_NULL(token->serverPk.val, "serverPk");
    token->serverPk.length = SERVER_PK_SIZE;
    token->pkInfo.deviceId.val = (uint8_t *)HcMalloc(DEV_AUTH_DEVICE_ID_SIZE, 0);
    GOTO_IF_CHECK_NULL(token->pkInfo.deviceId.val, "deviceId");
    token->pkInfo.deviceId.length = DEV_AUTH_DEVICE_ID_SIZE;
    token->pkInfo.userId.val = (uint8_t *)HcMalloc(DEV_AUTH_USER_ID_SIZE, 0);
    GOTO_IF_CHECK_NULL(token->pkInfo.userId.val, "userId");
    token->pkInfo.userId.length = DEV_AUTH_USER_ID_SIZE;
    token->pkInfo.version.val = (uint8_t *)HcMalloc(PK_VERSION_SIZE, 0);
    GOTO_IF_CHECK_NULL(token->pkInfo.version.val, "version");
    token->pkInfo.version.length = PK_VERSION_SIZE;
    token->pkInfo.devicePk.val = (uint8_t *)HcMalloc(PK_SIZE, 0);
    GOTO_IF_CHECK_NULL(token->pkInfo.devicePk.val, "devicePk");
    token->pkInfo.devicePk.length = PK_SIZE;
    return token;
ERR:
    DestroyAccountToken(token);
    return NULL;
}

void DestroyAccountToken(AccountToken *token)
{
    if (token == NULL) {
        LOGE("Input token is null");
        return;
    }
    HcFree(token->pkInfoStr.val);
    token->pkInfoStr.length = 0;
    HcFree(token->pkInfoSignature.val);
    token->pkInfoSignature.length = 0;
    HcFree(token->serverPk.val);
    token->serverPk.length = 0;
    HcFree(token->pkInfo.deviceId.val);
    token->pkInfo.deviceId.length = 0;
    HcFree(token->pkInfo.userId.val);
    token->pkInfo.userId.length = 0;
    HcFree(token->pkInfo.version.val);
    token->pkInfo.version.length = 0;
    HcFree(token->pkInfo.devicePk.val);
    token->pkInfo.devicePk.length = 0;
    HcFree(token);
}

AccountAuthTokenManager *GetAccountAuthTokenManager(void)
{
    return &g_asyTokenManager;
}

void DestroyTokenManager(void)
{
    g_accountDbMutex->lock(g_accountDbMutex);
    g_algLoader = NULL;
    (void)memset_s(&g_asyTokenManager, sizeof(AccountAuthTokenManager), 0, sizeof(AccountAuthTokenManager));
    uint32_t index;
    OsAccountTokenInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_accountTokenDb, index, info) {
        ClearAccountTokenVec(&info->tokens);
    }
    DESTROY_HC_VECTOR(AccountTokenDb, &g_accountTokenDb);
    g_isInitial = false;
    g_accountDbMutex->unlock(g_accountDbMutex);
    if (g_accountDbMutex != NULL) {
        DestroyHcMutex(g_accountDbMutex);
        HcFree(g_accountDbMutex);
        g_accountDbMutex = NULL;
    }
}