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

#include "across_account_group.h"

#include "account_module.h"
#include "alg_defs.h"
#include "callback_manager.h"
#include "common_defs.h"
#include "data_manager.h"
#include "device_auth_defines.h"
#include "dev_auth_module_manager.h"
#include "group_operation_common.h"
#include "hc_log.h"
#include "string_util.h"

/* 1: s1 > s2, -1: s1 <= s2 */
static int32_t CompareString(const char *s1, const char *s2)
{
    if ((s1 == NULL) || (s2 == NULL)) {
        LOGE("The input string contains NULL value!");
        return 0;
    }
    const char *tempChar1 = s1;
    const char *tempChar2 = s2;
    while ((*tempChar1 != '\0') && (*tempChar2 != '\0')) {
        if (*tempChar1 > *tempChar2) {
            return 1;
        } else if (*tempChar1 < *tempChar2) {
            return -1;
        }
        tempChar1++;
        tempChar2++;
    }
    if (*tempChar1 != '\0') {
        return 1;
    }
    return -1;
}

static int32_t GenerateGroupId(const char *userId, const char *sharedUserId, char **returnGroupId)
{
    /* across account group: groupId = sha256(userId1 | userId2) */
    uint8_t *hashMessage = NULL;
    uint32_t messageSize = 0;
    const char *firstUserId = userId;
    const char *secondUserId = sharedUserId;
    if (CompareString(firstUserId, secondUserId) > 0) {
        firstUserId = sharedUserId;
        secondUserId = userId;
    }
    Uint8Buff firstUserIdBuff = { (uint8_t *)firstUserId, HcStrlen(firstUserId) };
    Uint8Buff secondUserIdBuff = { (uint8_t *)secondUserId, HcStrlen(secondUserId) };
    int32_t result = GetHashMessage(&firstUserIdBuff, &secondUserIdBuff, &hashMessage, &messageSize);
    if (result != HC_SUCCESS) {
        return result;
    }
    int hashStrLen = SHA256_LEN * BYTE_TO_HEX_OPER_LENGTH + 1;
    *returnGroupId = (char *)HcMalloc(hashStrLen, 0);
    if (*returnGroupId == NULL) {
        LOGE("Failed to allocate returnGroupId memory!");
        HcFree(hashMessage);
        return HC_ERR_ALLOC_MEMORY;
    }
    result = GetHashResult(hashMessage, messageSize, *returnGroupId, hashStrLen);
    HcFree(hashMessage);
    if (result != HC_SUCCESS) {
        LOGE("Failed to get hash for groupId!");
        HcFree(*returnGroupId);
        *returnGroupId = NULL;
        return HC_ERR_HASH_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t GenerateDevParams(const CJson *jsonParams, const char *groupId, TrustedDeviceEntry *devParams)
{
    int32_t result;
    if (((result = AddSelfUdidToParams(devParams)) != HC_SUCCESS) ||
        ((result = AddAuthIdToParamsOrDefault(jsonParams, devParams)) != HC_SUCCESS) ||
        ((result = AddUserIdToDevParams(jsonParams, devParams)) != HC_SUCCESS) ||
        ((result = AddUserTypeToParamsOrDefault(jsonParams, devParams)) != HC_SUCCESS) ||
        ((result = AddGroupIdToDevParams(groupId, devParams)) != HC_SUCCESS) ||
        ((result = AddServiceTypeToParams(groupId, devParams)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t GenerateGroupParams(const CJson *jsonParams, const char *groupId, TrustedGroupEntry *groupParams)
{
    const char *appId = GetStringFromJson(jsonParams, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("Failed to get appId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    int32_t result;
    if (((result = AddGroupTypeToParams(ACROSS_ACCOUNT_AUTHORIZE_GROUP, groupParams)) != HC_SUCCESS) ||
        ((result = AddGroupNameToParams(groupId, groupParams)) != HC_SUCCESS) ||
        ((result = AddGroupIdToParams(groupId, groupParams)) != HC_SUCCESS) ||
        ((result = AddUserIdToGroupParams(jsonParams, groupParams)) != HC_SUCCESS) ||
        ((result = AddSharedUserIdToGroupParams(jsonParams, groupParams)) != HC_SUCCESS) ||
        ((result = AddGroupOwnerToParams(appId, groupParams)) != HC_SUCCESS) ||
        ((result = AddGroupVisibilityOrDefault(jsonParams, groupParams)) != HC_SUCCESS) ||
        ((result = AddExpireTimeOrDefault(jsonParams, groupParams)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t GenerateAcrossAccountGroupId(const CJson *jsonParams, char **returnGroupId)
{
    char *userId = NULL;
    char *sharedUserId = NULL;
    int32_t result = GetUserIdFromJson(jsonParams, &userId);
    if (result != HC_SUCCESS) {
        return result;
    }
    result = GetSharedUserIdFromJson(jsonParams, &sharedUserId);
    if (result != HC_SUCCESS) {
        HcFree(userId);
        return result;
    }
    result = GenerateGroupId(userId, sharedUserId, returnGroupId);
    HcFree(userId);
    HcFree(sharedUserId);
    if (result != HC_SUCCESS) {
        LOGE("Failed to generate groupId!");
        return result;
    }
    return HC_SUCCESS;
}

static int32_t AssertIdenticalGroupExist(int32_t osAccountId, const CJson *jsonParams)
{
    char *userId = NULL;
    int32_t result = GetUserIdFromJson(jsonParams, &userId);
    if (result != HC_SUCCESS) {
        return result;
    }
    GroupEntryVec groupEntryVec = CreateGroupEntryVec();
    QueryGroupParams params = InitQueryGroupParams();
    params.groupType = IDENTICAL_ACCOUNT_GROUP;
    result = QueryGroups(osAccountId, &params, &groupEntryVec);
    if (result != HC_SUCCESS) {
        LOGE("Failed to query groups!");
        HcFree(userId);
        ClearGroupEntryVec(&groupEntryVec);
        return result;
    }
    bool isExist = false;
    uint32_t index;
    TrustedGroupEntry **entry = NULL;
    FOR_EACH_HC_VECTOR(groupEntryVec, index, entry) {
        if ((entry != NULL) && (*entry != NULL) && (strcmp(userId, StringGet(&((*entry)->userId))) == 0)) {
            isExist = true;
            break;
        }
    }
    HcFree(userId);
    ClearGroupEntryVec(&groupEntryVec);
    if (!isExist) {
        LOGE("The identical account group has not been created!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    return HC_SUCCESS;
}

static int32_t CheckCreateParams(int32_t osAccountId, const CJson *jsonParams)
{
    const char *appId = GetStringFromJson(jsonParams, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("Failed to get appId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    int32_t result;
    if (((result = CheckUserTypeIfExist(jsonParams)) != HC_SUCCESS) ||
        ((result = CheckGroupVisibilityIfExist(jsonParams)) != HC_SUCCESS) ||
        ((result = CheckExpireTimeIfExist(jsonParams)) != HC_SUCCESS) ||
        ((result = AssertUserIdExist(jsonParams)) != HC_SUCCESS) ||
        ((result = AssertSharedUserIdExist(jsonParams)) != HC_SUCCESS) ||
        ((result = AssertIdenticalGroupExist(osAccountId, jsonParams)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t GenerateAddTokenParams(const CJson *jsonParams, CJson *addParams)
{
    const char *userId = GetStringFromJson(jsonParams, FIELD_USER_ID);
    if (userId == NULL) {
        LOGE("Failed to get userId from json!");
        return HC_ERR_JSON_GET;
    }
    const char *deviceId = GetStringFromJson(jsonParams, FIELD_DEVICE_ID);
    if (deviceId == NULL) {
        LOGE("Failed to get deviceId from json!");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(addParams, FIELD_DEVICE_ID, deviceId) != HC_SUCCESS) {
        LOGE("Failed to add deviceId to json!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(addParams, FIELD_USER_ID, userId) != HC_SUCCESS) {
        LOGE("Failed to add userId to json!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t GenerateDelTokenParams(const TrustedDeviceEntry *entry, CJson *delParams)
{
    if (AddIntToJson(delParams, FIELD_CREDENTIAL_TYPE, (int32_t)entry->credential) != HC_SUCCESS) {
        LOGE("Failed to add credentialType to json!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(delParams, FIELD_USER_ID, StringGet(&entry->userId)) != HC_SUCCESS) {
        LOGE("Failed to add userId to json!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(delParams, FIELD_DEVICE_ID, StringGet(&entry->authId)) != HC_SUCCESS) {
        LOGE("Failed to add deviceId to json!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t DelPeerDeviceToken(int32_t osAccountId, const TrustedDeviceEntry *entry)
{
    CJson *delParams = CreateJson();
    if (delParams == NULL) {
        LOGE("Failed to allocate delParams memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = GenerateDelTokenParams(entry, delParams);
    if (res != HC_SUCCESS) {
        FreeJson(delParams);
        return res;
    }
    res = ProcessAccountCredentials(osAccountId, DELETE_TRUSTED_CREDENTIALS, delParams, NULL);
    FreeJson(delParams);
    return res;
}

static void DelAllPeerTokens(int32_t osAccountId, const DeviceEntryVec *vec)
{
    int32_t res;
    uint32_t index;
    TrustedDeviceEntry **entry = NULL;
    FOR_EACH_HC_VECTOR(*vec, index, entry) {
        if ((entry == NULL) || (*entry == NULL) || (IsLocalDevice(StringGet(&(*entry)->udid)))) {
            continue;
        }
        res = DelPeerDeviceToken(osAccountId, *entry);
        if (res != HC_SUCCESS) {
            LOGE("Failed to delete peer device token! res: %d", res);
        }
    }
}

static int32_t DelGroupAndTokens(int32_t osAccountId, const char *groupId)
{
    DeviceEntryVec deviceList = CreateDeviceEntryVec();
    (void)GetTrustedDevices(osAccountId, groupId, &deviceList);
    int32_t res = DelGroupFromDb(osAccountId, groupId);
    DelAllPeerTokens(osAccountId, &deviceList);
    ClearDeviceEntryVec(&deviceList);
    return res;
}

static int32_t CheckChangeParams(int32_t osAccountId, const char *appId, CJson *jsonParams)
{
    const char *groupId = GetStringFromJson(jsonParams, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from json!");
        return HC_ERR_JSON_GET;
    }
    int32_t groupType;
    int32_t result;
    if (((result = CheckGroupExist(osAccountId, groupId)) != HC_SUCCESS) ||
        ((result = GetGroupTypeFromDb(osAccountId, groupId, &groupType)) != HC_SUCCESS) ||
        ((result = AssertGroupTypeMatch(groupType, ACROSS_ACCOUNT_AUTHORIZE_GROUP)) != HC_SUCCESS) ||
        ((result = CheckGroupEditAllowed(osAccountId, groupId, appId)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t DelDeviceById(int32_t osAccountId, const char *groupId, const char *deviceId, bool isUdid)
{
    QueryDeviceParams queryDeviceParams = InitQueryDeviceParams();
    queryDeviceParams.groupId = groupId;
    if (isUdid) {
        queryDeviceParams.udid = deviceId;
    } else {
        queryDeviceParams.authId = deviceId;
    }
    return DelTrustedDevice(osAccountId, &queryDeviceParams);
}

static int32_t GenerateTrustedDevParams(const CJson *jsonParams, const char *groupId, TrustedDeviceEntry *devParams)
{
    int32_t result;
    if (((result = AddUdidToParams(jsonParams, devParams)) != HC_SUCCESS) ||
        ((result = AddAuthIdToParams(jsonParams, devParams)) != HC_SUCCESS) ||
        ((result = AddCredTypeToParams(jsonParams, devParams)) != HC_SUCCESS) ||
        ((result = AddUserIdToDevParams(jsonParams, devParams)) != HC_SUCCESS) ||
        ((result = AddUserTypeToParamsOrDefault(jsonParams, devParams)) != HC_SUCCESS) ||
        ((result = AddGroupIdToDevParams(groupId, devParams)) != HC_SUCCESS) ||
        ((result = AddServiceTypeToParams(groupId, devParams)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t AddDeviceAndToken(int32_t osAccountId, CJson *jsonParams, CJson *deviceInfo)
{
    const char *groupId = GetStringFromJson(jsonParams, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from json!");
        return HC_ERR_JSON_GET;
    }
    CJson *credential = GetObjFromJson(deviceInfo, FIELD_CREDENTIAL);
    if (credential == NULL) {
        LOGE("Failed to get credential from json!");
        return HC_ERR_JSON_GET;
    }
    int32_t res = GenerateAddTokenParams(deviceInfo, credential);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = ProcessAccountCredentials(osAccountId, IMPORT_TRUSTED_CREDENTIALS, credential, NULL);
    if (res != HC_SUCCESS) {
        LOGE("Failed to import device token! res: %d", res);
        return res;
    }
    res = AddDeviceToDatabaseByJson(osAccountId, GenerateTrustedDevParams, deviceInfo, groupId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add device to database! res: %d", res);
    }
    return res;
}

static int32_t DelPeerDeviceAndToken(int32_t osAccountId, CJson *jsonParams, CJson *deviceInfo)
{
    const char *groupId = GetStringFromJson(jsonParams, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from json!");
        return HC_ERR_JSON_GET;
    }
    const char *deviceId = GetStringFromJson(deviceInfo, FIELD_DEVICE_ID);
    if (deviceId == NULL) {
        LOGE("Failed to get deviceId from json!");
        return HC_ERR_JSON_GET;
    }
    TrustedDeviceEntry *entry = GetTrustedDeviceEntryById(osAccountId, deviceId, false, groupId);
    if (entry == NULL) {
        LOGE("Failed to get device from db!");
        return HC_ERR_DEVICE_NOT_EXIST;
    }
    if (IsLocalDevice(StringGet(&entry->udid))) {
        LOGE("Do not delete the local device!");
        DestroyDeviceEntry(entry);
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t res = DelDeviceById(osAccountId, groupId, deviceId, false);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete device from database! res: %d", res);
        DestroyDeviceEntry(entry);
        return res;
    }
    res = DelPeerDeviceToken(osAccountId, entry);
    DestroyDeviceEntry(entry);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete token! res: %d", res);
    }
    return res;
}

static int32_t AddGroupAndLocalDev(int32_t osAccountId, CJson *jsonParams, const char *groupId)
{
    int32_t res = AddGroupToDatabaseByJson(osAccountId, GenerateGroupParams, jsonParams, groupId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add group to database!");
        return res;
    }
    res = AddDeviceToDatabaseByJson(osAccountId, GenerateDevParams, jsonParams, groupId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add device to database!");
        (void)DelGroupFromDb(osAccountId, groupId);
        return res;
    }
    res = SaveOsAccountDb(osAccountId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to save database!");
        (void)DelGroupFromDb(osAccountId, groupId);
    }
    return res;
}

static int32_t CreateGroup(int32_t osAccountId, CJson *jsonParams, char **returnJsonStr)
{
    LOGI("[Start]: Start to create a across account group!");
    if ((jsonParams == NULL) || (returnJsonStr == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    char *groupId = NULL;
    int32_t result;
    if (((result = CheckCreateParams(osAccountId, jsonParams)) != HC_SUCCESS) ||
        ((result = GenerateAcrossAccountGroupId(jsonParams, &groupId)) != HC_SUCCESS) ||
        ((result = AssertSameGroupNotExist(osAccountId, groupId)) != HC_SUCCESS) ||
        ((result = AddGroupAndLocalDev(osAccountId, jsonParams, groupId)) != HC_SUCCESS) ||
        ((result = ConvertGroupIdToJsonStr(groupId, returnJsonStr)) != HC_SUCCESS)) {
        HcFree(groupId);
        return result;
    }
    HcFree(groupId);
    LOGI("[End]: Create a across account group successfully!");
    return HC_SUCCESS;
}

static int32_t DeleteGroup(int32_t osAccountId, CJson *jsonParams, char **returnJsonStr)
{
    LOGI("[Start]: Start to delete a across account group!");
    if ((jsonParams == NULL) || (returnJsonStr == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t result;
    const char *groupId = NULL;
    if (((result = GetGroupIdFromJson(jsonParams, &groupId)) != HC_SUCCESS) ||
        ((result = DelGroupAndTokens(osAccountId, groupId)) != HC_SUCCESS) ||
        ((result = ConvertGroupIdToJsonStr(groupId, returnJsonStr)) != HC_SUCCESS)) {
        return result;
    }
    LOGI("[End]: Delete a across account group successfully!");
    return HC_SUCCESS;
}

static int32_t AddMultiMembersToGroup(int32_t osAccountId, const char *appId, CJson *jsonParams)
{
    LOGI("[Start]: Start to add multiple members to a across account group!");
    if ((appId == NULL) || (jsonParams == NULL)) {
        LOGE("Invalid params!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t res = CheckChangeParams(osAccountId, appId, jsonParams);
    if (res != HC_SUCCESS) {
        return res;
    }
    CJson *deviceList = GetObjFromJson(jsonParams, FIELD_DEVICE_LIST);
    if (deviceList == NULL) {
        LOGE("Failed to get deviceList from json!");
        return HC_ERR_JSON_GET;
    }
    int32_t deviceNum = GetItemNum(deviceList);
    int32_t addedCount = 0;
    for (int32_t i = 0; i < deviceNum; i++) {
        CJson *deviceInfo = GetItemFromArray(deviceList, i);
        if (deviceInfo == NULL) {
            LOGE("The deviceInfo is NULL!");
            continue;
        }
        if (AddDeviceAndToken(osAccountId, jsonParams, deviceInfo) == HC_SUCCESS) {
            addedCount++;
        }
    }
    LOGI("[End]: Add multiple members to a across account group successfully! [ListNum]: %d, [AddedNum]: %d",
        deviceNum, addedCount);
    return HC_SUCCESS;
}

static int32_t DelMultiMembersFromGroup(int32_t osAccountId, const char *appId, CJson *jsonParams)
{
    LOGI("[Start]: Start to delete multiple members from a across account group!");
    if ((appId == NULL) || (jsonParams == NULL)) {
        LOGE("Invalid params!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t res = CheckChangeParams(osAccountId, appId, jsonParams);
    if (res != HC_SUCCESS) {
        return res;
    }
    CJson *deviceList = GetObjFromJson(jsonParams, FIELD_DEVICE_LIST);
    if (deviceList == NULL) {
        LOGE("Failed to get deviceList from json!");
        return HC_ERR_JSON_GET;
    }
    int32_t deviceNum = GetItemNum(deviceList);
    int32_t deletedCount = 0;
    for (int32_t i = 0; i < deviceNum; i++) {
        CJson *deviceInfo = GetItemFromArray(deviceList, i);
        if (deviceInfo == NULL) {
            LOGE("The deviceInfo is NULL!");
            continue;
        }
        if (DelPeerDeviceAndToken(osAccountId, jsonParams, deviceInfo) == HC_SUCCESS) {
            deletedCount++;
        }
    }
    LOGI("[End]: Delete multiple members from a across account group successfully! [ListNum]: %d, [DeletedNum]: %d",
        deviceNum, deletedCount);
    return HC_SUCCESS;
}

static AcrossAccountGroup g_acrossAccountGroup = {
    .base.type = ACROSS_ACCOUNT_AUTHORIZE_GROUP,
    .base.createGroup = CreateGroup,
    .base.deleteGroup = DeleteGroup,
    .addMultiMembersToGroup = AddMultiMembersToGroup,
    .delMultiMembersFromGroup = DelMultiMembersFromGroup,
};

BaseGroup *GetAcrossAccountGroupInstance(void)
{
    return (BaseGroup *)&g_acrossAccountGroup;
}

bool IsAcrossAccountGroupSupported(void)
{
    return true;
}
