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

#include "identical_account_group.h"
#include "alg_defs.h"
#include "callback_manager.h"
#include "common_defs.h"
#include "data_manager.h"
#include "device_auth_defines.h"
#include "group_operation_common.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "string_util.h"
#include "dev_auth_module_manager.h"
#include "account_module.h"

static int32_t GenerateDevParams(const CJson *jsonParams, const char *groupId, TrustedDeviceEntry *devParams)
{
    int32_t result;
    if (((result = AddSelfUdidToParams(devParams)) != HC_SUCCESS) ||
        ((result = AddCredTypeToParams(jsonParams, devParams)) != HC_SUCCESS) ||
        ((result = AddUserIdToDevParams(jsonParams, devParams)) != HC_SUCCESS) ||
        ((result = AddAuthIdToParamsOrDefault(jsonParams, devParams)) != HC_SUCCESS) ||
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
    if (((result = AddGroupTypeToParams(IDENTICAL_ACCOUNT_GROUP, groupParams)) != HC_SUCCESS) ||
        ((result = AddGroupNameToParams(groupId, groupParams)) != HC_SUCCESS) ||
        ((result = AddGroupIdToParams(groupId, groupParams)) != HC_SUCCESS) ||
        ((result = AddUserIdToGroupParams(jsonParams, groupParams)) != HC_SUCCESS) ||
        ((result = AddGroupOwnerToParams(appId, groupParams)) != HC_SUCCESS) ||
        ((result = AddGroupVisibilityOrDefault(jsonParams, groupParams)) != HC_SUCCESS) ||
        ((result = AddExpireTimeOrDefault(jsonParams, groupParams)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t GenerateGroupId(const char *userId, char **returnGroupId)
{
    if ((userId == NULL) || (returnGroupId == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    /* identical account group: groupId = sha256(userId) */
    int hashStrLen = SHA256_LEN * BYTE_TO_HEX_OPER_LENGTH + 1;
    *returnGroupId = (char *)HcMalloc(hashStrLen, 0);
    if (*returnGroupId == NULL) {
        LOGE("Failed to allocate returnGroupId memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(*returnGroupId, hashStrLen, userId, HcStrlen(userId)) != EOK) {
        LOGE("Failed to copy userId for groupId!");
        HcFree(*returnGroupId);
        *returnGroupId = NULL;
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t GenerateIdenticalGroupId(const CJson *jsonParams, char **returnGroupId)
{
    char *userId = NULL;
    int32_t result = GetUserIdFromJson(jsonParams, &userId);
    if (result != HC_SUCCESS) {
        return result;
    }
    result = GenerateGroupId(userId, returnGroupId);
    HcFree(userId);
    if (result != HC_SUCCESS) {
        LOGE("Failed to generate groupId!");
        return result;
    }
    return HC_SUCCESS;
}

static int32_t AssertCredentialExist(const CJson *jsonParams)
{
    CJson *credJson = GetObjFromJson(jsonParams, FIELD_CREDENTIAL);
    if (credJson == NULL) {
        LOGE("Failed to get credential from json!");
        return HC_ERR_JSON_GET;
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
    if (((result = AssertUserIdExist(jsonParams)) != HC_SUCCESS) ||
        ((result = AssertCredentialExist(jsonParams)) != HC_SUCCESS) ||
        ((result = CheckUserTypeIfExist(jsonParams)) != HC_SUCCESS) ||
        ((result = CheckGroupVisibilityIfExist(jsonParams)) != HC_SUCCESS) ||
        ((result = CheckExpireTimeIfExist(jsonParams)) != HC_SUCCESS) ||
        ((result = CheckGroupNumLimit(osAccountId, IDENTICAL_ACCOUNT_GROUP, appId)) != HC_SUCCESS)) {
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

static int32_t ImportSelfToken(int32_t osAccountId, CJson *jsonParams)
{
    const char *userId = GetStringFromJson(jsonParams, FIELD_USER_ID);
    if (userId == NULL) {
        LOGE("Failed to get userId from json!");
        return HC_ERR_JSON_GET;
    }
    const char *deviceId = GetStringFromJson(jsonParams, FIELD_DEVICE_ID);
    char udid[INPUT_UDID_LEN] = { 0 };
    if (deviceId == NULL) {
        LOGD("No deviceId is found. The default value is udid!");
        int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
        if (res != HC_SUCCESS) {
            LOGE("Failed to get local udid! res: %d", res);
            return HC_ERR_DB;
        }
        deviceId = udid;
    }
    CJson *credJson = GetObjFromJson(jsonParams, FIELD_CREDENTIAL);
    if (credJson == NULL) {
        LOGE("Failed to get credential from json!");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(credJson, FIELD_USER_ID, userId) != HC_SUCCESS) {
        LOGE("Failed to add userId to json!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(credJson, FIELD_DEVICE_ID, deviceId) != HC_SUCCESS) {
        LOGE("Failed to add deviceId to json!");
        return HC_ERR_JSON_ADD;
    }
    return ProcessAccountCredentials(osAccountId, IMPORT_SELF_CREDENTIAL, credJson, NULL);
}

static int32_t DelSelfToken(int32_t osAccountId, CJson *jsonParams)
{
    CJson *credJson = GetObjFromJson(jsonParams, FIELD_CREDENTIAL);
    if (credJson == NULL) {
        LOGE("Failed to get credential from json!");
        return HC_ERR_JSON_GET;
    }
    return ProcessAccountCredentials(osAccountId, DELETE_SELF_CREDENTIAL, credJson, NULL);
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

static int32_t DelDeviceToken(int32_t osAccountId, const TrustedDeviceEntry *entry, bool isLocalDev)
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
    res = ProcessAccountCredentials(osAccountId, (isLocalDev ? DELETE_SELF_CREDENTIAL : DELETE_TRUSTED_CREDENTIALS),
        delParams, NULL);
    FreeJson(delParams);
    return res;
}

static void DelAllTokens(int32_t osAccountId, const DeviceEntryVec *vec)
{
    int32_t res;
    uint32_t index;
    TrustedDeviceEntry **entry = NULL;
    FOR_EACH_HC_VECTOR(*vec, index, entry) {
        if ((entry == NULL) || (*entry == NULL)) {
            continue;
        }
        if (IsLocalDevice(StringGet(&(*entry)->udid))) {
            res = DelDeviceToken(osAccountId, *entry, true);
        } else {
            res = DelDeviceToken(osAccountId, *entry, false);
        }
        if (res != HC_SUCCESS) {
            LOGE("Failed to delete token! res: %d", res);
        }
    }
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
        res = DelDeviceToken(osAccountId, *entry, false);
        if (res != HC_SUCCESS) {
            LOGE("Failed to delete peer device token! res: %d", res);
        }
    }
}

static int32_t DelAcrossAccountGroupAndTokens(int32_t osAccountId, const char *groupId)
{
    DeviceEntryVec deviceList = CreateDeviceEntryVec();
    (void)GetTrustedDevices(osAccountId, groupId, &deviceList);
    int32_t res = DelGroupFromDb(osAccountId, groupId);
    DelAllPeerTokens(osAccountId, &deviceList);
    ClearDeviceEntryVec(&deviceList);
    return res;
}

static int32_t GetRelatedAcrossAccountGroups(int32_t osAccountId, const char *groupId, GroupEntryVec *vec)
{
    TrustedGroupEntry *groupEntry = GetGroupEntryById(osAccountId, groupId);
    if (groupEntry == NULL) {
        LOGE("Failed to get groupEntry from db!");
        return HC_ERR_DB;
    }
    QueryGroupParams groupParams = InitQueryGroupParams();
    groupParams.userId = StringGet(&groupEntry->userId);
    groupParams.groupType = ACROSS_ACCOUNT_AUTHORIZE_GROUP;
    int32_t res = QueryGroups(osAccountId, &groupParams, vec);
    DestroyGroupEntry(groupEntry);
    return res;
}

static int32_t DelRelatedAcrossAccountGroups(int32_t osAccountId, const char *groupId)
{
    GroupEntryVec groupEntryVec = CreateGroupEntryVec();
    (void)GetRelatedAcrossAccountGroups(osAccountId, groupId, &groupEntryVec);
    int32_t res = HC_SUCCESS;
    uint32_t index;
    TrustedGroupEntry **entry = NULL;
    FOR_EACH_HC_VECTOR(groupEntryVec, index, entry) {
        if ((entry != NULL) && (*entry != NULL)) {
            if (DelAcrossAccountGroupAndTokens(osAccountId, StringGet(&(*entry)->id)) != HC_SUCCESS) {
                res = HC_ERR_DEL_GROUP;
            }
        }
    }
    ClearGroupEntryVec(&groupEntryVec);
    return res;
}

static int32_t DelGroupAndTokens(int32_t osAccountId, const char *groupId)
{
    int32_t res = HC_SUCCESS;
    if (DelRelatedAcrossAccountGroups(osAccountId, groupId) != HC_SUCCESS) {
        res = HC_ERR_DEL_GROUP;
    }
    DeviceEntryVec deviceList = CreateDeviceEntryVec();
    (void)GetTrustedDevices(osAccountId, groupId, &deviceList);
    if (DelGroupFromDb(osAccountId, groupId) != HC_SUCCESS) {
        res = HC_ERR_DEL_GROUP;
    }
    DelAllTokens(osAccountId, &deviceList);
    ClearDeviceEntryVec(&deviceList);
    return res;
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
    res = DelDeviceToken(osAccountId, entry, false);
    DestroyDeviceEntry(entry);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete token! res: %d", res);
    }
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
        ((result = AssertGroupTypeMatch(groupType, IDENTICAL_ACCOUNT_GROUP)) != HC_SUCCESS) ||
        ((result = CheckGroupEditAllowed(osAccountId, groupId, appId)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupAndToken(int32_t osAccountId, CJson *jsonParams, const char *groupId)
{
    int32_t res = AddGroupToDatabaseByJson(osAccountId, GenerateGroupParams, jsonParams, groupId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add group to database!");
        return res;
    }
    res = ImportSelfToken(osAccountId, jsonParams);
    if (res != HC_SUCCESS) {
        LOGE("Failed to import self token!");
        (void)DelGroupFromDb(osAccountId, groupId);
        return res;
    }
    res = AddDeviceToDatabaseByJson(osAccountId, GenerateDevParams, jsonParams, groupId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add device to database!");
        (void)DelGroupFromDb(osAccountId, groupId);
        (void)DelSelfToken(osAccountId, jsonParams);
        return res;
    }
    res = SaveOsAccountDb(osAccountId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to save database!");
        (void)DelGroupFromDb(osAccountId, groupId);
        (void)DelSelfToken(osAccountId, jsonParams);
    }
    return res;
}

static int32_t CreateGroup(int32_t osAccountId, CJson *jsonParams, char **returnJsonStr)
{
    LOGI("[Start]: Start to create a identical account group!");
    if ((jsonParams == NULL) || (returnJsonStr == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    char *groupId = NULL;
    int32_t result;
    if (((result = CheckCreateParams(osAccountId, jsonParams)) != HC_SUCCESS) ||
        ((result = GenerateIdenticalGroupId(jsonParams, &groupId)) != HC_SUCCESS) ||
        ((result = AssertSameGroupNotExist(osAccountId, groupId)) != HC_SUCCESS) ||
        ((result = AddGroupAndToken(osAccountId, jsonParams, groupId)) != HC_SUCCESS) ||
        ((result = ConvertGroupIdToJsonStr(groupId, returnJsonStr)) != HC_SUCCESS)) {
        HcFree(groupId);
        return result;
    }
    HcFree(groupId);
    LOGI("[End]: Create a identical account group successfully!");
    return HC_SUCCESS;
}

static int32_t DeleteGroup(int32_t osAccountId, CJson *jsonParams, char **returnJsonStr)
{
    LOGI("[Start]: Start to delete a identical account group!");
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
    LOGI("[End]: Delete a identical account group successfully!");
    return HC_SUCCESS;
}

static int32_t AddMultiMembersToGroup(int32_t osAccountId, const char *appId, CJson *jsonParams)
{
    LOGI("[Start]: Start to add multiple members to a identical account group!");
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
    LOGI("[End]: Add multiple members to a identical account group successfully! [ListNum]: %d, [AddedNum]: %d",
        deviceNum, addedCount);
    return HC_SUCCESS;
}

static int32_t DelMultiMembersFromGroup(int32_t osAccountId, const char *appId, CJson *jsonParams)
{
    LOGI("[Start]: Start to delete multiple members from a identical account group!");
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
    LOGI("[End]: Delete multiple members from a identical account group successfully! [ListNum]: %d, [DeletedNum]: %d",
        deviceNum, deletedCount);
    return HC_SUCCESS;
}

static IdenticalAccountGroup g_identicalAccountGroup = {
    .base.type = IDENTICAL_ACCOUNT_GROUP,
    .base.createGroup = CreateGroup,
    .base.deleteGroup = DeleteGroup,
    .addMultiMembersToGroup = AddMultiMembersToGroup,
    .delMultiMembersFromGroup = DelMultiMembersFromGroup,
};

BaseGroup *GetIdenticalAccountGroupInstance(void)
{
    return (BaseGroup *)&g_identicalAccountGroup;
}

bool IsIdenticalAccountGroupSupported(void)
{
    return true;
}