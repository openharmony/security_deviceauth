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

#include "alg_defs.h"
#include "callback_manager.h"
#include "common_defs.h"
#include "data_manager.h"
#include "device_auth_defines.h"
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
    if (((result = AddUdidToParams(devParams)) != HC_SUCCESS) ||
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

static int32_t CreateGroupInner(int32_t osAccountId, const CJson *jsonParams, char **returnGroupId)
{
    char *groupId = NULL;
    int32_t result;
    if (((result = CheckCreateParams(osAccountId, jsonParams)) != HC_SUCCESS) ||
        ((result = GenerateAcrossAccountGroupId(jsonParams, &groupId)) != HC_SUCCESS) ||
        ((result = AddGroupToDatabaseByJson(osAccountId, GenerateGroupParams, jsonParams, groupId)) != HC_SUCCESS) ||
        ((result = AddDeviceToDatabaseByJson(osAccountId, GenerateDevParams, jsonParams, groupId)) != HC_SUCCESS) ||
        ((result = SaveOsAccountDb(osAccountId)) != HC_SUCCESS)) {
        HcFree(groupId);
        return result;
    }
    *returnGroupId = groupId;
    return HC_SUCCESS;
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
    if (((result = CreateGroupInner(osAccountId, jsonParams, &groupId)) != HC_SUCCESS) ||
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
        ((result = DelGroupFromDb(osAccountId, groupId)) != HC_SUCCESS) ||
        ((result = ConvertGroupIdToJsonStr(groupId, returnJsonStr)) != HC_SUCCESS)) {
        return result;
    }
    LOGI("[End]: Delete a across account group successfully!");
    return HC_SUCCESS;
}

static AcrossAccountGroup g_acrossAccountGroup = {
    .base.type = ACROSS_ACCOUNT_AUTHORIZE_GROUP,
    .base.createGroup = CreateGroup,
    .base.deleteGroup = DeleteGroup,
};

BaseGroup *GetAcrossAccountGroupInstance(void)
{
    return (BaseGroup *)&g_acrossAccountGroup;
}

bool IsAcrossAccountGroupSupported(void)
{
    return true;
}
