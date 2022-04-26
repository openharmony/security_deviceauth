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
#include "hc_log.h"
#include "string_util.h"
#include "account_module.h"

static int32_t GenerateDevParams(const CJson *jsonParams, const char *groupId, TrustedDeviceEntry *devParams)
{
    int32_t result;
    if (((result = AddUdidToParams(devParams)) != HC_SUCCESS) ||
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
        LOGE("Failed to get credJson!");
        return HC_ERR_JSON_GET;
    }
    int32_t credType;
    int32_t ret = GetIntFromJson(credJson, FIELD_CREDENTIAL_TYPE, &credType);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get credential type");
        return ret;
    }
    const char *serverPk = GetStringFromJson(credJson, FIELD_SERVER_PK);
    if (serverPk == NULL) {
        LOGE("Failed to get serverPk");
        return HC_ERR_JSON_GET;
    }
    const char *pkInfoSignature = GetStringFromJson(credJson, FIELD_PK_INFO_SIGNATURE);
    if (pkInfoSignature == NULL) {
        LOGE("Failed to get pkInfoSignature");
        return HC_ERR_JSON_GET;
    }
    CJson *pkInfoJson = GetObjFromJson(credJson, FIELD_PK_INFO);
    if (pkInfoJson == NULL) {
        LOGE("Failed to get pkInfoJson");
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

static int32_t DeleteGroupById(int32_t osAccountId, const char *groupId)
{
    QueryGroupParams queryGroupParams = InitQueryGroupParams();
    queryGroupParams.groupId = groupId;
    return DelGroup(osAccountId, &queryGroupParams);
}

static int32_t DeleteDeviceById(int32_t osAccountId, const char *groupId)
{
    QueryDeviceParams queryDeviceParams = InitQueryDeviceParams();
    queryDeviceParams.groupId = groupId;
    return DelTrustedDevice(osAccountId, &queryDeviceParams);
}

static int32_t CreateIdenticalGroup(int32_t osAccountId, const CJson *jsonParams, char *groupId)
{
    int32_t result = AddGroupToDatabaseByJson(osAccountId, GenerateGroupParams, jsonParams, groupId);
    if (result != HC_SUCCESS) {
        LOGE("Add group to database failed");
        return result;
    }
    result = ProcessAccountCredentials(osAccountId, IMPORT_SELF_CREDENTIAL, jsonParams, NULL);
    if (result != HC_SUCCESS) {
        LOGE("Import credential failed");
        DeleteGroupById(osAccountId, groupId);
        return result;
    }
    result = AddDeviceToDatabaseByJson(osAccountId, GenerateDevParams, jsonParams, groupId);
    if (result != HC_SUCCESS) {
        LOGE("Add device to database failed");
        DeleteGroupById(osAccountId, groupId);
        ProcessAccountCredentials(osAccountId, DELETE_SELF_CREDENTIAL, jsonParams, NULL);
        return result;
    }
    result = SaveOsAccountDb(osAccountId);
    if (result != HC_SUCCESS) {
        LOGE("Save data to db file failed");
        DeleteGroupById(osAccountId, groupId);
        ProcessAccountCredentials(osAccountId, DELETE_SELF_CREDENTIAL, jsonParams, NULL);
        DeleteDeviceById(osAccountId, groupId);
    }
    return result;
}

static int32_t CreateGroupInner(int32_t osAccountId, const CJson *jsonParams, char **returnGroupId)
{
    char *groupId = NULL;
    int32_t result;
    if (((result = CheckCreateParams(osAccountId, jsonParams)) != HC_SUCCESS) ||
        ((result = GenerateIdenticalGroupId(jsonParams, &groupId)) != HC_SUCCESS)) {
        LOGE("Check create params or generate groupId failed");
        return result;
    }
    if (IsGroupExistByGroupId(osAccountId, groupId)) {
        LOGE("Group already exists, do not create it again");
        HcFree(groupId);
        return HC_ERR_GROUP_DUPLICATE;
    }
    result = CreateIdenticalGroup(osAccountId, jsonParams, groupId);
    if (result != HC_SUCCESS) {
        HcFree(groupId);
        return result;
    }
    *returnGroupId = groupId;
    return HC_SUCCESS;
}

static int32_t CreateGroup(int32_t osAccountId, CJson *jsonParams, char **returnJsonStr)
{
    LOGI("[Start]: Start to create a identical account group!");
    if ((jsonParams == NULL) || (returnJsonStr == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t result;
    char *groupId = NULL;
    if (((result = CreateGroupInner(osAccountId, jsonParams, &groupId)) != HC_SUCCESS) ||
        ((result = ConvertGroupIdToJsonStr(groupId, returnJsonStr)) != HC_SUCCESS)) {
        HcFree(groupId);
        LOGE("Create identical group failed, result:%d", result);
        return result;
    }
    HcFree(groupId);
    LOGI("[End]: Create a identical account group successfully!");
    return HC_SUCCESS;
}

static int32_t DeleteAcrossAccountGroup(int32_t osAccountId, const char *identicalGroupId)
{
    TrustedGroupEntry *groupInfo = CreateGroupEntry();
    if (groupInfo == NULL) {
        LOGE("Failed to allocate groupInfo memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t ret = GetGroupInfoById(osAccountId, identicalGroupId, groupInfo);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to obtain the group information from the database!");
        DestroyGroupEntry(groupInfo);
        return ret;
    }
    const char *userId = StringGet(&groupInfo->userId);
    DestroyGroupEntry(groupInfo);
    GroupEntryVec groupEntryVec = CreateGroupEntryVec();
    QueryGroupParams groupParams = InitQueryGroupParams();
    groupParams.userId = userId;
    groupParams.groupType = ACROSS_ACCOUNT_AUTHORIZE_GROUP;
    ret = QueryGroups(osAccountId, &groupParams, &groupEntryVec);
    if (ret != HC_SUCCESS) {
        LOGE("query across account groups failed!");
        ClearGroupEntryVec(&groupEntryVec);
        return ret;
    }
    uint32_t groupIndex;
    TrustedGroupEntry **entry = NULL;
    FOR_EACH_HC_VECTOR(groupEntryVec, groupIndex, entry) {
        if ((entry != NULL) && (*entry != NULL)) {
            if (DeleteDeviceById(osAccountId, StringGet(&(*entry)->id)) != HC_SUCCESS) {
                LOGE("Delete across account device failed");
                ret = HC_ERR_DEL_GROUP;
            }
            if (DeleteGroupById(osAccountId, StringGet(&(*entry)->id)) != HC_SUCCESS) {
                LOGE("Delete across account group failed");
                ret = HC_ERR_DEL_GROUP;
            }
        }
    }
    ClearGroupEntryVec(&groupEntryVec);
    return ret;
}

static int32_t DeleteGroupInner(int32_t osAccountId, const char *groupId, CJson *jsonParams)
{
    int32_t ret = DeleteAcrossAccountGroup(osAccountId, groupId);
    if ((ret != HC_SUCCESS) && (ret != HC_ERR_DEL_GROUP)) {
        return ret;
    }
    if (DeleteDeviceById(osAccountId, groupId) != HC_SUCCESS) {
        LOGE("Delete identical account device failed");
        ret = HC_ERR_DEL_GROUP;
    }
    if (DeleteGroupById(osAccountId, groupId) != HC_SUCCESS) {
        LOGE("Delete identical account group failed");
        ret = HC_ERR_DEL_GROUP;
    }
    if (SaveOsAccountDb(osAccountId) != HC_SUCCESS) {
        LOGE("Save data to db file failed");
        ret = HC_ERR_DEL_GROUP;
    }
    if ((AddStringToJson(jsonParams, FIELD_USER_ID, groupId) != HC_SUCCESS) ||
        (ProcessAccountCredentials(osAccountId, DELETE_SELF_CREDENTIAL, jsonParams, NULL) != HC_SUCCESS)) {
        LOGE("Delete credential failed");
        ret = HC_ERR_DEL_GROUP;
    }
    return ret;
}

static int32_t DeleteGroup(int32_t osAccountId, CJson *jsonParams, char **returnJsonStr)
{
    LOGI("[Start]: Start to delete the identical account group!");
    if ((jsonParams == NULL) || (returnJsonStr == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    const char *groupId = NULL;
    int32_t ret = GetGroupIdFromJson(jsonParams, &groupId);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get groupId");
        return ret;
    }
    ret = DeleteGroupInner(osAccountId, groupId, jsonParams);
    if (ret != HC_SUCCESS) {
        LOGE("Delete group inner failed");
        return ret;
    }
    ret = ConvertGroupIdToJsonStr(groupId, returnJsonStr);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to convert groupId to json");
        return ret;
    }
    LOGI("[End]: Delete the identical account group successfully!");
    return HC_SUCCESS;
}

static IdenticalAccountGroup g_identicalAccountGroup = {
    .base.type = IDENTICAL_ACCOUNT_GROUP,
    .base.createGroup = CreateGroup,
    .base.deleteGroup = DeleteGroup,
    .generateGroupId = GenerateGroupId
};

BaseGroup *GetIdenticalAccountGroupInstance(void)
{
    return (BaseGroup *)&g_identicalAccountGroup;
}

bool IsIdenticalAccountGroupSupported(void)
{
    return true;
}