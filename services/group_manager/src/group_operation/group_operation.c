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

#include "group_operation.h"

#include "alg_defs.h"
#include "broadcast_manager.h"
#include "callback_manager.h"
#include "database_manager.h"
#include "dev_auth_module_manager.h"
#include "group_manager_common.h"
#include "group_operation_common.h"
#include "hc_log.h"
#include "session_manager.h"
#include "task_manager.h"

#include "across_account_group.h"
#include "identical_account_group.h"
#include "peer_to_peer_group.h"

static bool IsGroupTypeSupported(int groupType)
{
    if (((groupType == PEER_TO_PEER_GROUP) && (IsPeerToPeerGroupSupported())) ||
        ((groupType == IDENTICAL_ACCOUNT_GROUP) && (IsIdenticalAccountGroupSupported())) ||
        ((groupType == ACROSS_ACCOUNT_AUTHORIZE_GROUP) && (IsAcrossAccountGroupSupported()))) {
        return true;
    }
    LOGE("Invalid group type! [GroupType]: %d", groupType);
    return false;
}

static void RemoveNoPermissionGroup(GroupInfoVec *groupInfoVec, const char *appId)
{
    uint32_t index = 0;
    void **groupInfoPtr = NULL;
    while (index < groupInfoVec->size(groupInfoVec)) {
        groupInfoPtr = groupInfoVec->getp(groupInfoVec, index);
        if ((groupInfoPtr == NULL) || (*groupInfoPtr == NULL)) {
            index++;
            continue;
        }
        GroupInfo *groupInfo = (GroupInfo *)(*groupInfoPtr);
        if (IsGroupAccessible(StringGet(&groupInfo->id), appId)) {
            index++;
            continue;
        }
        void *tempEntry = NULL;
        HC_VECTOR_POPELEMENT(groupInfoVec, &tempEntry, index);
    }
}

static int32_t GenerateReturnEmptyArrayStr(char **returnVec)
{
    CJson *json = CreateJsonArray();
    if (json == NULL) {
        LOGE("Failed to allocate json memory!");
        return HC_ERR_JSON_FAIL;
    }
    *returnVec = PackJsonToString(json);
    FreeJson(json);
    if (*returnVec == NULL) {
        LOGE("Failed to convert json to string!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t GenerateReturnGroupVec(GroupInfoVec *groupInfoVec, char **returnGroupVec, uint32_t *groupNum)
{
    if (HC_VECTOR_SIZE(groupInfoVec) == 0) {
        LOGI("No group is found based on the query parameters!");
        *groupNum = 0;
        return GenerateReturnEmptyArrayStr(returnGroupVec);
    }

    CJson *json = CreateJsonArray();
    if (json == NULL) {
        LOGE("Failed to allocate json memory!");
        return HC_ERR_JSON_FAIL;
    }
    uint32_t groupCount = 0;
    uint32_t index;
    void **groupInfoPtr = NULL;
    FOR_EACH_HC_VECTOR(*groupInfoVec, index, groupInfoPtr) {
        if ((groupInfoPtr != NULL) && ((*groupInfoPtr) != NULL)) {
            GroupInfo *groupInfo = (GroupInfo*)(*groupInfoPtr);
            CJson *groupInfoJson = CreateJson();
            if (groupInfoJson == NULL) {
                LOGE("Failed to allocate groupInfoJson memory!");
                FreeJson(json);
                return HC_ERR_ALLOC_MEMORY;
            }
            int32_t result = GenerateReturnGroupInfo(groupInfo, groupInfoJson);
            if (result != HC_SUCCESS) {
                FreeJson(groupInfoJson);
                FreeJson(json);
                return result;
            }
            if (AddObjToArray(json, groupInfoJson) != HC_SUCCESS) {
                LOGE("Failed to add groupInfoStr to returnGroupVec!");
                FreeJson(groupInfoJson);
                FreeJson(json);
                return HC_ERR_JSON_FAIL;
            }
            ++groupCount;
        }
    }
    *returnGroupVec = PackJsonToString(json);
    FreeJson(json);
    if ((*returnGroupVec) == NULL) {
        LOGE("Failed to convert json to string!");
        return HC_ERR_JSON_FAIL;
    }
    *groupNum = groupCount;
    return HC_SUCCESS;
}

static int32_t GenerateReturnDeviceVec(DeviceInfoVec *devInfoVec, char **returnDevInfoVec, uint32_t *deviceNum)
{
    if (HC_VECTOR_SIZE(devInfoVec) == 0) {
        LOGI("No device is found based on the query parameters!");
        *deviceNum = 0;
        return GenerateReturnEmptyArrayStr(returnDevInfoVec);
    }

    CJson *json = CreateJsonArray();
    if (json == NULL) {
        LOGE("Failed to allocate json memory!");
        return HC_ERR_JSON_FAIL;
    }
    uint32_t devCount = 0;
    uint32_t index;
    void **devInfoPtr = NULL;
    FOR_EACH_HC_VECTOR(*devInfoVec, index, devInfoPtr) {
        if ((devInfoPtr != NULL) && ((*devInfoPtr) != NULL)) {
            DeviceInfo *devInfo = (DeviceInfo*)(*devInfoPtr);
            CJson *devInfoJson = CreateJson();
            if (devInfoJson == NULL) {
                LOGE("Failed to allocate devInfoJson memory!");
                FreeJson(json);
                return HC_ERR_ALLOC_MEMORY;
            }
            int32_t result = GenerateReturnDevInfo(devInfo, devInfoJson);
            if (result != HC_SUCCESS) {
                FreeJson(devInfoJson);
                FreeJson(json);
                return result;
            }
            if (AddObjToArray(json, devInfoJson) != HC_SUCCESS) {
                LOGE("Failed to add devInfoStr to returnGroupVec!");
                FreeJson(devInfoJson);
                FreeJson(json);
                return HC_ERR_JSON_FAIL;
            }
            ++devCount;
        }
    }
    *returnDevInfoVec = PackJsonToString(json);
    FreeJson(json);
    if ((*returnDevInfoVec) == NULL) {
        LOGE("Failed to convert json to string!");
        return HC_ERR_JSON_FAIL;
    }
    *deviceNum = devCount;
    return HC_SUCCESS;
}

static bool IsQueryParamsValid(int groupType, const char *groupId, const char *groupName, const char *groupOwner)
{
    if ((groupType == ALL_GROUP) && (groupId == NULL) && (groupName == NULL) && (groupOwner == NULL)) {
        return false;
    } else {
        return true;
    }
}

static int32_t QueryRelatedGroupsForGetPk(const char *udid, GroupInfoVec *groupInfoVec)
{
    GroupQueryParams dbQueryParams = { 0 };
    dbQueryParams.visibility = GROUP_VISIBILITY_PUBLIC;
    dbQueryParams.type = PEER_TO_PEER_GROUP;
    dbQueryParams.udid = NULL;
    dbQueryParams.authId = NULL;
    if (udid != NULL) {
        uint32_t peerUdidLen = HcStrlen(udid) + 1;
        dbQueryParams.udid = (char *)HcMalloc(peerUdidLen, 0);
        if (dbQueryParams.udid == NULL) {
            LOGE("Failed to allocate memory for queryParams of udid!");
            return HC_ERR_ALLOC_MEMORY;
        }
        if (strcpy_s(dbQueryParams.udid, peerUdidLen, udid) != EOK) {
            LOGE("Failed to copy udid for queryParams!");
            HcFree(dbQueryParams.udid);
            dbQueryParams.udid = NULL;
            return HC_ERR_MEMORY_COPY;
        }
    }
    int32_t result = GetJoinedGroupInfoVecByDevId(&dbQueryParams, groupInfoVec);
    HcFree(dbQueryParams.udid);
    return result;
}

static int32_t GetPkByParams(const char *groupId, const DeviceInfo *deviceInfo, char *returnPkHexStr,
    int32_t returnPkHexStrLen)
{
    /* Use the DeviceGroupManager package name. */
    const char *appId = GROUP_MANAGER_PACKAGE_NAME;
    int userType = deviceInfo->devType;
    const char *authId = StringGet(&deviceInfo->authId);
    if (authId == NULL) {
        LOGE("Failed to get authId from deviceInfo!");
        return HC_ERR_DB;
    }
    Uint8Buff authIdBuff = { 0, 0 };
    authIdBuff.length = HcStrlen(authId);
    authIdBuff.val = (uint8_t *)HcMalloc(authIdBuff.length, 0);
    if (authIdBuff.val == NULL) {
        LOGE("Failed to allocate authIdBuff memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(authIdBuff.val, authIdBuff.length, authId, authIdBuff.length) != HC_SUCCESS) {
        LOGE("Failed to copy authId!");
        HcFree(authIdBuff.val);
        return HC_ERR_MEMORY_COPY;
    }
    uint8_t returnPkBytes[PUBLIC_KEY_MAX_LENGTH] = { 0 };
    Uint8Buff returnPkBuff = { 0, 0 };
    returnPkBuff.length = PUBLIC_KEY_MAX_LENGTH;
    returnPkBuff.val = returnPkBytes;
    int32_t res = GetPublicKey(appId, groupId, &authIdBuff, userType, DAS_MODULE, &returnPkBuff);
    HcFree(authIdBuff.val);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = GetHashResult(returnPkBuff.val, returnPkBuff.length, returnPkHexStr, returnPkHexStrLen);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get hash for pk!");
        return HC_ERR_HASH_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t GeneratePkInfo(const char *queryUdid, const char *groupId, CJson *pkInfo)
{
    DeviceInfo *deviceInfo = CreateDeviceInfoStruct();
    if (deviceInfo == NULL) {
        LOGE("Failed to allocate deviceInfo memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = GetTrustedDevInfoById(queryUdid, true, groupId, deviceInfo);
    if (res != HC_SUCCESS) {
        DestroyDeviceInfoStruct(deviceInfo);
        return res;
    }
    char returnPkHexStr[SHA256_LEN * BYTE_TO_HEX_OPER_LENGTH + 1] = { 0 };
    res = GetPkByParams(groupId, deviceInfo, returnPkHexStr, sizeof(returnPkHexStr));
    DestroyDeviceInfoStruct(deviceInfo);
    if (res != HC_SUCCESS) {
        return res;
    }
    if (AddStringToJson(pkInfo, FIELD_GROUP_ID, groupId) != HC_SUCCESS) {
        LOGE("Failed to add groupId to pkInfo!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(pkInfo, FIELD_PUBLIC_KEY, returnPkHexStr) != HC_SUCCESS) {
        LOGE("Failed to add publicKey to pkInfo!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static void AddAllPkInfoToList(const char *queryUdid, const GroupInfoVec *groupInfoVec, CJson *pkInfoList)
{
    uint32_t index;
    void **groupInfoPtr;
    FOR_EACH_HC_VECTOR(*groupInfoVec, index, groupInfoPtr) {
        if ((groupInfoPtr == NULL) || (*groupInfoPtr == NULL)) {
            continue;
        }
        GroupInfo *groupInfo = (GroupInfo *)*groupInfoPtr;
        const char *groupId = StringGet(&groupInfo->id);
        if (groupId == NULL) {
            LOGE("Failed to get groupId from groupInfo!");
            continue;
        }
        CJson *pkInfo = CreateJson();
        if (pkInfo == NULL) {
            LOGE("Failed to create json!");
            continue;
        }
        int32_t res = GeneratePkInfo(queryUdid, groupId, pkInfo);
        if (res != HC_SUCCESS) {
            FreeJson(pkInfo);
            continue;
        }
        if (AddObjToArray(pkInfoList, pkInfo) != HC_SUCCESS) {
            LOGE("Failed to add pkInfo to pkInfoList!");
            FreeJson(pkInfo);
        }
    }
}

static int32_t GeneratePkInfoList(const char *appId, const CJson *params, CJson *pkInfoList)
{
    const char *udid = GetStringFromJson(params, FIELD_UDID);
    if (udid == NULL) {
        LOGE("Failed to get udid from params!");
        return HC_ERR_JSON_GET;
    }
    bool isSelfPk = false;
    if (GetBoolFromJson(params, FIELD_IS_SELF_PK, &isSelfPk) != HC_SUCCESS) {
        LOGE("Failed to get isSelfPk from json!");
        return HC_ERR_JSON_GET;
    }
    GroupInfoVec groupInfoVec;
    CreateGroupInfoVecStruct(&groupInfoVec);
    int32_t res = QueryRelatedGroupsForGetPk(udid, &groupInfoVec);
    if (res != HC_SUCCESS) {
        DestroyGroupInfoVecStruct(&groupInfoVec);
        return res;
    }
    RemoveNoPermissionGroup(&groupInfoVec, appId);
    const char *queryUdid = isSelfPk ? GetLocalDevUdid() : udid;
    if (queryUdid == NULL) {
        LOGE("Failed to get local udid!");
        DestroyGroupInfoVecStruct(&groupInfoVec);
        return HC_ERR_DB;
    }
    AddAllPkInfoToList(queryUdid, &groupInfoVec, pkInfoList);
    DestroyGroupInfoVecStruct(&groupInfoVec);
    return HC_SUCCESS;
}

static BaseGroup *GetGroupInstance(int32_t groupType)
{
    if (!IsGroupTypeSupported(groupType)) {
        return NULL;
    }
    BaseGroup *instance = NULL;
    if (groupType == PEER_TO_PEER_GROUP) {
        instance = GetPeerToPeerGroupInstance();
    } else if (groupType == IDENTICAL_ACCOUNT_GROUP) {
        instance = GetIdenticalAccountGroupInstance();
    } else if (groupType == ACROSS_ACCOUNT_AUTHORIZE_GROUP) {
        instance = GetAcrossAccountGroupInstance();
    }
    return instance;
}

static int32_t CreateGroup(CJson *jsonParams, char **returnJsonStr)
{
    if ((jsonParams == NULL) || (returnJsonStr == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t groupType = PEER_TO_PEER_GROUP;
    if (GetIntFromJson(jsonParams, FIELD_GROUP_TYPE, &groupType) != HC_SUCCESS) {
        LOGE("Failed to get groupType from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    BaseGroup *instance = GetGroupInstance(groupType);
    if ((instance == NULL) || (instance->createGroup == NULL)) {
        LOGE("The group instance is NULL or its function ptr is NULL!");
        return HC_ERR_NULL_PTR;
    }
    return instance->createGroup(jsonParams, returnJsonStr);
}

static int32_t DeleteGroup(CJson *jsonParams, char **returnJsonStr)
{
    if ((jsonParams == NULL) || (returnJsonStr == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t result;
    const char *groupId = NULL;
    const char *appId = NULL;
    int32_t groupType = PEER_TO_PEER_GROUP;
    if (((result = GetGroupIdFromJson(jsonParams, &groupId)) != HC_SUCCESS) ||
        ((result = GetAppIdFromJson(jsonParams, &appId)) != HC_SUCCESS) ||
        ((result = CheckGroupExist(groupId)) != HC_SUCCESS) ||
        ((result = GetGroupTypeFromDb(groupId, &groupType)) != HC_SUCCESS) ||
        ((result = CheckPermForGroup(GROUP_DISBAND, appId, groupId)) != HC_SUCCESS)) {
        return result;
    }
    BaseGroup *instance = GetGroupInstance(groupType);
    if ((instance == NULL) || (instance->deleteGroup == NULL)) {
        LOGE("The group instance is NULL or its function ptr is NULL!");
        return HC_ERR_NULL_PTR;
    }
    return instance->deleteGroup(jsonParams, returnJsonStr);
}

static int32_t AddMemberToPeerToPeerGroup(int64_t requestId, CJson *jsonParams, const DeviceAuthCallback *callback)
{
    if ((jsonParams == NULL) || (callback == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsPeerToPeerGroupSupported()) {
        LOGE("Peer to peer group is not supported!");
        return HC_ERR_NOT_SUPPORT;
    }
    PeerToPeerGroup *instance = (PeerToPeerGroup *)GetPeerToPeerGroupInstance();
    if ((instance == NULL) || (instance->addMember == NULL)) {
        LOGE("The group instance is NULL or its function ptr is NULL!");
        return HC_ERR_NULL_PTR;
    }
    return instance->addMember(requestId, jsonParams, callback);
}

static int32_t DeleteMemberFromPeerToPeerGroup(int64_t requestId, CJson *jsonParams, const DeviceAuthCallback *callback)
{
    if ((jsonParams == NULL) || (callback == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsPeerToPeerGroupSupported()) {
        LOGE("Peer to peer group is not supported!");
        return HC_ERR_NOT_SUPPORT;
    }
    PeerToPeerGroup *instance = (PeerToPeerGroup *)GetPeerToPeerGroupInstance();
    if ((instance == NULL) || (instance->deleteMember == NULL)) {
        LOGE("The group instance is NULL or its function ptr is NULL!");
        return HC_ERR_NULL_PTR;
    }
    return instance->deleteMember(requestId, jsonParams, callback);
}

static int32_t ProcessBindData(int64_t requestId, CJson *jsonParams, const DeviceAuthCallback *callback)
{
    if ((jsonParams == NULL) || (callback == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsPeerToPeerGroupSupported()) {
        LOGE("Peer to peer group is not supported!");
        return HC_ERR_NOT_SUPPORT;
    }
    PeerToPeerGroup *instance = (PeerToPeerGroup *)GetPeerToPeerGroupInstance();
    if ((instance == NULL) || (instance->processData == NULL)) {
        LOGE("The group instance is NULL or its function ptr is NULL!");
        return HC_ERR_NULL_PTR;
    }
    return instance->processData(requestId, jsonParams, callback);
}

static int32_t GenerateAccountGroupId(int32_t groupType, const char *userIdHash, const char *sharedUserIdHash,
    char **returnGroupId)
{
    if ((!IsAccountRelatedGroup(groupType)) || (!IsGroupTypeSupported(groupType))) {
        LOGE("This type of group is not supported!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (groupType == IDENTICAL_ACCOUNT_GROUP) {
        IdenticalAccountGroup *instance = (IdenticalAccountGroup *)GetIdenticalAccountGroupInstance();
        if ((instance == NULL) || (instance->generateGroupId == NULL)) {
            LOGE("The group instance is NULL or its function ptr is NULL!");
            return HC_ERR_NULL_PTR;
        }
        return instance->generateGroupId(userIdHash, returnGroupId);
    }
    AcrossAccountGroup *instance = (AcrossAccountGroup *)GetAcrossAccountGroupInstance();
    if ((instance == NULL) || (instance->generateGroupId == NULL)) {
        LOGE("The group instance is NULL or its function ptr is NULL!");
        return HC_ERR_NULL_PTR;
    }
    return instance->generateGroupId(userIdHash, sharedUserIdHash, returnGroupId);
}

static int32_t SyncAcrossAccountGroup(const char *appId, const char *userIdHash, const char *deviceId,
    const CJson *sharedUserIdHashList)
{
    if ((appId == NULL) || (deviceId == NULL) || (userIdHash == NULL) || (sharedUserIdHashList == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsAcrossAccountGroupSupported()) {
        LOGE("Across account group is not supported!");
        return HC_ERR_NOT_SUPPORT;
    }
    AcrossAccountGroup *instance = (AcrossAccountGroup *)GetAcrossAccountGroupInstance();
    if ((instance == NULL) || (instance->syncGroup == NULL)) {
        LOGE("The group instance is NULL or its function ptr is NULL!");
        return HC_ERR_NULL_PTR;
    }
    return instance->syncGroup(appId, userIdHash, deviceId, sharedUserIdHashList);
}

static int32_t AddGroupRoleWithCheck(bool isManager, const char *appId, const char *groupId, const char *roleAppId)
{
    if ((appId == NULL) || (groupId == NULL) || (roleAppId == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsPeerToPeerGroupSupported()) {
        LOGE("Peer to peer group is not supported!");
        return HC_ERR_NOT_SUPPORT;
    }
    PeerToPeerGroup *instance = (PeerToPeerGroup *)GetPeerToPeerGroupInstance();
    if ((instance == NULL) || (instance->addGroupRole == NULL)) {
        LOGE("The group instance is NULL or its function ptr is NULL!");
        return HC_ERR_NULL_PTR;
    }
    return instance->addGroupRole(isManager, appId, groupId, roleAppId);
}

static int32_t DeleteGroupRoleWithCheck(bool isManager, const char *appId, const char *groupId, const char *roleAppId)
{
    if ((appId == NULL) || (groupId == NULL) || (roleAppId == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsPeerToPeerGroupSupported()) {
        LOGE("Peer to peer group is not supported!");
        return HC_ERR_NOT_SUPPORT;
    }
    PeerToPeerGroup *instance = (PeerToPeerGroup *)GetPeerToPeerGroupInstance();
    if ((instance == NULL) || (instance->deleteGroupRole == NULL)) {
        LOGE("The group instance is NULL or its function ptr is NULL!");
        return HC_ERR_NULL_PTR;
    }
    return instance->deleteGroupRole(isManager, appId, groupId, roleAppId);
}

static int32_t GetGroupRolesWithCheck(bool isManager, const char *appId, const char *groupId, char **returnJsonStr,
    uint32_t *returnSize)
{
    if ((appId == NULL) || (groupId == NULL) || (returnJsonStr == NULL) || (returnSize == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsPeerToPeerGroupSupported()) {
        LOGE("Peer to peer group is not supported!");
        return HC_ERR_NOT_SUPPORT;
    }
    PeerToPeerGroup *instance = (PeerToPeerGroup *)GetPeerToPeerGroupInstance();
    if ((instance == NULL) || (instance->getGroupRoles == NULL)) {
        LOGE("The group instance is NULL or its function ptr is NULL!");
        return HC_ERR_NULL_PTR;
    }
    return instance->getGroupRoles(isManager, appId, groupId, returnJsonStr, returnSize);
}

static int32_t GetOpCodeWhenAdd(const CJson *jsonParams)
{
    bool isAdmin = true;
    /* The isAdmin parameter is optional. Default value is true. */
    (void)GetBoolFromJson(jsonParams, FIELD_IS_ADMIN, &isAdmin);
    return isAdmin ? MEMBER_INVITE : MEMBER_JOIN;
}

static void DoCreateGroup(HcTaskBase *baseTask)
{
    if (baseTask == NULL) {
        LOGE("The input task is NULL!");
        return;
    }
    GroupManagerTask *task = (GroupManagerTask *)baseTask;
    LOGI("[Start]: DoCreateGroup! [ReqId]: %" PRId64, task->reqId);
    char *returnJsonStr = NULL;
    int32_t result = CreateGroup(task->params, &returnJsonStr);
    if (result != HC_SUCCESS) {
        ProcessErrorCallback(task->reqId, GROUP_CREATE, result, NULL, task->cb);
    } else {
        ProcessFinishCallback(task->reqId, GROUP_CREATE, returnJsonStr, task->cb);
        FreeJsonString(returnJsonStr);
    }
}

static void DoDeleteGroup(HcTaskBase *baseTask)
{
    if (baseTask == NULL) {
        LOGE("The input task is NULL!");
        return;
    }
    GroupManagerTask *task = (GroupManagerTask *)baseTask;
    LOGI("[Start]: DoDeleteGroup! [ReqId]: %" PRId64, task->reqId);
    char *returnJsonStr = NULL;
    int32_t result = DeleteGroup(task->params, &returnJsonStr);
    if (result != HC_SUCCESS) {
        ProcessErrorCallback(task->reqId, GROUP_DISBAND, result, NULL, task->cb);
    } else {
        ProcessFinishCallback(task->reqId, GROUP_DISBAND, returnJsonStr, task->cb);
        FreeJsonString(returnJsonStr);
    }
}

static void DoAddMember(HcTaskBase *baseTask)
{
    if (baseTask == NULL) {
        LOGE("The input task is NULL!");
        return;
    }
    GroupManagerTask *task = (GroupManagerTask *)baseTask;
    LOGI("[Start]: DoAddMember! [ReqId]: %" PRId64, task->reqId);
    (void)AddMemberToPeerToPeerGroup(task->reqId, task->params, task->cb);
}

static void DoDeleteMember(HcTaskBase *baseTask)
{
    if (baseTask == NULL) {
        LOGE("The input task is NULL!");
        return;
    }
    GroupManagerTask *task = (GroupManagerTask *)baseTask;
    LOGI("[Start]: DoDeleteMember! [ReqId]: %" PRId64, task->reqId);
    (void)DeleteMemberFromPeerToPeerGroup(task->reqId, task->params, task->cb);
}

static void DoProcessBindData(HcTaskBase *baseTask)
{
    if (baseTask == NULL) {
        LOGE("The input task is NULL!");
        return;
    }
    GroupManagerTask *task = (GroupManagerTask *)baseTask;
    LOGI("[Start]: DoProcessBindData! [ReqId]: %" PRId64, task->reqId);
    if (IsRequestExist(task->reqId)) {
        int ret = ProcessSession(task->reqId, BIND_TYPE, task->params);
        if (ret != CONTINUE) {
            DestroySession(task->reqId);
        }
        return;
    }
    if ((BindCallbackToTask(task, task->params) != HC_SUCCESS) ||
        (CheckMsgRepeatability(task->params, DAS_MODULE) != HC_SUCCESS)) {
        return;
    }
    (void)ProcessBindData(task->reqId, task->params, task->cb);
}

static void DoConfirmRequest(HcTaskBase *baseTask)
{
    if (baseTask == NULL) {
        LOGE("The input task is NULL!");
        return;
    }
    GroupManagerTask *task = (GroupManagerTask *)baseTask;
    LOGI("[Start]: DoConfirmRequest! [ReqId]: %" PRId64, task->reqId);
    OnConfirmed(task->reqId, task->params);
}

static int32_t RequestCreateGroup(int64_t requestId, const char *appId, const char *createParams)
{
    if ((appId == NULL) || (createParams == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGI("[Start]: RequestCreateGroup! [AppId]: %s, [RequestId]: %" PRId64, appId, requestId);
    CJson *params = CreateJsonFromString(createParams);
    if (params == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t result = AddBindParamsToJson(GROUP_CREATE, requestId, appId, params);
    if (result != HC_SUCCESS) {
        FreeJson(params);
        return result;
    }
    if (InitAndPushGMTask(GROUP_CREATE, requestId, params, DoCreateGroup) != HC_SUCCESS) {
        FreeJson(params);
        return HC_ERR_INIT_TASK_FAIL;
    }
    LOGI("[End]: RequestCreateGroup!");
    return HC_SUCCESS;
}

static int32_t RequestDeleteGroup(int64_t requestId, const char *appId, const char *disbandParams)
{
    if ((appId == NULL) || (disbandParams == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGI("[Start]: RequestDeleteGroup! [AppId]: %s, [RequestId]: %" PRId64, appId, requestId);
    CJson *params = CreateJsonFromString(disbandParams);
    if (params == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t result = AddBindParamsToJson(GROUP_DISBAND, requestId, appId, params);
    if (result != HC_SUCCESS) {
        FreeJson(params);
        return result;
    }
    if (InitAndPushGMTask(GROUP_DISBAND, requestId, params, DoDeleteGroup) != HC_SUCCESS) {
        FreeJson(params);
        return HC_ERR_INIT_TASK_FAIL;
    }
    LOGI("[End]: RequestDeleteGroup!");
    return HC_SUCCESS;
}

static int32_t RequestAddMemberToGroup(int64_t requestId, const char *appId, const char *addParams)
{
    if ((appId == NULL) || (addParams == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGI("[Start]: RequestAddMemberToGroup! [AppId]: %s, [RequestId]: %" PRId64, appId, requestId);
    CJson *params = CreateJsonFromString(addParams);
    if (params == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t opCode = GetOpCodeWhenAdd(params);
    int32_t result = AddBindParamsToJson(opCode, requestId, appId, params);
    if (result != HC_SUCCESS) {
        FreeJson(params);
        return result;
    }
    if (InitAndPushGMTask(opCode, requestId, params, DoAddMember) != HC_SUCCESS) {
        FreeJson(params);
        return HC_ERR_INIT_TASK_FAIL;
    }
    LOGI("[End]: RequestAddMemberToGroup!");
    return HC_SUCCESS;
}

static int32_t RequestDeleteMemberFromGroup(int64_t requestId, const char *appId, const char *deleteParams)
{
    if ((appId == NULL) || (deleteParams == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGI("[Start]: RequestDeleteMemberFromGroup! [AppId]: %s, [RequestId]: %" PRId64, appId, requestId);
    CJson *params = CreateJsonFromString(deleteParams);
    if (params == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t result = AddBindParamsToJson(MEMBER_DELETE, requestId, appId, params);
    if (result != HC_SUCCESS) {
        FreeJson(params);
        return result;
    }
    if (InitAndPushGMTask(MEMBER_DELETE, requestId, params, DoDeleteMember) != HC_SUCCESS) {
        FreeJson(params);
        return HC_ERR_INIT_TASK_FAIL;
    }
    LOGI("[End]: RequestDeleteMemberFromGroup!");
    return HC_SUCCESS;
}

static int32_t RequestProcessBindData(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    if ((data == NULL) || (dataLen == 0) || (dataLen > MAX_DATA_BUFFER_SIZE)) {
        LOGE("The input data is invalid!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGI("[Start]: RequestProcessBindData! [RequestId]: %" PRId64, requestId);
    CJson *params = CreateJsonFromString((const char *)data);
    if (params == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    int64_t tempRequestId = DEFAULT_REQUEST_ID;
    if (GetInt64FromJson(params, FIELD_REQUEST_ID, &tempRequestId) != HC_SUCCESS) {
        LOGE("Failed to get requestId from json!");
        FreeJson(params);
        return HC_ERR_JSON_GET;
    }
    if (tempRequestId != requestId) {
        LOGE("The requestId is invalid! [ServiceReqId]: %" PRId64 ", [ReqId]: %" PRId64, requestId, tempRequestId);
        FreeJson(params);
        return HC_ERR_INVALID_PARAMS;
    }
    if (InitAndPushGMTask(CODE_NULL, requestId, params, DoProcessBindData) != HC_SUCCESS) {
        FreeJson(params);
        return HC_ERR_INIT_TASK_FAIL;
    }
    LOGI("[End]: RequestProcessBindData!");
    return HC_SUCCESS;
}

static int32_t RequestConfirmRequest(int64_t requestId, const char *appId, const char *confirmParams)
{
    if ((appId == NULL) || (confirmParams == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGI("[Start]: RequestConfirmRequest! [AppId]: %s, [RequestId]: %" PRId64, appId, requestId);
    CJson *params = CreateJsonFromString(confirmParams);
    if (params == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    if (AddStringToJson(params, FIELD_APP_ID, appId) != HC_SUCCESS) {
        LOGE("Failed to add appId to json!");
        FreeJson(params);
        return HC_ERR_JSON_FAIL;
    }
    if (InitAndPushGMTask(CODE_NULL, requestId, params, DoConfirmRequest) != HC_SUCCESS) {
        FreeJson(params);
        return HC_ERR_INIT_TASK_FAIL;
    }
    LOGI("[End]: RequestConfirmRequest!");
    return HC_SUCCESS;
}

static int32_t RegListener(const char *appId, const DataChangeListener *listener)
{
    if ((appId == NULL) || (listener == NULL)) {
        LOGE("The input parameter contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsBroadcastSupported()) {
        LOGE("Broadcast is not supported!");
        return HC_ERR_NOT_SUPPORT;
    }
    return AddListener(appId, listener);
}

static int32_t UnRegListener(const char *appId)
{
    if (appId == NULL) {
        LOGE("The input appId is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsBroadcastSupported()) {
        LOGE("Broadcast is not supported!");
        return HC_ERR_NOT_SUPPORT;
    }
    return RemoveListener(appId);
}

static int32_t CheckAccessToGroup(const char *appId, const char *groupId)
{
    if ((appId == NULL) || (groupId == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsGroupAccessible(groupId, appId)) {
        LOGE("You do not have the permission to query the group information!");
        return HC_ERR_ACCESS_DENIED;
    }
    return HC_SUCCESS;
}

static int32_t GetPkInfoList(const char *appId, const char *queryParams, char **returnInfoList, uint32_t *returnInfoNum)
{
    LOGI("[Start]: start to get pk list!");
    if ((appId == NULL) || (queryParams == NULL) || (returnInfoList == NULL) || (returnInfoNum == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    CJson *params = CreateJsonFromString(queryParams);
    if (params == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_CREATE;
    }
    CJson *pkInfoList = CreateJsonArray();
    if (pkInfoList == NULL) {
        LOGE("Failed to create json array!");
        FreeJson(params);
        return HC_ERR_JSON_CREATE;
    }
    int32_t res = GeneratePkInfoList(appId, params, pkInfoList);
    FreeJson(params);
    if (res != HC_SUCCESS) {
        FreeJson(pkInfoList);
        return res;
    }
    int32_t pkInfoNum = GetItemNum(pkInfoList);
    char *pkInfoListStr = PackJsonToString(pkInfoList);
    FreeJson(pkInfoList);
    if (pkInfoListStr == NULL) {
        LOGE("Failed to convert json to string!");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    *returnInfoList = pkInfoListStr;
    *returnInfoNum = pkInfoNum;
    LOGI("[End]: Get pk list successfully!");
    return HC_SUCCESS;
}

static int32_t GetAccessibleGroupInfoById(const char *appId, const char *groupId, char **returnGroupInfo)
{
    if ((appId == NULL) || (groupId == NULL) || (returnGroupInfo == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsGroupExistByGroupId(groupId)) {
        LOGE("No group is found based on the query parameters!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    if (!IsGroupAccessible(groupId, appId)) {
        LOGE("You do not have the permission to query the group information!");
        return HC_ERR_ACCESS_DENIED;
    }
    GroupInfo *groupInfo = CreateGroupInfoStruct();
    if (groupInfo == NULL) {
        LOGE("Failed to allocate groupInfo memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetGroupInfoById(groupId, groupInfo) != HC_SUCCESS) {
        LOGE("Failed to obtain the group information from the database!");
        DestroyGroupInfoStruct(groupInfo);
        return HC_ERR_DB;
    }
    CJson *groupInfoJson = CreateJson();
    if (groupInfoJson == NULL) {
        LOGE("Failed to allocate groupInfoJson memory!");
        DestroyGroupInfoStruct(groupInfo);
        return HC_ERR_JSON_FAIL;
    }
    int32_t result = GenerateReturnGroupInfo(groupInfo, groupInfoJson);
    DestroyGroupInfoStruct(groupInfo);
    if (result != HC_SUCCESS) {
        FreeJson(groupInfoJson);
        return result;
    }
    *returnGroupInfo = PackJsonToString(groupInfoJson);
    FreeJson(groupInfoJson);
    if (*returnGroupInfo == NULL) {
        LOGE("Failed to convert json to string!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t GetAccessibleGroupInfo(const char *appId, const char *queryParams, char **returnGroupVec,
    uint32_t *groupNum)
{
    if ((appId == NULL) || (queryParams == NULL) || (returnGroupVec == NULL) || (groupNum == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    CJson *queryParamsJson = CreateJsonFromString(queryParams);
    if (queryParamsJson == NULL) {
        LOGE("Failed to create queryParamsJson from string!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t groupType = ALL_GROUP;
    (void)GetIntFromJson(queryParamsJson, FIELD_GROUP_TYPE, &groupType);
    if ((groupType != ALL_GROUP) && (!IsGroupTypeSupported(groupType))) {
        LOGE("Invalid group type!");
        FreeJson(queryParamsJson);
        return HC_ERR_INVALID_PARAMS;
    }
    const char *groupId = GetStringFromJson(queryParamsJson, FIELD_GROUP_ID);
    const char *groupName = GetStringFromJson(queryParamsJson, FIELD_GROUP_NAME);
    const char *groupOwner = GetStringFromJson(queryParamsJson, FIELD_GROUP_OWNER);
    if (!IsQueryParamsValid(groupType, groupId, groupName, groupOwner)) {
        LOGE("The query parameters cannot be all null!");
        FreeJson(queryParamsJson);
        return HC_ERR_INVALID_PARAMS;
    }
    GroupInfoVec groupInfoVec;
    CreateGroupInfoVecStruct(&groupInfoVec);
    int32_t result = GetGroupInfo(groupType, groupId, groupName, groupOwner, &groupInfoVec);
    FreeJson(queryParamsJson);
    if (result != HC_SUCCESS) {
        DestroyGroupInfoVecStruct(&groupInfoVec);
        return result;
    }
    RemoveNoPermissionGroup(&groupInfoVec, appId);
    result = GenerateReturnGroupVec(&groupInfoVec, returnGroupVec, groupNum);
    DestroyGroupInfoVecStruct(&groupInfoVec);
    return result;
}

static int32_t GetAccessibleJoinedGroups(const char *appId, int groupType, char **returnGroupVec, uint32_t *groupNum)
{
    if ((appId == NULL) || (returnGroupVec == NULL) || (groupNum == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsGroupTypeSupported(groupType)) {
        LOGE("Invalid group type!");
        return HC_ERR_INVALID_PARAMS;
    }
    GroupInfoVec groupInfoVec;
    CreateGroupInfoVecStruct(&groupInfoVec);
    int32_t result = GetJoinedGroups(groupType, &groupInfoVec);
    if (result != HC_SUCCESS) {
        DestroyGroupInfoVecStruct(&groupInfoVec);
        return result;
    }
    RemoveNoPermissionGroup(&groupInfoVec, appId);
    result = GenerateReturnGroupVec(&groupInfoVec, returnGroupVec, groupNum);
    DestroyGroupInfoVecStruct(&groupInfoVec);
    return result;
}

static int32_t GetAccessibleRelatedGroups(const char *appId, const char *peerDeviceId, bool isUdid,
    char **returnGroupVec, uint32_t *groupNum)
{
    if ((appId == NULL) || (peerDeviceId == NULL) || (returnGroupVec == NULL) || (groupNum == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGI("Start to get related groups! [AppId]: %s", appId);
    GroupInfoVec groupInfoVec;
    CreateGroupInfoVecStruct(&groupInfoVec);
    int32_t result = GetRelatedGroups(peerDeviceId, isUdid, &groupInfoVec);
    if (result != HC_SUCCESS) {
        DestroyGroupInfoVecStruct(&groupInfoVec);
        return result;
    }
    RemoveNoPermissionGroup(&groupInfoVec, appId);
    result = GenerateReturnGroupVec(&groupInfoVec, returnGroupVec, groupNum);
    DestroyGroupInfoVecStruct(&groupInfoVec);
    return result;
}

static int32_t GetAccessibleDeviceInfoById(const char *appId, const char *deviceId, bool isUdid,
    const char *groupId, char **returnDeviceInfo)
{
    if ((appId == NULL) || (deviceId == NULL) || (groupId == NULL) || (returnDeviceInfo == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsGroupExistByGroupId(groupId)) {
        LOGE("No group is found based on the query parameters!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    if (!IsGroupAccessible(groupId, appId)) {
        LOGE("You do not have the permission to query the group information!");
        return HC_ERR_ACCESS_DENIED;
    }
    DeviceInfo *devInfo = CreateDeviceInfoStruct();
    if (devInfo == NULL) {
        LOGE("Failed to allocate devInfo memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetTrustedDevInfoById(deviceId, isUdid, groupId, devInfo) != HC_SUCCESS) {
        LOGE("No device is found based on the query parameters!");
        DestroyDeviceInfoStruct(devInfo);
        return HC_ERR_DEVICE_NOT_EXIST;
    }
    CJson *devInfoJson = CreateJson();
    if (devInfoJson == NULL) {
        LOGE("Failed to allocate devInfoJson memory!");
        DestroyDeviceInfoStruct(devInfo);
        return HC_ERR_JSON_FAIL;
    }
    int32_t result = GenerateReturnDevInfo(devInfo, devInfoJson);
    DestroyDeviceInfoStruct(devInfo);
    if (result != HC_SUCCESS) {
        FreeJson(devInfoJson);
        return result;
    }
    *returnDeviceInfo = PackJsonToString(devInfoJson);
    FreeJson(devInfoJson);
    if (*returnDeviceInfo == NULL) {
        LOGE("Failed to convert json to string!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t GetAccessibleTrustedDevices(const char *appId, const char *groupId,
    char **returnDevInfoVec, uint32_t *deviceNum)
{
    if ((appId == NULL) || (groupId == NULL) || (returnDevInfoVec == NULL) || (deviceNum == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsGroupExistByGroupId(groupId)) {
        LOGE("No group is found based on the query parameters!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    if (!IsGroupAccessible(groupId, appId)) {
        LOGE("You do not have the permission to query the group information!");
        return HC_ERR_ACCESS_DENIED;
    }
    DeviceInfoVec deviceInfoVec;
    CreateDeviceInfoVecStruct(&deviceInfoVec);
    int32_t result = GetTrustedDevices(groupId, &deviceInfoVec);
    if (result != HC_SUCCESS) {
        DestroyDeviceInfoVecStruct(&deviceInfoVec);
        return result;
    }
    result = GenerateReturnDeviceVec(&deviceInfoVec, returnDevInfoVec, deviceNum);
    DestroyDeviceInfoVecStruct(&deviceInfoVec);
    return result;
}

static bool IsDeviceInAccessibleGroup(const char *appId, const char *groupId, const char *deviceId, bool isUdid)
{
    if ((appId == NULL) || (groupId == NULL) || (deviceId == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return false;
    }
    if (!IsGroupExistByGroupId(groupId)) {
        LOGE("No group is found based on the query parameters!");
        return false;
    }
    if (!IsGroupAccessible(groupId, appId)) {
        LOGE("You do not have the permission to query the group information!");
        return false;
    }
    return IsTrustedDeviceInGroup(groupId, deviceId, isUdid);
}

static void DestroyInfo(char **returnInfo)
{
    if ((returnInfo == NULL) || (*returnInfo == NULL)) {
        return;
    }
    FreeJsonString(*returnInfo);
    *returnInfo = NULL;
}

static const GroupImpl g_groupImplInstance = {
    .createGroup = RequestCreateGroup,
    .deleteGroup = RequestDeleteGroup,
    .addMember = RequestAddMemberToGroup,
    .deleteMember = RequestDeleteMemberFromGroup,
    .processBindData = RequestProcessBindData,
    .confirmRequest = RequestConfirmRequest,
    .generateAccountGroupId = GenerateAccountGroupId,
    .syncAcrossAccountGroup = SyncAcrossAccountGroup,
    .addGroupRole = AddGroupRoleWithCheck,
    .deleteGroupRole = DeleteGroupRoleWithCheck,
    .getGroupRoles = GetGroupRolesWithCheck,
    .regListener = RegListener,
    .unRegListener = UnRegListener,
    .checkAccessToGroup = CheckAccessToGroup,
    .getPkInfoList = GetPkInfoList,
    .getAccessibleGroupInfoById = GetAccessibleGroupInfoById,
    .getAccessibleGroupInfo = GetAccessibleGroupInfo,
    .getAccessibleJoinedGroups = GetAccessibleJoinedGroups,
    .getAccessibleRelatedGroups = GetAccessibleRelatedGroups,
    .getAccessibleDeviceInfoById = GetAccessibleDeviceInfoById,
    .getAccessibleTrustedDevices = GetAccessibleTrustedDevices,
    .isDeviceInAccessibleGroup = IsDeviceInAccessibleGroup,
    .destroyInfo = DestroyInfo
};

int32_t InitGroupRelatedModule(void)
{
    if (IsBroadcastSupported()) {
        if (InitBroadcastManager() != HC_SUCCESS) {
            LOGE("[End]: [Service]: Failed to init broadcast manage module!");
            return HC_ERR_SERVICE_NEED_RESTART;
        }
    }
    if (IsAcrossAccountGroupSupported()) {
        RegGenerateGroupIdFunc(((AcrossAccountGroup *)GetAcrossAccountGroupInstance())->generateGroupId);
    }
    return HC_SUCCESS;
}

void DestroyGroupRelatedModule(void)
{
    DeregGenerateGroupIdFunc();
    DestroyBroadcastManager();
}

const GroupImpl *GetGroupImplInstance(void)
{
    return &g_groupImplInstance;
}

bool IsGroupSupport(void)
{
    return true;
}