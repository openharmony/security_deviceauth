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

#include "peer_to_peer_group.h"

#include "alg_defs.h"
#include "callback_manager.h"
#include "channel_manager.h"
#include "string_util.h"
#include "database_manager.h"
#include "group_operation_common.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "session_manager.h"

static int32_t CheckGroupName(const char *appId, const CJson *jsonParams)
{
    const char *groupName = GetStringFromJson(jsonParams, FIELD_GROUP_NAME);
    if (groupName == NULL) {
        LOGE("Failed to get groupName from jsonParams!");
        return HC_ERR_JSON_GET;
    }

    if (IsSameNameGroupExist(appId, groupName)) {
        LOGE("A group with the same group name has been created! [AppId]: %s, [GroupName]: %s", appId, groupName);
        return HC_ERR_INVALID_PARAMS;
    }
    return HC_SUCCESS;
}

static int32_t GenerateGroupId(const char *groupName, const char *appId, char **returnGroupId)
{
    /* peer to peer group: groupId = sha256(groupName | appId) */
    uint8_t *hashMessage = NULL;
    uint32_t messageSize = 0;
    Uint8Buff groupNameBuff = {(uint8_t *)groupName, HcStrlen(groupName)};
    Uint8Buff appIdBuff = {(uint8_t *)appId, HcStrlen(appId)};
    int32_t result = GetHashMessage(&groupNameBuff, &appIdBuff, &hashMessage, &messageSize);
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
        LOGE("Failed to get hash for groupId! [AppId]: %s, [GroupName]: %s", appId, groupName);
        HcFree(*returnGroupId);
        *returnGroupId = NULL;
        return HC_ERR_HASH_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t GeneratePeerToPeerGroupId(const CJson *jsonParams, char **returnGroupId)
{
    const char *groupName = GetStringFromJson(jsonParams, FIELD_GROUP_NAME);
    if (groupName == NULL) {
        LOGE("Failed to get groupName from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    const char *appId = GetStringFromJson(jsonParams, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("Failed to get appId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    int32_t result = GenerateGroupId(groupName, appId, returnGroupId);
    if (result != HC_SUCCESS) {
        LOGE("Failed to generate groupId! [GroupName]: %s, [AppId]: %s", groupName, appId);
        return result;
    }
    return HC_SUCCESS;
}

static int32_t CheckCreateParams(const CJson *jsonParams)
{
    const char *appId = GetStringFromJson(jsonParams, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("Failed to get appId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    int32_t result;
    if (((result = CheckGroupName(appId, jsonParams)) != HC_SUCCESS) ||
        ((result = CheckUserTypeIfExist(jsonParams)) != HC_SUCCESS) ||
        ((result = CheckGroupVisibilityIfExist(jsonParams)) != HC_SUCCESS) ||
        ((result = CheckExpireTimeIfExist(jsonParams)) != HC_SUCCESS) ||
        ((result = CheckGroupNumLimit(PEER_TO_PEER_GROUP, appId)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t GenerateGroupParams(const CJson *jsonParams, const char *groupId, GroupInfo *groupParams)
{
    const char *groupName = GetStringFromJson(jsonParams, FIELD_GROUP_NAME);
    if (groupName == NULL) {
        LOGE("Failed to get groupName from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    const char *appId = GetStringFromJson(jsonParams, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("Failed to get appId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    int32_t result;
    if (((result = AddGroupTypeToParams(PEER_TO_PEER_GROUP, groupParams)) != HC_SUCCESS) ||
        ((result = AddGroupNameToParams(groupName, groupParams)) != HC_SUCCESS) ||
        ((result = AddGroupIdToParams(groupId, groupParams)) != HC_SUCCESS) ||
        ((result = AddGroupOwnerToParams(appId, groupParams)) != HC_SUCCESS) ||
        ((result = AddGroupVisibilityOrDefault(jsonParams, groupParams)) != HC_SUCCESS) ||
        ((result = AddExpireTimeOrDefault(jsonParams, groupParams)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t GenerateDevParams(const CJson *jsonParams, const char *groupId, DeviceInfo *devParams)
{
    int32_t result;
    if (((result = AddUdidToParams(devParams)) != HC_SUCCESS) ||
        ((result = AddAuthIdToParamsOrDefault(jsonParams, devParams))) ||
        ((result = AddUserTypeToParamsOrDefault(jsonParams, devParams)) != HC_SUCCESS) ||
        ((result = AddGroupIdToDevParams(groupId, devParams)) != HC_SUCCESS) ||
        ((result = AddServiceTypeToParams(groupId, devParams)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t CreateGroupInner(const CJson *jsonParams, char **returnGroupId)
{
    char *groupId = NULL;
    int32_t result;
    if (((result = CheckCreateParams(jsonParams)) != HC_SUCCESS) ||
        ((result = GeneratePeerToPeerGroupId(jsonParams, &groupId)) != HC_SUCCESS) ||
        ((result = ProcessKeyPair(CREATE_KEY_PAIR, jsonParams, groupId)) != HC_SUCCESS) ||
        ((result = AddGroupToDatabaseByJson(GenerateGroupParams, jsonParams, groupId)) != HC_SUCCESS) ||
        ((result = AddDeviceToDatabaseByJson(GenerateDevParams, jsonParams, groupId)) != HC_SUCCESS)) {
        HcFree(groupId);
        return result;
    }
    *returnGroupId = groupId;
    return HC_SUCCESS;
}

static int32_t GetPeerUserType(const char *groupId, const char *peerAuthId)
{
    int peerUserType = DEVICE_TYPE_ACCESSORY;
    DeviceInfo *devAuthParams = CreateDeviceInfoStruct();
    if (devAuthParams == NULL) {
        LOGE("Failed to allocate devEntry memory!");
        return peerUserType;
    }
    if (GetTrustedDevInfoById(peerAuthId, false, groupId, devAuthParams) != HC_SUCCESS) {
        LOGE("Failed to obtain the device information from the database!");
        DestroyDeviceInfoStruct(devAuthParams);
        return peerUserType;
    }
    peerUserType = devAuthParams->devType;
    DestroyDeviceInfoStruct(devAuthParams);
    return peerUserType;
}

static int32_t HandleLocalUnbind(int64_t requestId, const CJson *jsonParams, const DeviceAuthCallback *callback)
{
    const char *peerAuthId = GetStringFromJson(jsonParams, FIELD_DELETE_ID);
    if (peerAuthId == NULL) {
        LOGE("Failed to get peerAuthId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    const char *groupId = GetStringFromJson(jsonParams, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    int32_t peerUserType = GetPeerUserType(groupId, peerAuthId);
    int32_t result = DelTrustedDevice(peerAuthId, false, groupId);
    if (result != HC_SUCCESS) {
        LOGE("Failed to delete trust device from database!");
        return result;
    }
    /*
     * If the trusted device has been deleted from the database but the peer key fails to be deleted,
     * the forcible unbinding is still considered successful. Only logs need to be printed.
     */
    result = DeletePeerKeyIfForceUnbind(groupId, peerAuthId, peerUserType);
    if (result != HC_SUCCESS) {
        LOGD("Failed to delete peer key!");
    }
    char *returnDataStr = NULL;
    result = GenerateUnbindSuccessData(peerAuthId, groupId, &returnDataStr);
    if (result != HC_SUCCESS) {
        return result;
    }
    ProcessFinishCallback(requestId, MEMBER_DELETE, returnDataStr, callback);
    FreeJsonString(returnDataStr);
    return HC_SUCCESS;
}

static int32_t AddAuthIdAndUserTypeToParams(const char *groupId, CJson *jsonParams)
{
    DeviceInfo *deviceInfo = CreateDeviceInfoStruct();
    if (deviceInfo == NULL) {
        LOGE("Failed to allocate deviceInfo memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    const char *udid = GetLocalDevUdid();
    if (udid == NULL) {
        LOGE("Failed to get local udid!");
        DestroyDeviceInfoStruct(deviceInfo);
        return HC_ERROR;
    }
    if (GetTrustedDevInfoById(udid, true, groupId, deviceInfo) != HC_SUCCESS) {
        LOGE("Failed to obtain the device information from the database!");
        DestroyDeviceInfoStruct(deviceInfo);
        return HC_ERR_DB;
    }
    if (AddStringToJson(jsonParams, FIELD_DEVICE_ID, StringGet(&deviceInfo->authId)) != HC_SUCCESS) {
        LOGE("Failed to add authId to params!");
        DestroyDeviceInfoStruct(deviceInfo);
        return HC_ERR_JSON_FAIL;
    }
    if (AddIntToJson(jsonParams, FIELD_USER_TYPE, deviceInfo->devType) != HC_SUCCESS) {
        LOGE("Failed to add userType to params!");
        DestroyDeviceInfoStruct(deviceInfo);
        return HC_ERR_JSON_FAIL;
    }
    DestroyDeviceInfoStruct(deviceInfo);
    return HC_SUCCESS;
}

static int32_t AssertPeerToPeerGroupType(int32_t groupType)
{
    if (groupType != PEER_TO_PEER_GROUP) {
        LOGE("Invalid group type! [GroupType]: %d", groupType);
        return HC_ERR_INVALID_PARAMS;
    }
    return HC_SUCCESS;
}

static int32_t CheckInputGroupTypeValid(const CJson *jsonParams)
{
    int32_t groupType = PEER_TO_PEER_GROUP;
    if (GetIntFromJson(jsonParams, FIELD_GROUP_TYPE, &groupType) != HC_SUCCESS) {
        LOGE("Failed to get groupType from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    return AssertPeerToPeerGroupType(groupType);
}

static int32_t IsPeerDeviceIdNotSelf(const char *peerUdid)
{
    if (peerUdid == NULL) {
        LOGE("The input peerUdid is NULL!");
        return HC_ERR_NULL_PTR;
    }
    const char *udid = GetLocalDevUdid();
    if (udid == NULL) {
        LOGE("Failed to get local udid!");
        return HC_ERROR;
    }
    if (strcmp(peerUdid, udid) == 0) {
        LOGE("You are not allowed to delete yourself!");
        return HC_ERR_INVALID_PARAMS;
    }
    return HC_SUCCESS;
}

static int32_t CheckPeerDeviceStatus(const char *groupId, const CJson *jsonParams)
{
    const char *peerAuthId = GetStringFromJson(jsonParams, FIELD_DELETE_ID);
    if (peerAuthId == NULL) {
        LOGE("Failed to get peerUdid from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    DeviceInfo *deviceInfo = CreateDeviceInfoStruct();
    if (deviceInfo == NULL) {
        LOGE("Failed to allocate deviceInfo memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t result = GetTrustedDevInfoById(peerAuthId, false, groupId, deviceInfo);
    if (result != HC_SUCCESS) {
        LOGE("Failed to obtain the peer device information from the database!");
        DestroyDeviceInfoStruct(deviceInfo);
        return result;
    }
    result = IsPeerDeviceIdNotSelf(StringGet(&deviceInfo->udid));
    DestroyDeviceInfoStruct(deviceInfo);
    return result;
}

static int32_t CheckInvitePeer(const CJson *jsonParams)
{
    const char *groupId = GetStringFromJson(jsonParams, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    const char *appId = GetStringFromJson(jsonParams, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("Failed to get appId from jsonParams!");
        return HC_ERR_JSON_GET;
    }

    int32_t groupType = PEER_TO_PEER_GROUP;
    int32_t result;
    if (((result = CheckGroupExist(groupId)) != HC_SUCCESS) ||
        ((result = GetGroupTypeFromDb(groupId, &groupType)) != HC_SUCCESS) ||
        ((result = AssertPeerToPeerGroupType(groupType)) != HC_SUCCESS) ||
        ((result = CheckPermForGroup(MEMBER_INVITE, appId, groupId)) != HC_SUCCESS) ||
        ((result = CheckDeviceNumLimit(groupId, NULL)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t CheckJoinPeer(const CJson *jsonParams)
{
    return CheckInputGroupTypeValid(jsonParams);
}

static int32_t CheckDeletePeer(const CJson *jsonParams)
{
    const char *groupId = GetStringFromJson(jsonParams, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    const char *appId = GetStringFromJson(jsonParams, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("Failed to get appId from jsonParams!");
        return HC_ERR_JSON_GET;
    }

    int32_t groupType = PEER_TO_PEER_GROUP;
    int32_t result;
    if (((result = CheckGroupExist(groupId)) != HC_SUCCESS) ||
        ((result = GetGroupTypeFromDb(groupId, &groupType)) != HC_SUCCESS) ||
        ((result = AssertPeerToPeerGroupType(groupType)) != HC_SUCCESS) ||
        ((result = CheckPermForGroup(MEMBER_DELETE, appId, groupId)) != HC_SUCCESS) ||
        ((result = CheckPeerDeviceStatus(groupId, jsonParams)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t CheckClientStatus(int operationCode, const CJson *jsonParams)
{
    switch (operationCode) {
        case MEMBER_INVITE:
            return CheckInvitePeer(jsonParams);
        case MEMBER_JOIN:
            return CheckJoinPeer(jsonParams);
        case MEMBER_DELETE:
            return CheckDeletePeer(jsonParams);
        default:
            LOGE("Enter the exception case!");
            return HC_ERR_CASE;
    }
}

static CJson *GenerateGroupErrorMsg(int32_t errorCode, int64_t requestId, const CJson *jsonParams)
{
    const char *appId = GetStringFromJson(jsonParams, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("Failed to get appId from jsonParams!");
        return NULL;
    }
    CJson *errorData = CreateJson();
    if (errorData == NULL) {
        LOGE("Failed to allocate errorData memory!");
        return NULL;
    }
    if (AddIntToJson(errorData, FIELD_GROUP_ERROR_MSG, errorCode) != HC_SUCCESS) {
        LOGE("Failed to add errorCode to errorData!");
        FreeJson(errorData);
        return NULL;
    }
    if (AddStringToJson(errorData, FIELD_APP_ID, appId) != HC_SUCCESS) {
        LOGE("Failed to add appId to errorData!");
        FreeJson(errorData);
        return NULL;
    }
    if (AddInt64StringToJson(errorData, FIELD_REQUEST_ID, requestId) != HC_SUCCESS) {
        LOGE("Failed to add requestId to errorData!");
        FreeJson(errorData);
        return NULL;
    }
    return errorData;
}

static void InformPeerProcessError(int64_t requestId, const CJson *jsonParams, const DeviceAuthCallback *callback,
    int32_t errorCode)
{
    ChannelType channelType = GetChannelType(callback, jsonParams);
    int64_t channelId = DEFAULT_CHANNEL_ID;
    if ((channelType == SOFT_BUS) &&
        (GetByteFromJson(jsonParams, FIELD_CHANNEL_ID, (uint8_t *)&channelId, sizeof(int64_t)) != HC_SUCCESS)) {
        LOGE("No soft bus available channel found!");
        return;
    }
    CJson *errorData = GenerateGroupErrorMsg(errorCode, requestId, jsonParams);
    if (errorData == NULL) {
        return;
    }
    char *errorDataStr = PackJsonToString(errorData);
    FreeJson(errorData);
    if (errorDataStr == NULL) {
        LOGE("An error occurred when converting json to string!");
        return;
    }
    (void)HcSendMsg(channelType, requestId, channelId, callback, errorDataStr);
    FreeJsonString(errorDataStr);
}

static int32_t CheckServerStatusIfNotInvite(int operationCode, const CJson *jsonParams)
{
    if (operationCode == MEMBER_INVITE) {
        return HC_SUCCESS;
    }
    const char *groupId = GetStringFromJson(jsonParams, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    const char *appId = GetStringFromJson(jsonParams, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("Failed to get appId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    const char *peerUdid = GetStringFromJson(jsonParams, FIELD_CONN_DEVICE_ID);
    if (peerUdid == NULL) {
        LOGE("Failed to get peerUdid from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    int32_t result = CheckGroupExist(groupId);
    if (result != HC_SUCCESS) {
        return result;
    }
    if (operationCode == MEMBER_JOIN) {
        /* The client sends a join request, which is equivalent to the server performing an invitation operation. */
        result = CheckPermForGroup(MEMBER_INVITE, appId, groupId);
        if (result != HC_SUCCESS) {
            return result;
        }
        result = CheckDeviceNumLimit(groupId, peerUdid);
    } else if (operationCode == MEMBER_DELETE) {
        result = CheckPermForGroup(MEMBER_DELETE, appId, groupId);
        if (result != HC_SUCCESS) {
            return result;
        }
        if (!IsTrustedDeviceInGroup(groupId, peerUdid, true)) {
            result = HC_ERR_DEVICE_NOT_EXIST;
        }
    }
    return result;
}

static int32_t ShouldForceUnbind(bool isForceDelete, const CJson *jsonParams)
{
    bool isIgnoreChannel = false;
    (void)GetBoolFromJson(jsonParams, FIELD_IS_IGNORE_CHANNEL, &isIgnoreChannel);
    return (isForceDelete && isIgnoreChannel);
}

static int32_t CreateClientSession(int64_t requestId, int32_t operationCode, ChannelType channelType,
    CJson *jsonParams, const DeviceAuthCallback *callback)
{
    int32_t result = CreateSession(requestId, TYPE_CLIENT_BIND_SESSION, jsonParams, callback);
    if (result != HC_SUCCESS) {
        if (result != HC_ERR_CREATE_SESSION_FAIL) {
            ProcessErrorCallback(requestId, operationCode, result, NULL, callback);
        }
        return result;
    }
    /**
     * If service open the channel by itself,
     * a channel opened message needs to be triggered to unify the channel usage policy.
     */
    if (channelType == SERVICE_CHANNEL) {
        /* Release the memory in advance to reduce the memory usage. */
        DeleteAllItem(jsonParams);
        OnChannelOpened(requestId, DEFAULT_CHANNEL_ID);
    }
    return HC_SUCCESS;
}

static int32_t CreateServerSession(int64_t requestId, int32_t operationCode, CJson *jsonParams,
    const DeviceAuthCallback *callback)
{
    int32_t result = CreateSession(requestId, TYPE_SERVER_BIND_SESSION, jsonParams, callback);
    if (result != HC_SUCCESS) {
        if (result != HC_ERR_CREATE_SESSION_FAIL) {
            InformPeerProcessError(requestId, jsonParams, callback, result);
            ProcessErrorCallback(requestId, operationCode, result, NULL, callback);
        }
        return result;
    }
    return HC_SUCCESS;
}

static int32_t CreateGroup(CJson *jsonParams, char **returnJsonStr)
{
    LOGI("[Start]: Start to create a peer to peer group!");
    if ((jsonParams == NULL) || (returnJsonStr == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    char *groupId = NULL;
    int32_t result = CreateGroupInner(jsonParams, &groupId);
    if (result != HC_SUCCESS) {
        return result;
    }
    result = ConvertGroupIdToJsonStr(groupId, returnJsonStr);
    HcFree(groupId);
    if (result != HC_SUCCESS) {
        return result;
    }
    LOGI("[End]: Create a peer to peer group successfully!");
    return HC_SUCCESS;
}

static int32_t DeleteGroup(CJson *jsonParams, char **returnJsonStr)
{
    LOGI("[Start]: Start to delete a peer to peer group!");
    if ((jsonParams == NULL) || (returnJsonStr == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t result;
    const char *groupId = NULL;
    if (((result = GetGroupIdFromJson(jsonParams, &groupId)) != HC_SUCCESS) ||
        ((result = AddAuthIdAndUserTypeToParams(groupId, jsonParams)) != HC_SUCCESS) ||
        ((result = DelGroupFromDatabase(groupId)) != HC_SUCCESS) ||
        ((result = ConvertGroupIdToJsonStr(groupId, returnJsonStr)) != HC_SUCCESS)) {
        return result;
    }
    /*
     * If the group has been disbanded from the database but the key pair fails to be deleted,
     * we still believe we succeeded in disbanding the group. Only logs need to be printed.
     */
    result = ProcessKeyPair(DELETE_KEY_PAIR, jsonParams, groupId);
    if (result != HC_SUCCESS) {
        LOGD("Failed to delete peer key!");
    }
    LOGI("[End]: Delete a peer to peer group successfully!");
    return HC_SUCCESS;
}

static int32_t AddMemberToGroup(int64_t requestId, CJson *jsonParams, const DeviceAuthCallback *callback)
{
    LOGI("[Start]: Start to add member to a peer to peer group!");
    if ((jsonParams == NULL) || (callback == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t result;
    int operationCode = MEMBER_INVITE;
    (void)GetIntFromJson(jsonParams, FIELD_OPERATION_CODE, &operationCode);
    result = CheckClientStatus(operationCode, jsonParams);
    if (result != HC_SUCCESS) {
        ProcessErrorCallback(requestId, operationCode, result, NULL, callback);
        return result;
    }
    return CreateClientSession(requestId, operationCode, GetChannelType(callback, jsonParams), jsonParams, callback);
}

static int32_t DeleteMemberFromGroup(int64_t requestId, CJson *jsonParams, const DeviceAuthCallback *callback)
{
    LOGI("[Start]: Start to delete member from a peer to peer group!");
    if ((jsonParams == NULL) || (callback == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t result = CheckClientStatus(MEMBER_DELETE, jsonParams);
    if (result != HC_SUCCESS) {
        ProcessErrorCallback(requestId, MEMBER_DELETE, result, NULL, callback);
        return result;
    }
    bool isForceDelete = false;
    (void)(GetBoolFromJson(jsonParams, FIELD_IS_FORCE_DELETE, &isForceDelete));
    if (ShouldForceUnbind(isForceDelete, jsonParams)) {
        result = HandleLocalUnbind(requestId, jsonParams, callback);
        if (result != HC_SUCCESS) {
            ProcessErrorCallback(requestId, MEMBER_DELETE, result, NULL, callback);
        }
        return result;
    }
    return CreateClientSession(requestId, MEMBER_DELETE, GetChannelType(callback, jsonParams), jsonParams, callback);
}

static int32_t ProcessData(int64_t requestId, CJson *jsonParams, const DeviceAuthCallback *callback)
{
    LOGI("[Start]: Start to process binding data!");
    if ((jsonParams == NULL) || (callback == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    int operationCode = MEMBER_INVITE;
    (void)(GetIntFromJson(jsonParams, FIELD_GROUP_OP, &operationCode));
    int32_t result = CheckServerStatusIfNotInvite(operationCode, jsonParams);
    if (result != HC_SUCCESS) {
        InformPeerProcessError(requestId, jsonParams, callback, result);
        ProcessErrorCallback(requestId, operationCode, result, NULL, callback);
        return result;
    }
    return CreateServerSession(requestId, operationCode, jsonParams, callback);
}

static int32_t AddManagerWithCheck(const char *appId, const char *groupId, const char *managerAppId)
{
    int32_t groupType = PEER_TO_PEER_GROUP;
    if (GetGroupTypeFromDb(groupId, &groupType) != HC_SUCCESS) {
        LOGE("No group is found based on the query parameters!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    if (AssertPeerToPeerGroupType(groupType) != HC_SUCCESS) {
        return HC_ERR_NOT_SUPPORT;
    }
    if (!IsGroupOwner(groupId, appId)) {
        LOGE("You do not have the permission to add a manager to the group!");
        return HC_ERR_ACCESS_DENIED;
    }
    if (AddGroupRole(groupId, GROUP_MANAGER, managerAppId) != HC_SUCCESS) {
        LOGE("Failed to add manager!");
        return HC_ERR_DB;
    }
    return HC_SUCCESS;
}

static int32_t AddFriendWithCheck(const char *appId, const char *groupId, const char *friendAppId)
{
    int32_t groupType = PEER_TO_PEER_GROUP;
    if (GetGroupTypeFromDb(groupId, &groupType) != HC_SUCCESS) {
        LOGE("No group is found based on the query parameters!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    if (AssertPeerToPeerGroupType(groupType) != HC_SUCCESS) {
        return HC_ERR_NOT_SUPPORT;
    }
    if (!IsGroupEditAllowed(groupId, appId)) {
        LOGE("You do not have the permission to add a friend to the group!");
        return HC_ERR_ACCESS_DENIED;
    }
    if (CompareVisibility(groupId, GROUP_VISIBILITY_ALLOW_LIST) != HC_SUCCESS) {
        LOGE("The group dose not support the allow list protection!");
        return HC_ERR_NOT_SUPPORT;
    }
    if (AddGroupRole(groupId, GROUP_FRIEND, friendAppId) != HC_SUCCESS) {
        LOGE("Failed to add friend!");
        return HC_ERR_DB;
    }
    return HC_SUCCESS;
}

static int32_t DeleteManagerWithCheck(const char *appId, const char *groupId, const char *managerAppId)
{
    int32_t groupType = PEER_TO_PEER_GROUP;
    if (GetGroupTypeFromDb(groupId, &groupType) != HC_SUCCESS) {
        LOGE("No group is found based on the query parameters!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    if (AssertPeerToPeerGroupType(groupType) != HC_SUCCESS) {
        return HC_ERR_NOT_SUPPORT;
    }
    if (!IsGroupOwner(groupId, appId)) {
        LOGE("You do not have the permission to delete a manager from the group!");
        return HC_ERR_ACCESS_DENIED;
    }
    if (RemoveGroupRole(groupId, GROUP_MANAGER, managerAppId) != HC_SUCCESS) {
        LOGE("Failed to delete manager!");
        return HC_ERR_DB;
    }
    return HC_SUCCESS;
}

static int32_t DeleteFriendWithCheck(const char *appId, const char *groupId, const char *friendAppId)
{
    int32_t groupType = PEER_TO_PEER_GROUP;
    if (GetGroupTypeFromDb(groupId, &groupType) != HC_SUCCESS) {
        LOGE("No group is found based on the query parameters!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    if (AssertPeerToPeerGroupType(groupType) != HC_SUCCESS) {
        return HC_ERR_NOT_SUPPORT;
    }
    if (!IsGroupEditAllowed(groupId, appId)) {
        LOGE("You do not have the permission to add a friend to the group!");
        return HC_ERR_ACCESS_DENIED;
    }
    if (CompareVisibility(groupId, GROUP_VISIBILITY_ALLOW_LIST) != HC_SUCCESS) {
        LOGE("The group dose not support the allow list protection!");
        return HC_ERR_NOT_SUPPORT;
    }
    if (RemoveGroupRole(groupId, GROUP_FRIEND, friendAppId) != HC_SUCCESS) {
        LOGE("Failed to delete friend!");
        return HC_ERR_DB;
    }
    return HC_SUCCESS;
}

static int32_t GetManagersWithCheck(const char *appId, const char *groupId, char **returnManagers, uint32_t *returnSize)
{
    int32_t groupType = PEER_TO_PEER_GROUP;
    if (GetGroupTypeFromDb(groupId, &groupType) != HC_SUCCESS) {
        LOGE("No group is found based on the query parameters!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    if (AssertPeerToPeerGroupType(groupType) != HC_SUCCESS) {
        return HC_ERR_NOT_SUPPORT;
    }
    if (!IsGroupOwner(groupId, appId)) {
        LOGE("You do not have the permission to query the group managers information!");
        return HC_ERR_ACCESS_DENIED;
    }
    CJson *managers = CreateJsonArray();
    if (managers == NULL) {
        LOGE("Failed to allocate managers memory!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t result = GetGroupRoles(groupId, GROUP_MANAGER, managers);
    if (result != HC_SUCCESS) {
        LOGE("Failed to get managers!");
        FreeJson(managers);
        return result;
    }
    *returnManagers = PackJsonToString(managers);
    if (*returnManagers == NULL) {
        LOGE("Failed to convert json to string!");
        FreeJson(managers);
        return HC_ERR_JSON_FAIL;
    }
    *returnSize = GetItemNum(managers);
    FreeJson(managers);
    return HC_SUCCESS;
}

static int32_t GetFriendsWithCheck(const char *appId, const char *groupId, char **returnFriends, uint32_t *returnSize)
{
    int32_t groupType = PEER_TO_PEER_GROUP;
    if (GetGroupTypeFromDb(groupId, &groupType) != HC_SUCCESS) {
        LOGE("No group is found based on the query parameters!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    if (AssertPeerToPeerGroupType(groupType) != HC_SUCCESS) {
        return HC_ERR_NOT_SUPPORT;
    }
    if (!IsGroupEditAllowed(groupId, appId)) {
        LOGE("You do not have the permission to query the group friends information!");
        return HC_ERR_ACCESS_DENIED;
    }
    CJson *friends = CreateJsonArray();
    if (friends == NULL) {
        LOGE("Failed to allocate friends memory!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t result = GetGroupRoles(groupId, GROUP_FRIEND, friends);
    if (result != HC_SUCCESS) {
        LOGE("Failed to get friends!");
        FreeJson(friends);
        return result;
    }
    *returnFriends = PackJsonToString(friends);
    if (*returnFriends == NULL) {
        LOGE("Failed to convert json to string!");
        FreeJson(friends);
        return HC_ERR_JSON_FAIL;
    }
    *returnSize = GetItemNum(friends);
    FreeJson(friends);
    return HC_SUCCESS;
}

static int32_t AddGroupRoleWithCheck(bool isManager, const char *appId, const char *groupId, const char *roleAppId)
{
    if (isManager) {
        return AddManagerWithCheck(appId, groupId, roleAppId);
    }
    return AddFriendWithCheck(appId, groupId, roleAppId);
}

static int32_t DeleteGroupRoleWithCheck(bool isManager, const char *appId, const char *groupId, const char *roleAppId)
{
    if (isManager) {
        return DeleteManagerWithCheck(appId, groupId, roleAppId);
    }
    return DeleteFriendWithCheck(appId, groupId, roleAppId);
}

static int32_t GetGroupRolesWithCheck(bool isManager, const char *appId, const char *groupId, char **returnJsonStr,
    uint32_t *returnSize)
{
    if (isManager) {
        return GetManagersWithCheck(appId, groupId, returnJsonStr, returnSize);
    }
    return GetFriendsWithCheck(appId, groupId, returnJsonStr, returnSize);
}

static PeerToPeerGroup g_peerToPeerGroup = {
    .base.type = PEER_TO_PEER_GROUP,
    .base.createGroup = CreateGroup,
    .base.deleteGroup = DeleteGroup,
    .addMember = AddMemberToGroup,
    .deleteMember = DeleteMemberFromGroup,
    .processData = ProcessData,
    .addGroupRole = AddGroupRoleWithCheck,
    .deleteGroupRole = DeleteGroupRoleWithCheck,
    .getGroupRoles = GetGroupRolesWithCheck,
};

BaseGroup *GetPeerToPeerGroupInstance(void)
{
    return (BaseGroup *)&g_peerToPeerGroup;
}

bool IsPeerToPeerGroupSupported(void)
{
    return true;
}
