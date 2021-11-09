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

#include "group_manager.h"

#include "bind_peer.h"
#include "common_defs.h"
#include "database_manager.h"
#include "group_operation.h"
#include "key_agree.h"

int32_t CreateGroupImpl(int64_t requestId, const char *appId, const char *createParams)
{
    return IsGroupSupport() ? GetGroupImplInstance()->createGroup(requestId, appId, createParams) : HC_ERR_NOT_SUPPORT;
}

int32_t DeleteGroupImpl(int64_t requestId, const char *appId, const char *disbandParams)
{
    return IsGroupSupport() ? GetGroupImplInstance()->deleteGroup(requestId, appId, disbandParams) : HC_ERR_NOT_SUPPORT;
}

int32_t AddMemberToGroupImpl(int64_t requestId, const char *appId, const char *addParams)
{
    return IsGroupSupport() ? GetGroupImplInstance()->addMember(requestId, appId, addParams) : HC_ERR_NOT_SUPPORT;
}

int32_t DeleteMemberFromGroupImpl(int64_t requestId, const char *appId, const char *deleteParams)
{
    return IsGroupSupport() ? GetGroupImplInstance()->deleteMember(requestId, appId, deleteParams) : HC_ERR_NOT_SUPPORT;
}

int32_t ProcessBindDataImpl(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    return IsGroupSupport() ? GetGroupImplInstance()->processBindData(requestId, data, dataLen) : HC_ERR_NOT_SUPPORT;
}

int32_t ConfirmRequestImpl(int64_t requestId, const char *appId, const char *confirmParams)
{
    return IsGroupSupport() ? GetGroupImplInstance()->confirmRequest(requestId, appId,
        confirmParams) : HC_ERR_NOT_SUPPORT;
}

int32_t GenerateAccountGroupIdImpl(int32_t groupType, const char *userIdHash, const char *sharedUserIdHash,
    char **returnGroupId)
{
    return IsGroupSupport() ? GetGroupImplInstance()->generateAccountGroupId(groupType, userIdHash, sharedUserIdHash,
        returnGroupId) : HC_ERR_NOT_SUPPORT;
}

int32_t SyncAcrossAccountGroupImpl(const char *appId, const char *userIdHash, const char *deviceId,
    const CJson *sharedUserIdHashList)
{
    return IsGroupSupport() ? GetGroupImplInstance()->syncAcrossAccountGroup(appId, userIdHash, deviceId,
        sharedUserIdHashList) : HC_ERR_NOT_SUPPORT;
}

int32_t AddGroupManagerImpl(const char *appId, const char *groupId, const char *managerAppId)
{
    return IsGroupSupport() ? GetGroupImplInstance()->addGroupRole(true, appId, groupId,
        managerAppId) : HC_ERR_NOT_SUPPORT;
}

int32_t AddGroupFriendImpl(const char *appId, const char *groupId, const char *friendAppId)
{
    return IsGroupSupport() ? GetGroupImplInstance()->addGroupRole(false, appId, groupId,
        friendAppId) : HC_ERR_NOT_SUPPORT;
}

int32_t DeleteGroupManagerImpl(const char *appId, const char *groupId, const char *managerAppId)
{
    return IsGroupSupport() ? GetGroupImplInstance()->deleteGroupRole(true, appId, groupId,
        managerAppId) : HC_ERR_NOT_SUPPORT;
}

int32_t DeleteGroupFriendImpl(const char *appId, const char *groupId, const char *friendAppId)
{
    return IsGroupSupport() ? GetGroupImplInstance()->deleteGroupRole(false, appId, groupId,
        friendAppId) : HC_ERR_NOT_SUPPORT;
}

int32_t GetGroupManagersImpl(const char *appId, const char *groupId, char **returnManagers, uint32_t *returnSize)
{
    return IsGroupSupport() ? GetGroupImplInstance()->getGroupRoles(true, appId, groupId,
        returnManagers, returnSize) : HC_ERR_NOT_SUPPORT;
}

int32_t GetGroupFriendsImpl(const char *appId, const char *groupId, char **returnFriends, uint32_t *returnSize)
{
    return IsGroupSupport() ? GetGroupImplInstance()->getGroupRoles(false, appId, groupId,
        returnFriends, returnSize) : HC_ERR_NOT_SUPPORT;
}

int32_t RegListenerImpl(const char *appId, const DataChangeListener *listener)
{
    return IsGroupSupport() ? GetGroupImplInstance()->regListener(appId, listener) : HC_ERR_NOT_SUPPORT;
}

int32_t UnRegListenerImpl(const char *appId)
{
    return IsGroupSupport() ? GetGroupImplInstance()->unRegListener(appId) : HC_ERR_NOT_SUPPORT;
}

int32_t CheckAccessToGroupImpl(const char *appId, const char *groupId)
{
    return IsGroupSupport() ? GetGroupImplInstance()->checkAccessToGroup(appId, groupId) : HC_ERR_NOT_SUPPORT;
}

int32_t GetPkInfoListImpl(const char *appId, const char *queryParams, char **returnInfoList, uint32_t *returnInfoNum)
{
    return IsGroupSupport() ? GetGroupImplInstance()->getPkInfoList(appId, queryParams, returnInfoList,
        returnInfoNum) : HC_ERR_NOT_SUPPORT;
}

int32_t GetGroupInfoByIdImpl(const char *appId, const char *groupId, char **returnGroupInfo)
{
    return IsGroupSupport() ? GetGroupImplInstance()->getAccessibleGroupInfoById(appId, groupId,
        returnGroupInfo) : HC_ERR_NOT_SUPPORT;
}

int32_t GetGroupInfoImpl(const char *appId, const char *queryParams, char **returnGroupVec, uint32_t *groupNum)
{
    return IsGroupSupport() ? GetGroupImplInstance()->getAccessibleGroupInfo(appId, queryParams, returnGroupVec,
        groupNum) : HC_ERR_NOT_SUPPORT;
}

int32_t GetJoinedGroupsImpl(const char *appId, int groupType, char **returnGroupVec, uint32_t *groupNum)
{
    return IsGroupSupport() ? GetGroupImplInstance()->getAccessibleJoinedGroups(appId, groupType, returnGroupVec,
        groupNum) : HC_ERR_NOT_SUPPORT;
}

int32_t GetRelatedGroupsImpl(const char *appId, const char *peerDeviceId, char **returnGroupVec, uint32_t *groupNum)
{
    return IsGroupSupport() ? GetGroupImplInstance()->getAccessibleRelatedGroups(appId, peerDeviceId, false,
        returnGroupVec, groupNum) : HC_ERR_NOT_SUPPORT;
}

int32_t GetDeviceInfoByIdImpl(const char *appId, const char *deviceId, const char *groupId, char **returnDeviceInfo)
{
    return IsGroupSupport() ? GetGroupImplInstance()->getAccessibleDeviceInfoById(appId, deviceId, false, groupId,
        returnDeviceInfo) : HC_ERR_NOT_SUPPORT;
}

int32_t GetTrustedDevicesImpl(const char *appId, const char *groupId, char **returnDevInfoVec, uint32_t *deviceNum)
{
    return IsGroupSupport() ? GetGroupImplInstance()->getAccessibleTrustedDevices(appId, groupId, returnDevInfoVec,
        deviceNum) : HC_ERR_NOT_SUPPORT;
}

bool IsDeviceInGroupImpl(const char *appId, const char *groupId, const char *deviceId)
{
    return IsGroupSupport() ? GetGroupImplInstance()->isDeviceInAccessibleGroup(appId, groupId,
        deviceId, false) : false;
}

void DestroyInfoImpl(char **returnInfo)
{
    if (IsGroupSupport()) {
        GetGroupImplInstance()->destroyInfo(returnInfo);
    }
}

int32_t BindPeerImpl(int64_t requestId, const char *appId, const char *bindParams)
{
    return RequestBindPeer(requestId, appId, bindParams);
}

int32_t UnbindPeerImpl(int64_t requestId, const char *appId, const char *unbindParams)
{
    return RequestUnbindPeer(requestId, appId, unbindParams);
}

int32_t ProcessLiteDataImpl(int64_t requestId, const char *appId, const uint8_t *data, uint32_t dataLen)
{
    return RequestProcessLiteData(requestId, appId, data, dataLen);
}

int32_t AuthKeyAgreeImpl(int64_t requestId, const char *appId, const char *agreeParams)
{
    return RequestAuthKeyAgree(requestId, appId, agreeParams);
}

int32_t ProcessKeyAgreeDataImpl(int64_t requestId, const char *appId, const uint8_t *data, uint32_t dataLen)
{
    return RequestProcessKeyAgreeData(requestId, appId, data, dataLen);
}

int32_t InitGroupManager(void)
{
    if (InitDatabase() != HC_SUCCESS) {
        return HC_ERR_SERVICE_NEED_RESTART;
    }
    return IsGroupSupport() ? InitGroupRelatedModule() : HC_SUCCESS;
}

void DestroyGroupManager(void)
{
    if (IsGroupSupport()) {
        DestroyGroupRelatedModule();
    }
    DestroyDatabase();
}