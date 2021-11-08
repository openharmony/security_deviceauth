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

#ifndef DATABASE_MANAGER_H
#define DATABASE_MANAGER_H

#include "common_defs.h"
#include "common_util.h"
#include "database.h"

#define HC_TRUST_DEV_ENTRY_MAX_NUM 101
#define HC_TRUST_GROUP_ENTRY_MAX_NUM 100

typedef struct {
    int32_t type; /* group type */
    int32_t visibility; /* group visibility */
    char *udid; /* unique device id */
    char *authId; /* id by service defined for authentication */
} GroupQueryParams;

typedef enum {
    GROUP_MANAGER = 1,
    GROUP_FRIEND = 2
} GroupRole;

#ifdef __cplusplus
extern "C" {
#endif

int32_t InitDatabase(void);
void DestroyDatabase(void);

StringVector CreateStrVector(void);
void DestroyStrVector(StringVector *obj);

int32_t AddGroup(const GroupInfo *addParams);
int32_t DelGroupByGroupId(const char *groupId);
int32_t AddTrustedDevice(const DeviceInfo *deviceInfo, const Uint8Buff *ext);
int32_t DelTrustedDevice(const char *deviceId, bool isUdid, const char *groupId);
int32_t DeleteUserIdExpiredGroups(const char *curUserIdHash);
int32_t DeleteAllAccountGroup(void);
int32_t OnlyAddSharedUserIdVec(const StringVector *sharedUserIdHashVec, CJson *groupIdList);
int32_t ChangeSharedUserIdVec(const StringVector *sharedUserIdHashVec);

const char *GetLocalDevUdid(void);

void RegGenerateGroupIdFunc(GenGroupIdFunc func);
void DeregGenerateGroupIdFunc(void);

int32_t GetTrustedDevNumber(void);
int32_t GetGroupInfoById(const char *groupId, GroupInfo *returnGroupInfo);
int32_t GetGroupInfoIfDevExist(const char *groupId, const char *udid, GroupInfo *returnGroupInfo);
int32_t GetDeviceInfoById(const char *deviceId, bool isUdid, const char *groupId, DeviceInfo *deviceInfo);
int32_t GetJoinedGroupInfoVecByDevId(const GroupQueryParams *params, GroupInfoVec *vec);
int32_t GetGroupNumByOwner(const char *ownerName);
int32_t GetCurDeviceNumByGroupId(const char *groupId);
int32_t CompareVisibility(const char *groupId, int groupVisibility);
bool IsGroupOwner(const char *groupId, const char *appId);
bool IsGroupAccessible(const char *groupId, const char *appId);
bool IsGroupEditAllowed(const char *groupId, const char *appId);
bool IsSameNameGroupExist(const char *ownerName, const char *groupName);
bool IsIdenticalGroupExist(void);
bool IsAcrossAccountGroupExist(void);
bool IsGroupExistByGroupId(const char *groupId);
bool IsTrustedDeviceExist(const char *udid);
bool IsTrustedDeviceInGroup(const char *groupId, const char *deviceId, bool isUdid);
int32_t GetJoinedGroups(int groupType, GroupInfoVec *groupInfoVec);
int32_t GetGroupInfo(int groupType, const char *groupId, const char *groupName, const char *groupOwner,
    GroupInfoVec *groupInfoVec);
int32_t GetRelatedGroups(const char *peerDeviceId, bool isUdid, GroupInfoVec *groupInfoVec);
int32_t GetTrustedDevices(const char *groupId, DeviceInfoVec *deviceInfoVec);

int32_t AddGroupRole(const char *groupId, GroupRole roleType, const char *appId);
int32_t RemoveGroupRole(const char *groupId, GroupRole roleType, const char *appId);
int32_t GetGroupRoles(const char *groupId, GroupRole roleType, CJson *returnRoles);

GroupInfo *CreateGroupInfoStruct(void);
DeviceInfo *CreateDeviceInfoStruct(void);
void DestroyGroupInfoStruct(GroupInfo *groupInfo);
void DestroyDeviceInfoStruct(DeviceInfo *deviceInfo);
void CreateGroupInfoVecStruct(GroupInfoVec *vec);
void DestroyGroupInfoVecStruct(GroupInfoVec *vec);
void CreateDeviceInfoVecStruct(DeviceInfoVec *vec);
void DestroyDeviceInfoVecStruct(DeviceInfoVec *vec);

#ifdef __cplusplus
}
#endif
#endif