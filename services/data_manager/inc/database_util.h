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

#ifndef DATABASE_UTIL_H
#define DATABASE_UTIL_H

#include "database.h"

#ifdef __cplusplus
extern "C" {
#endif

bool SetGroupElement(TlvGroupElement *element, TrustedGroupEntry **entry);
bool SetDeviceElement(TlvDevAuthElement *element, TrustedDeviceEntry *entry);

void RegGenerateGroupIdFunc(GenGroupIdFunc func);
void DeregGenerateGroupIdFunc(void);

bool LoadStringVectorFromParcel(StringVector *vec, HcParcel *parcel);
bool SaveStringVectorToParcel(const StringVector *vec, HcParcel *parcel);

StringVector CreateStrVector(void);
void DestroyStrVector(StringVector *vec);
GroupInfo *CreateGroupInfoStruct(void);
void DestroyGroupInfoStruct(GroupInfo *groupInfo);
DeviceInfo *CreateDeviceInfoStruct(void);
void DestroyDeviceInfoStruct(DeviceInfo *deviceInfo);
TrustedGroupEntry *CreateGroupEntryStruct(void);
void DestroyGroupEntryStruct(TrustedGroupEntry *groupEntry);
void DestroyDeviceEntryStruct(TrustedDeviceEntry *deviceEntry);

int32_t GenerateGroupInfoByEntry(const TrustedGroupEntry *groupEntry, const char *groupId,
    const char *sharedUserIdHash, GroupInfo *returnGroupInfo);
int32_t GenerateDeviceInfoByEntry(const TrustedDeviceEntry *deviceEntry, const char *groupId,
    DeviceInfo *returnDeviceInfo);

int32_t GetSharedUserIdFromVecByGroupId(const TrustedGroupEntry *groupEntry, const char *groupId,
    const char **returnUserIdHash);
void AddNewSharedUserId(const StringVector *sharedUserIdHashList, TrustedGroupEntry *entry, CJson *groupIdList);
void DeleteExpiredSharedUserId(const StringVector *sharedUserIdHashList, TrustedGroupEntry *entry);

bool CompareGroupTypeInGroupEntryOrAll(const TrustedGroupEntry *groupEntry, int32_t groupType);
bool CompareDevIdInDeviceEntryOrNull(const TrustedDeviceEntry *deviceEntry, const char *devId, bool isUdid);
bool CompareGroupIdInDeviceEntryOrNull(const TrustedDeviceEntry *deviceEntry, const char *groupId);
bool CompareSearchParams(int32_t groupType, const char *groupId, const char *groupName, const char *groupOwner,
    const TrustedGroupEntry *entry);
bool IsGroupIdEquals(const TrustedGroupEntry *groupEntry, const char *groupId);
bool IsGroupNameEquals(const TrustedGroupEntry *groupEntry, const char *groupName);
bool IsGroupManager(const char *appId, const TrustedGroupEntry *entry);
bool IsGroupFriend(const char *appId, const TrustedGroupEntry *entry);
bool SatisfyType(int32_t type, int32_t standardType);
bool SatisfyVisibility(int32_t visibility, int32_t standardVisibility);

void NotifyGroupCreated(const TrustedGroupEntry *groupEntry, const char *sharedUserIdHash);
void NotifyGroupDeleted(const TrustedGroupEntry *groupEntry, const char *sharedUserIdHash);
void NotifyDeviceBound(const TrustedDeviceEntry *deviceEntry);
void NotifyDeviceUnBound(const TrustedDeviceEntry *deviceEntry);
void NotifyDeviceNotTrusted(const char *peerUdid);
void NotifyLastGroupDeleted(const char *peerUdid, int groupType);
void NotifyTrustedDeviceNumChanged(int trustedDeviceNum);

#ifdef __cplusplus
}
#endif
#endif