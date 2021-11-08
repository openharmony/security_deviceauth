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

#include "database_util.h"

#include "broadcast_manager.h"
#include "device_auth.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hc_types.h"
#include "securec.h"

IMPLEMENT_HC_VECTOR(StringVector, HcString, 1)

/* cache across account groupId func */
static GenGroupIdFunc g_generateIdFunc = NULL;

static bool EndWithZero(HcParcel *parcel)
{
    const char *p = GetParcelLastChar(parcel);
    if (p == NULL) {
        return false;
    }
    if (*p == '\0') {
        return true;
    }
    return false;
}

static int32_t GenerateGroupInfoCommonByEntry(const TrustedGroupEntry *groupEntry, GroupInfo *returnGroupInfo)
{
    if (HC_VECTOR_SIZE(&(groupEntry->managers)) == 0) {
        LOGE("[DB]: The group owner is lost!");
        return HC_ERR_LOST_DATA;
    }
    HcString entryOwner = HC_VECTOR_GET(&groupEntry->managers, 0);
    if (!StringSet(&(returnGroupInfo->ownerName), entryOwner)) {
        LOGE("[DB]: Failed to copy groupOwner!");
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSet(&(returnGroupInfo->userIdHash), groupEntry->userIdHash)) {
        LOGE("[DB]: Failed to copy userIdHash!");
        return HC_ERR_MEMORY_COPY;
    }
    returnGroupInfo->type = groupEntry->type;
    returnGroupInfo->visibility = groupEntry->visibility;
    returnGroupInfo->expireTime = groupEntry->expireTime;
    return HC_SUCCESS;
}

static int32_t GenerateGroupInfoIdAndName(const char *groupId, const char *groupName, GroupInfo *returnGroupInfo)
{
    if (!StringSetPointer(&(returnGroupInfo->id), groupId)) {
        LOGE("[DB]: Failed to copy groupId!");
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSetPointer(&(returnGroupInfo->name), groupName)) {
        LOGE("[DB]: Failed to copy groupName!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t GenerateGroupInfoSharedUserIdHash(const char *sharedUserIdHash, GroupInfo *returnGroupInfo)
{
    if (!StringSetPointer(&(returnGroupInfo->sharedUserIdHash), sharedUserIdHash)) {
        LOGE("[DB]: Failed to copy sharedUserIdHash!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t GenerateAcrossAccountGroupInfoById(const TrustedGroupEntry *groupEntry, const char *groupId,
    GroupInfo *returnGroupInfo)
{
    int32_t result = GenerateGroupInfoIdAndName(groupId, groupId, returnGroupInfo);
    if (result != HC_SUCCESS) {
        return result;
    }
    const char *targetSharedUserIdHash = NULL;
    result = GetSharedUserIdFromVecByGroupId(groupEntry, groupId, &targetSharedUserIdHash);
    if (result != HC_SUCCESS) {
        return result;
    }
    return GenerateGroupInfoSharedUserIdHash(targetSharedUserIdHash, returnGroupInfo);
}

static int32_t GenerateAcrossAccountGroupInfoByUserIdHash(const TrustedGroupEntry *groupEntry,
    const char *sharedUserIdHash, GroupInfo *returnGroupInfo)
{
    if (g_generateIdFunc == NULL) {
        LOGE("[DB]: Generate groupId function is NULL!");
        return HC_ERR_NOT_SUPPORT;
    }
    char *tempGroupId = NULL;
    const char *userIdHash = StringGet(&groupEntry->userIdHash);
    if (userIdHash == NULL) {
        LOGE("[DB]: Failed to get userIdHash from groupEntry!");
        return HC_ERR_NULL_PTR;
    }
    int32_t result = g_generateIdFunc(userIdHash, sharedUserIdHash, &tempGroupId);
    if (result != HC_SUCCESS) {
        LOGE("[DB]: Failed to generate temp groupId!");
        return result;
    }
    result = GenerateGroupInfoIdAndName(tempGroupId, tempGroupId, returnGroupInfo);
    HcFree(tempGroupId);
    if (result != HC_SUCCESS) {
        return result;
    }
    return GenerateGroupInfoSharedUserIdHash(sharedUserIdHash, returnGroupInfo);
}

static int32_t GenerateDeviceInfoCommonByEntry(const TrustedDeviceEntry *entry, DeviceInfo *returnDeviceInfo)
{
    if (!StringSet(&returnDeviceInfo->udid, entry->udid)) {
        LOGE("[DB]: Failed to copy udid!");
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSet(&returnDeviceInfo->authId, entry->authId)) {
        LOGE("[DB]: Failed to copy authId!");
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSet(&returnDeviceInfo->serviceType, entry->serviceType)) {
        LOGE("[DB]: Failed to copy serviceType!");
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSet(&returnDeviceInfo->userIdHash, entry->userIdHash)) {
        LOGE("[DB]: Failed to copy userIdHash!");
        return HC_ERR_MEMORY_COPY;
    }
    returnDeviceInfo->credential = entry->credential;
    returnDeviceInfo->devType = entry->devType;
    return HC_SUCCESS;
}

static int32_t GenerateDeviceInfoId(const char *groupId, DeviceInfo *returnDeviceInfo)
{
    if (!StringSetPointer(&(returnDeviceInfo->groupId), groupId)) {
        LOGE("[DB]: Failed to copy groupId!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t GenerateGroupInfoByDevEntry(const TrustedDeviceEntry *deviceEntry, GroupInfo *groupInfo)
{
    const TrustedGroupEntry *groupEntry = deviceEntry->groupEntry;
    if (groupEntry == NULL) {
        LOGE("[DB]: The groupEntry is NULL!");
        return HC_ERR_NULL_PTR;
    }
    const char *groupId = StringGet(&deviceEntry->serviceType);
    if (groupId == NULL) {
        LOGE("[DB]: The groupId is NULL!");
        return HC_ERR_NULL_PTR;
    }
    return GenerateGroupInfoByEntry(groupEntry, groupId, NULL, groupInfo);
}

static int32_t AddGroupIdToList(const char *userIdHash, const char *sharedUserIdHash, CJson *groupIdList)
{
    char *groupId = NULL;
    int32_t result = g_generateIdFunc(userIdHash, sharedUserIdHash, &groupId);
    if (result != HC_SUCCESS) {
        LOGE("[DB]: Failed to generate groupId!");
        return result;
    }
    if (AddStringToArray(groupIdList, groupId) != HC_SUCCESS) {
        LOGE("[DB]: Failed to add groupId to groupIdList!");
        HcFree(groupId);
        return HC_ERR_JSON_ADD;
    }
    HcFree(groupId);
    return HC_SUCCESS;
}

bool LoadStringVectorFromParcel(StringVector *vec, HcParcel *parcel)
{
    uint32_t strLen = 0;
    do {
        if (!ParcelReadUint32(parcel, &strLen)) {
            return true;
        }
        if ((strLen == 0) || (strLen > MAX_STRING_LEN)) {
            return false;
        }
        HcString str = CreateString();
        ClearParcel(&str.parcel);
        if (!ParcelReadParcel(parcel, &str.parcel, strLen, false) ||
            !EndWithZero(&str.parcel)) {
            DeleteString(&str);
            return false;
        } else {
            if (vec->pushBack(vec, &str) == NULL) {
                DeleteString(&str);
                return false;
            }
        }
    } while (1);
}

bool SaveStringVectorToParcel(const StringVector *vec, HcParcel *parcel)
{
    uint32_t index;
    HcString *str = NULL;
    FOR_EACH_HC_VECTOR(*vec, index, str) {
        uint32_t len = StringLength(str) + sizeof(char);
        if (!ParcelWriteUint32(parcel, len)) {
            return false;
        }
        if (!ParcelWrite(parcel, GetParcelData(&str->parcel), GetParcelDataSize(&str->parcel))) {
            return false;
        }
    }
    return true;
}

StringVector CreateStrVector(void)
{
    return CreateStringVector();
}

void DestroyStrVector(StringVector *vec)
{
    uint32_t index;
    HcString *strItemPtr = NULL;
    FOR_EACH_HC_VECTOR(*vec, index, strItemPtr) {
        DeleteString(strItemPtr);
    }
    DESTROY_HC_VECTOR(StringVector, vec)
}

GroupInfo *CreateGroupInfoStruct(void)
{
    GroupInfo *ptr = (GroupInfo *)HcMalloc(sizeof(GroupInfo), 0);
    if (ptr == NULL) {
        LOGE("[DB]: Failed to allocate groupInfo memory!");
        return NULL;
    }
    ptr->name = CreateString();
    ptr->id = CreateString();
    ptr->ownerName = CreateString();
    ptr->userIdHash = CreateString();
    ptr->sharedUserIdHash = CreateString();
    return ptr;
}

void DestroyGroupInfoStruct(GroupInfo *groupInfo)
{
    if (groupInfo == NULL) {
        return;
    }
    DeleteString(&(groupInfo->name));
    DeleteString(&(groupInfo->id));
    DeleteString(&(groupInfo->ownerName));
    DeleteString(&(groupInfo->userIdHash));
    DeleteString(&(groupInfo->sharedUserIdHash));
    HcFree(groupInfo);
}

DeviceInfo *CreateDeviceInfoStruct(void)
{
    DeviceInfo *deviceInfo = (DeviceInfo *)HcMalloc(sizeof(DeviceInfo), 0);
    if (deviceInfo == NULL) {
        LOGE("[DB]: Failed to allocate deviceInfo memory!");
        return NULL;
    }
    deviceInfo->authId = CreateString();
    deviceInfo->udid = CreateString();
    deviceInfo->serviceType = CreateString();
    deviceInfo->userIdHash = CreateString();
    deviceInfo->groupId = CreateString();
    return deviceInfo;
}

void DestroyDeviceInfoStruct(DeviceInfo *deviceInfo)
{
    if (deviceInfo == NULL) {
        return;
    }
    DeleteString(&(deviceInfo->authId));
    DeleteString(&(deviceInfo->udid));
    DeleteString(&(deviceInfo->serviceType));
    DeleteString(&(deviceInfo->userIdHash));
    DeleteString(&(deviceInfo->groupId));
    HcFree(deviceInfo);
}

TrustedGroupEntry *CreateGroupEntryStruct(void)
{
    TrustedGroupEntry *ptr = (TrustedGroupEntry *)HcMalloc(sizeof(TrustedGroupEntry), 0);
    if (ptr == NULL) {
        LOGE("[DB]: Failed to allocate groupEntry memory!");
        return NULL;
    }
    ptr->name = CreateString();
    ptr->id = CreateString();
    ptr->userIdHash = CreateString();
    ptr->sharedUserIdHashVec = CREATE_HC_VECTOR(StringVector);
    ptr->managers = CREATE_HC_VECTOR(StringVector);
    ptr->friends = CREATE_HC_VECTOR(StringVector);
    return ptr;
}

void DestroyGroupEntryStruct(TrustedGroupEntry *groupEntry)
{
    DeleteString(&groupEntry->name);
    DeleteString(&groupEntry->id);
    DeleteString(&groupEntry->userIdHash);
    DestroyStrVector(&groupEntry->managers);
    DestroyStrVector(&groupEntry->friends);
    DestroyStrVector(&groupEntry->sharedUserIdHashVec);
}

void DestroyDeviceEntryStruct(TrustedDeviceEntry *deviceEntry)
{
    DeleteString(&deviceEntry->udid);
    DeleteString(&deviceEntry->authId);
    DeleteString(&deviceEntry->serviceType);
    DeleteString(&deviceEntry->userIdHash);
    DeleteParcel(&deviceEntry->ext);
}

int32_t GenerateGroupInfoByEntry(const TrustedGroupEntry *groupEntry, const char *groupId,
    const char *sharedUserIdHash, GroupInfo *returnGroupInfo)
{
    if ((groupEntry == NULL) || (returnGroupInfo == NULL)) {
        LOGE("[DB]: The input parameters contains NULL value!");
        return HC_ERR_NULL_PTR;
    }
    int32_t result = GenerateGroupInfoCommonByEntry(groupEntry, returnGroupInfo);
    if (result != HC_SUCCESS) {
        return result;
    }
    if (groupEntry->type != ACROSS_ACCOUNT_AUTHORIZE_GROUP) {
        return GenerateGroupInfoIdAndName(StringGet(&groupEntry->id), StringGet(&groupEntry->name), returnGroupInfo);
    }
    if (groupId != NULL) {
        return GenerateAcrossAccountGroupInfoById(groupEntry, groupId, returnGroupInfo);
    } else if (sharedUserIdHash != NULL) {
        return GenerateAcrossAccountGroupInfoByUserIdHash(groupEntry, sharedUserIdHash, returnGroupInfo);
    } else {
        return HC_ERR_INVALID_PARAMS;
    }
}

int32_t GenerateDeviceInfoByEntry(const TrustedDeviceEntry *deviceEntry, const char *groupId,
    DeviceInfo *returnDeviceInfo)
{
    int32_t result = GenerateDeviceInfoCommonByEntry(deviceEntry, returnDeviceInfo);
    if (result != HC_SUCCESS) {
        return result;
    }
    if (groupId != NULL) {
        return GenerateDeviceInfoId(groupId, returnDeviceInfo);
    }
    if (deviceEntry->groupEntry->type != ACROSS_ACCOUNT_AUTHORIZE_GROUP) {
        return GenerateDeviceInfoId(StringGet(&deviceEntry->groupEntry->id), returnDeviceInfo);
    }
    return GenerateDeviceInfoId(StringGet(&deviceEntry->serviceType), returnDeviceInfo);
}

int32_t GetSharedUserIdFromVecByGroupId(const TrustedGroupEntry *groupEntry, const char *groupId,
    const char **returnUserIdHash)
{
    if ((groupEntry == NULL) || (groupId == NULL) || (returnUserIdHash == NULL)) {
        LOGE("[DB]: The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    if ((groupEntry->type != ACROSS_ACCOUNT_AUTHORIZE_GROUP) || (g_generateIdFunc == NULL)) {
        return HC_ERR_NOT_SUPPORT;
    }
    if (strcmp(groupId, "") == 0) {
        return HC_ERR_INVALID_PARAMS;
    }
    const char *userIdHash = StringGet(&groupEntry->userIdHash);
    if (userIdHash == NULL) {
        LOGE("[DB]: Failed to get userIdHash from groupEntry!");
        return HC_ERR_NULL_PTR;
    }
    /* The groupId of the across account group needs to be generated temporarily due to device resource problems. */
    uint32_t index;
    HcString *sharedUserIdHash = NULL;
    FOR_EACH_HC_VECTOR(groupEntry->sharedUserIdHashVec, index, sharedUserIdHash) {
        const char *sharedUserIdHashPtr = StringGet(sharedUserIdHash);
        if (sharedUserIdHashPtr == NULL) {
            LOGW("[DB]: Failed to get sharedUserIdHash from sharedUserIdHashVec!");
            continue;
        }
        char *tmpGroupId = NULL;
        int32_t result = g_generateIdFunc(userIdHash, sharedUserIdHashPtr, &tmpGroupId);
        if (result != HC_SUCCESS) {
            LOGE("[DB]: Failed to generate temp groupId!");
            return result;
        }
        bool isEquals = (strcmp(tmpGroupId, groupId) == 0) ? true : false;
        HcFree(tmpGroupId);
        if (isEquals) {
            *returnUserIdHash = sharedUserIdHashPtr;
            return HC_SUCCESS;
        }
    }
    return HC_ERR_GROUP_NOT_EXIST;
}

void AddNewSharedUserId(const StringVector *sharedUserIdHashList, TrustedGroupEntry *entry, CJson *groupIdList)
{
    if ((sharedUserIdHashList == NULL) || (entry == NULL) || (groupIdList == NULL)) {
        LOGE("[DB]: The input parameters contains NULL value!");
        return;
    }
    HcString *sharedUserIdHash = NULL;
    uint32_t sharedUserIdIndex = 0;
    while (sharedUserIdIndex < sharedUserIdHashList->size(sharedUserIdHashList)) {
        sharedUserIdHash = sharedUserIdHashList->getp(sharedUserIdHashList, sharedUserIdIndex);
        sharedUserIdIndex++;
        const char *sharedUserIdHashPtr = StringGet(sharedUserIdHash);
        if (sharedUserIdHashPtr == NULL) {
            continue;
        }
        bool isNeedAdd = true;
        uint32_t tmpIndex;
        HcString *tmpSharedUserIdHash = NULL;
        FOR_EACH_HC_VECTOR(entry->sharedUserIdHashVec, tmpIndex, tmpSharedUserIdHash) {
            const char *tmpSharedUserIdHashPtr = StringGet(tmpSharedUserIdHash);
            if ((tmpSharedUserIdHashPtr != NULL) && (strcmp(sharedUserIdHashPtr, tmpSharedUserIdHashPtr) == 0)) {
                isNeedAdd = false;
                break;
            }
        }
        if (!isNeedAdd) {
            continue;
        }
        HcString newSharedUserIdHash = CreateString();
        if (!StringSet(&newSharedUserIdHash, *sharedUserIdHash)) {
            LOGE("Failed to copy sharedUserIdHash!");
            DeleteString(&newSharedUserIdHash);
            continue;
        }
        HC_VECTOR_PUSHBACK(&entry->sharedUserIdHashVec, &newSharedUserIdHash);
        NotifyGroupCreated(entry, StringGet(&newSharedUserIdHash));
        if (groupIdList != NULL) {
            (void)AddGroupIdToList(StringGet(&entry->userIdHash), StringGet(&newSharedUserIdHash), groupIdList);
        }
        LOGI("[DB]: Add a across account group to database successfully!");
    }
}

void DeleteExpiredSharedUserId(const StringVector *sharedUserIdHashList, TrustedGroupEntry *entry)
{
    if ((sharedUserIdHashList == NULL) || (entry == NULL)) {
        LOGE("[DB]: The input parameters contains NULL value!");
        return;
    }
    HcString *sharedUserIdHash = NULL;
    uint32_t sharedUserIdIndex = 0;
    while (sharedUserIdIndex < entry->sharedUserIdHashVec.size(&entry->sharedUserIdHashVec)) {
        sharedUserIdHash = entry->sharedUserIdHashVec.getp(&entry->sharedUserIdHashVec, sharedUserIdIndex);
        const char *sharedUserIdHashPtr = StringGet(sharedUserIdHash);
        if (sharedUserIdHash == NULL) {
            sharedUserIdIndex++;
            continue;
        }
        bool isNeedRemove = true;
        uint32_t tmpIndex;
        HcString *tmpSharedUserIdHash = NULL;
        FOR_EACH_HC_VECTOR(*sharedUserIdHashList, tmpIndex, tmpSharedUserIdHash) {
            const char *tmpSharedUserIdHashPtr = StringGet(tmpSharedUserIdHash);
            if ((tmpSharedUserIdHashPtr != NULL) && (strcmp(sharedUserIdHashPtr, tmpSharedUserIdHashPtr) == 0)) {
                isNeedRemove = false;
                break;
            }
        }
        if (!isNeedRemove) {
            sharedUserIdIndex++;
            continue;
        }
        HcString popSharedUserIdHash;
        HC_VECTOR_POPELEMENT(&entry->sharedUserIdHashVec, &popSharedUserIdHash, sharedUserIdIndex);
        NotifyGroupDeleted(entry, StringGet(&popSharedUserIdHash));
        DeleteString(&popSharedUserIdHash);
        LOGI("[DB]: Delete a across account group from database successfully!");
    }
}

bool CompareGroupTypeInGroupEntryOrAll(const TrustedGroupEntry *groupEntry, int32_t groupType)
{
    if (groupType == ALL_GROUP) {
        return true;
    } else {
        return (groupType == groupEntry->type);
    }
}

bool CompareDevIdInDeviceEntryOrNull(const TrustedDeviceEntry *deviceEntry, const char *devId, bool isUdid)
{
    if (devId == NULL) {
        return true;
    } else {
        const char *entryDevId = isUdid ? StringGet(&deviceEntry->udid) : StringGet(&deviceEntry->authId);
        if (entryDevId == NULL) {
            return false;
        }
        return (strcmp(entryDevId, devId) == 0);
    }
}

bool CompareGroupIdInDeviceEntryOrNull(const TrustedDeviceEntry *deviceEntry, const char *groupId)
{
    if (groupId == NULL) {
        return true;
    } else {
        const char *tmpGroupId = (deviceEntry->groupEntry->type != ACROSS_ACCOUNT_AUTHORIZE_GROUP) ?
                                 (StringGet(&deviceEntry->groupEntry->id)) : (StringGet(&deviceEntry->serviceType));
        if (tmpGroupId == NULL) {
            return false;
        }
        /* Check whether the device is the local device entry in the across account group. */
        if (strcmp(tmpGroupId, "") != 0) {
            return (strcmp(tmpGroupId, groupId) == 0);
        }
        const char *sharedUserIdHash = NULL;
        if (GetSharedUserIdFromVecByGroupId(deviceEntry->groupEntry, groupId, &sharedUserIdHash) == HC_SUCCESS) {
            return true;
        } else {
            return false;
        }
    }
}

bool CompareSearchParams(int32_t groupType, const char *groupId, const char *groupName, const char *groupOwner,
    const TrustedGroupEntry *entry)
{
    if ((groupType != ALL_GROUP) && (entry->type != groupType)) {
        return false;
    }
    if ((groupId != NULL) && (!IsGroupIdEquals(entry, groupId))) {
        return false;
    }
    if ((groupName != NULL) && (!IsGroupNameEquals(entry, groupName))) {
        return false;
    }
    if (HC_VECTOR_SIZE(&(entry->managers)) == 0) {
        LOGE("[DB]: The group owner is lost!");
        return false;
    }
    if (groupOwner != NULL) {
        HcString entryOwnerStr = HC_VECTOR_GET(&(entry->managers), 0);
        const char *entryOwner = StringGet(&entryOwnerStr);
        if ((entryOwner == NULL) || (strcmp(entryOwner, groupOwner) != 0)) {
            return false;
        }
    }
    return true;
}

bool IsGroupIdEquals(const TrustedGroupEntry *groupEntry, const char *groupId)
{
    if ((groupEntry == NULL) || (groupId == NULL)) {
        return false;
    }
    if (groupEntry->type != ACROSS_ACCOUNT_AUTHORIZE_GROUP) {
        const char *entryGroupId = StringGet(&groupEntry->id);
        if ((entryGroupId != NULL) && (strcmp(entryGroupId, groupId) == 0)) {
            return true;
        }
        return false;
    }
    const char *sharedUserIdHash = NULL;
    if (GetSharedUserIdFromVecByGroupId(groupEntry, groupId, &sharedUserIdHash) == HC_SUCCESS) {
        return true;
    }
    return false;
}

bool IsGroupNameEquals(const TrustedGroupEntry *groupEntry, const char *groupName)
{
    if ((groupEntry == NULL) || (groupName == NULL)) {
        return false;
    }
    if (groupEntry->type != ACROSS_ACCOUNT_AUTHORIZE_GROUP) {
        const char *entryGroupName = StringGet(&groupEntry->name);
        if ((entryGroupName != NULL) && (strcmp(entryGroupName, groupName) == 0)) {
            return true;
        }
        return false;
    }
    const char *sharedUserIdHash = NULL;
    if (GetSharedUserIdFromVecByGroupId(groupEntry, groupName, &sharedUserIdHash) == HC_SUCCESS) {
        return true;
    }
    return false;
}

bool IsGroupManager(const char *appId, const TrustedGroupEntry *entry)
{
    uint32_t index;
    HcString *manager = NULL;
    FOR_EACH_HC_VECTOR(entry->managers, index, manager) {
        if (strcmp(StringGet(manager), appId) == 0) {
            return true;
        }
    }
    return false;
}

bool IsGroupFriend(const char *appId, const TrustedGroupEntry *entry)
{
    uint32_t index;
    HcString *trustedFriend = NULL;
    FOR_EACH_HC_VECTOR(entry->friends, index, trustedFriend) {
        if (strcmp(StringGet(trustedFriend), appId) == 0) {
            return true;
        }
    }
    return false;
}

bool SetGroupElement(TlvGroupElement *element, TrustedGroupEntry **entry)
{
    if (!StringSet(&element->name.data, (*entry)->name)) {
        return false;
    }
    if (!StringSet(&element->id.data, (*entry)->id)) {
        return false;
    }
    if (!StringSet(&element->userIdHash.data, (*entry)->userIdHash)) {
        return false;
    }
    element->type.data = (*entry)->type;
    element->visibility.data = (*entry)->visibility;
    element->expireTime.data = (*entry)->expireTime;
    if (!SaveStringVectorToParcel(&(*entry)->managers, &element->managers.data)) {
        return false;
    }
    if (!SaveStringVectorToParcel(&(*entry)->friends, &element->friends.data)) {
        return false;
    }
    if (!SaveStringVectorToParcel(&(*entry)->sharedUserIdHashVec, &element->sharedUserIdHashVec.data)) {
        return false;
    }
    return true;
}

bool SetDeviceElement(TlvDevAuthElement *element, TrustedDeviceEntry *entry)
{
    if (!StringSet(&element->groupId.data, entry->groupEntry->id)) {
        return false;
    }
    if (!StringSet(&element->udid.data, entry->udid)) {
        return false;
    }
    if (!StringSet(&element->authId.data, entry->authId)) {
        return false;
    }
    if (!StringSet(&element->serviceType.data, entry->serviceType)) {
        return false;
    }
    if (!StringSet(&element->userIdHash.data, entry->userIdHash)) {
        return false;
    }
    if (!ParcelCopy(&element->ext.data, &entry->ext)) {
        return false;
    }
    element->info.data.credential = entry->credential;
    element->info.data.devType = entry->devType;
    element->info.data.lastTm = entry->lastTm;
    return true;
}

bool SatisfyType(int32_t type, int32_t standardType)
{
    return ((standardType == ALL_GROUP) || (type == standardType));
}

bool SatisfyVisibility(int32_t visibility, int32_t standardVisibility)
{
    return ((standardVisibility == ALL_GROUP_VISIBILITY) || (visibility == standardVisibility));
}

void RegGenerateGroupIdFunc(GenGroupIdFunc func)
{
    if (func == NULL) {
        LOGE("[DB]: The input func is NULL!");
        return;
    }
    g_generateIdFunc = func;
}

void DeregGenerateGroupIdFunc(void)
{
    g_generateIdFunc = NULL;
}

void NotifyGroupCreated(const TrustedGroupEntry *groupEntry, const char *sharedUserIdHash)
{
    if (!IsBroadcastSupported()) {
        return;
    }
    if ((groupEntry == NULL) || (sharedUserIdHash == NULL)) {
        return;
    }
    Broadcaster *broadcaster = GetBroadcaster();
    if ((broadcaster == NULL) || (broadcaster->postOnGroupCreated == NULL)) {
        LOGE("[DB]: Failed to get broadcaster!");
        return;
    }
    GroupInfo *groupInfo = CreateGroupInfoStruct();
    if (groupInfo == NULL) {
        LOGE("[DB]: Failed to allocate groupInfo memory!");
        return;
    }
    if (GenerateGroupInfoByEntry(groupEntry, NULL, sharedUserIdHash, groupInfo) != HC_SUCCESS) {
        DestroyGroupInfoStruct(groupInfo);
        return;
    }
    broadcaster->postOnGroupCreated(groupInfo);
    DestroyGroupInfoStruct(groupInfo);
}

void NotifyGroupDeleted(const TrustedGroupEntry *groupEntry, const char *sharedUserIdHash)
{
    if (!IsBroadcastSupported()) {
        return;
    }
    if ((groupEntry == NULL) || (sharedUserIdHash == NULL)) {
        return;
    }
    Broadcaster *broadcaster = GetBroadcaster();
    if ((broadcaster == NULL) || (broadcaster->postOnGroupDeleted == NULL)) {
        LOGE("[DB]: Failed to get broadcaster!");
        return;
    }
    GroupInfo *groupInfo = CreateGroupInfoStruct();
    if (groupInfo == NULL) {
        LOGE("[DB]: Failed to allocate groupInfo memory!");
        return;
    }
    if (GenerateGroupInfoByEntry(groupEntry, NULL, sharedUserIdHash, groupInfo) != HC_SUCCESS) {
        DestroyGroupInfoStruct(groupInfo);
        return;
    }
    broadcaster->postOnGroupDeleted(groupInfo);
    DestroyGroupInfoStruct(groupInfo);
}

void NotifyDeviceBound(const TrustedDeviceEntry *deviceEntry)
{
    if (!IsBroadcastSupported()) {
        return;
    }
    if (deviceEntry == NULL) {
        return;
    }
    Broadcaster *broadcaster = GetBroadcaster();
    if ((broadcaster == NULL) || (broadcaster->postOnDeviceBound == NULL)) {
        LOGE("[DB]: Failed to get broadcaster!");
        return;
    }
    GroupInfo *groupInfo = CreateGroupInfoStruct();
    if (groupInfo == NULL) {
        LOGE("[DB]: Failed to allocate groupInfo memory!");
        return;
    }
    if (GenerateGroupInfoByDevEntry(deviceEntry, groupInfo) != HC_SUCCESS) {
        DestroyGroupInfoStruct(groupInfo);
        return;
    }
    broadcaster->postOnDeviceBound(StringGet(&deviceEntry->udid), groupInfo);
    DestroyGroupInfoStruct(groupInfo);
}

void NotifyDeviceUnBound(const TrustedDeviceEntry *deviceEntry)
{
    if (!IsBroadcastSupported()) {
        return;
    }
    if (deviceEntry == NULL) {
        return;
    }
    Broadcaster *broadcaster = GetBroadcaster();
    if ((broadcaster == NULL) || (broadcaster->postOnDeviceUnBound == NULL)) {
        LOGE("[DB]: Failed to get broadcaster!");
        return;
    }
    GroupInfo *groupInfo = CreateGroupInfoStruct();
    if (groupInfo == NULL) {
        LOGE("[DB]: Failed to allocate groupInfo memory!");
        return;
    }
    if (GenerateGroupInfoByDevEntry(deviceEntry, groupInfo) != HC_SUCCESS) {
        DestroyGroupInfoStruct(groupInfo);
        return;
    }
    broadcaster->postOnDeviceUnBound(StringGet(&deviceEntry->udid), groupInfo);
    DestroyGroupInfoStruct(groupInfo);
}

void NotifyDeviceNotTrusted(const char *peerUdid)
{
    if (!IsBroadcastSupported()) {
        return;
    }
    if (peerUdid == NULL) {
        return;
    }
    Broadcaster *broadcaster = GetBroadcaster();
    if ((broadcaster == NULL) || (broadcaster->postOnDeviceNotTrusted == NULL)) {
        LOGE("[DB]: Failed to get broadcaster!");
        return;
    }
    broadcaster->postOnDeviceNotTrusted(peerUdid);
}

void NotifyLastGroupDeleted(const char *peerUdid, int groupType)
{
    if (!IsBroadcastSupported()) {
        return;
    }
    if (peerUdid == NULL) {
        return;
    }
    Broadcaster *broadcaster = GetBroadcaster();
    if ((broadcaster == NULL) || (broadcaster->postOnLastGroupDeleted == NULL)) {
        LOGE("[DB]: Failed to get broadcaster!");
        return;
    }
    broadcaster->postOnLastGroupDeleted(peerUdid, groupType);
}

void NotifyTrustedDeviceNumChanged(int trustedDeviceNum)
{
    if (!IsBroadcastSupported()) {
        return;
    }
    Broadcaster *broadcaster = GetBroadcaster();
    if ((broadcaster == NULL) || (broadcaster->postOnTrustedDeviceNumChanged == NULL)) {
        LOGE("[DB]: Failed to get broadcaster!");
        return;
    }
    broadcaster->postOnTrustedDeviceNumChanged(trustedDeviceNum);
}