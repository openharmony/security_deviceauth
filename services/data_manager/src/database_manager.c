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

#include "database_manager.h"

#include "database_util.h"
#include "device_auth.h"
#include "hc_dev_info.h"
#include "hc_file.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "hc_types.h"
#include "securec.h"

DEFINE_TLV_FIX_LENGTH_TYPE(TlvDevAuthFixedLenInfo, NO_REVERT)

BEGIN_TLV_STRUCT_DEFINE(TlvGroupElement, 0x0001)
    TLV_MEMBER(TlvString, name, 0x4001)
    TLV_MEMBER(TlvString, id, 0x4002)
    TLV_MEMBER(TlvUint32, type, 0x4003)
    TLV_MEMBER(TlvInt32, visibility, 0x4004)
    TLV_MEMBER(TlvInt32, expireTime, 0x4005)
    TLV_MEMBER(TlvString, userIdHash, 0x4006)
    TLV_MEMBER(TlvBuffer, sharedUserIdHashVec, 0x4007)
    TLV_MEMBER(TlvBuffer, managers, 0x4008)
    TLV_MEMBER(TlvBuffer, friends, 0x4009)
END_TLV_STRUCT_DEFINE()
IMPLEMENT_TLV_VECTOR(TlvGroupVec, TlvGroupElement, 1)

BEGIN_TLV_STRUCT_DEFINE(TlvDevAuthElement, 0x0002)
    TLV_MEMBER(TlvString, groupId, 0x4101)
    TLV_MEMBER(TlvString, udid, 0x4102)
    TLV_MEMBER(TlvString, authId, 0x4103)
    TLV_MEMBER(TlvString, userIdHash, 0x4107)
    TLV_MEMBER(TlvString, serviceType, 0x4104)
    TLV_MEMBER(TlvBuffer, ext, 0x4105)
    TLV_MEMBER(TlvDevAuthFixedLenInfo, info, 0x4106)
END_TLV_STRUCT_DEFINE()
IMPLEMENT_TLV_VECTOR(TlvDevAuthVec, TlvDevAuthElement, 2)

BEGIN_TLV_STRUCT_DEFINE(HCDataBaseV1, 0x0001)
    TLV_MEMBER(TlvInt32, version, 0x6001)
    TLV_MEMBER(TlvGroupVec, groups, 0x6002)
    TLV_MEMBER(TlvDevAuthVec, devices, 0x6003)
END_TLV_STRUCT_DEFINE()

IMPLEMENT_HC_VECTOR(TrustedGroupTable, TrustedGroupEntry *, 1)
IMPLEMENT_HC_VECTOR(TrustedDeviceTable, TrustedDeviceEntry, 2)
IMPLEMENT_HC_VECTOR(GroupInfoVec, void *, 1)
IMPLEMENT_HC_VECTOR(DeviceInfoVec, void *, 2)

static HcMutex *g_databaseMutex = NULL;
static char g_localUdid[INPUT_UDID_LEN] = { 0 };
static TrustedGroupTable g_trustedGroupTable;
static TrustedDeviceTable g_trustedDeviceTable;

static void DestroyGroupTable(void)
{
    uint32_t groupIndex;
    TrustedGroupEntry **entry = NULL;
    FOR_EACH_HC_VECTOR(g_trustedGroupTable, groupIndex, entry) {
        DestroyGroupEntryStruct(*entry);
        HcFree(*entry);
    }
    DESTROY_HC_VECTOR(TrustedGroupTable, &g_trustedGroupTable);
}

static void DestroyTrustDeviceTable(void)
{
    uint32_t devIndex;
    TrustedDeviceEntry *deviceEntry = NULL;
    FOR_EACH_HC_VECTOR(g_trustedDeviceTable, devIndex, deviceEntry) {
        DestroyDeviceEntryStruct(deviceEntry);
    }
    DESTROY_HC_VECTOR(TrustedDeviceTable, &g_trustedDeviceTable);
}

static TrustedGroupEntry *GetGroupEntryById(const char *groupId)
{
    uint32_t groupIndex;
    TrustedGroupEntry **entry = NULL;
    FOR_EACH_HC_VECTOR(g_trustedGroupTable, groupIndex, entry) {
        if ((entry != NULL) && (*entry != NULL) && (IsGroupIdEquals(*entry, groupId))) {
            return *entry;
        }
    }
    return NULL;
}

static TrustedDeviceEntry *GetTrustedDeviceEntryById(const char *deviceId, bool isUdid, const char *groupId)
{
    uint32_t index;
    TrustedDeviceEntry *deviceEntry = NULL;
    FOR_EACH_HC_VECTOR(g_trustedDeviceTable, index, deviceEntry) {
        if (CompareDevIdInDeviceEntryOrNull(deviceEntry, deviceId, isUdid)) {
            if (CompareGroupIdInDeviceEntryOrNull(deviceEntry, groupId)) {
                return deviceEntry;
            }
        }
    }
    return NULL;
}

static bool HasDevEntryInSuchTypeGroup(const char *udid, int32_t groupType)
{
    uint32_t devIndex;
    TrustedDeviceEntry *deviceEntry = NULL;
    FOR_EACH_HC_VECTOR(g_trustedDeviceTable, devIndex, deviceEntry) {
        if ((deviceEntry != NULL) && (deviceEntry->groupEntry != NULL)) {
            if (CompareDevIdInDeviceEntryOrNull(deviceEntry, udid, true) &&
                CompareGroupTypeInGroupEntryOrAll(deviceEntry->groupEntry, groupType)) {
                return true;
            }
        }
    }
    return false;
}

/*
 * Currently, this interface does not return the actual number of trusted devices.
 * If at least one trusted device exists, return 1. Otherwise, return 0.
 */
static int GetTrustedDeviceNum(void)
{
    return (g_trustedDeviceTable.size(&g_trustedDeviceTable) > 0) ? 1 : 0;
}

static bool GenerateGroupEntryFromTlv(TrustedGroupEntry *entry, TlvGroupElement *group)
{
    entry->name = CreateString();
    entry->id = CreateString();
    entry->userIdHash = CreateString();
    entry->managers = CreateStrVector();
    entry->friends = CreateStrVector();
    entry->sharedUserIdHashVec = CreateStrVector();
    if (!LoadStringVectorFromParcel(&entry->managers, &group->managers.data)) {
        return false;
    }
    if (!LoadStringVectorFromParcel(&entry->friends, &group->friends.data)) {
        return false;
    }
    if (!LoadStringVectorFromParcel(&entry->sharedUserIdHashVec, &group->sharedUserIdHashVec.data)) {
        return false;
    }
    if (!StringSet(&entry->name, group->name.data)) {
        return false;
    }
    if (!StringSet(&entry->id, group->id.data)) {
        return false;
    }
    if (!StringSet(&entry->userIdHash, group->userIdHash.data)) {
        return false;
    }
    entry->type = group->type.data;
    entry->visibility = group->visibility.data;
    entry->expireTime = group->expireTime.data;
    return true;
}

static bool LoadGroupDb(HCDataBaseV1 *db)
{
    uint32_t index;
    TlvGroupElement *group = NULL;
    FOR_EACH_HC_VECTOR(db->groups.data, index, group) {
        TrustedGroupEntry *entry = HcMalloc(sizeof(TrustedGroupEntry), 0);
        if (entry == NULL) {
            return false;
        }
        if (!GenerateGroupEntryFromTlv(entry, group)) {
            DestroyGroupEntryStruct(entry);
            HcFree(entry);
            return false;
        }
        if (g_trustedGroupTable.pushBack(&g_trustedGroupTable, (const TrustedGroupEntry **)&entry) == NULL) {
            DestroyGroupEntryStruct(entry);
            HcFree(entry);
            return false;
        }
    }
    return true;
}

static bool GenerateDeviceEntryFromTlv(TrustedDeviceEntry *deviceEntry, TlvDevAuthElement *devAuth)
{
    deviceEntry->udid = CreateString();
    deviceEntry->authId = CreateString();
    deviceEntry->serviceType = CreateString();
    deviceEntry->userIdHash = CreateString();
    deviceEntry->ext = CreateParcel(0, 0);
    const char *groupId = StringGet(&devAuth->groupId.data);
    if (groupId == NULL) {
        LOGE("[DB]: Failed to get groupId from devAuth!");
        return false;
    }
    deviceEntry->groupEntry = GetGroupEntryById(groupId);
    if (deviceEntry->groupEntry == NULL) {
        LOGE("[DB]: Failed to find groupEntry by groupId!");
        return false;
    }
    if (!StringSet(&deviceEntry->udid, devAuth->udid.data)) {
        return false;
    }
    if (!StringSet(&deviceEntry->authId, devAuth->authId.data)) {
        return false;
    }
    if (!StringSet(&deviceEntry->serviceType, devAuth->serviceType.data)) {
        return false;
    }
    if (!StringSet(&deviceEntry->userIdHash, devAuth->userIdHash.data)) {
        return false;
    }
    if (!ParcelCopy(&devAuth->ext.data, &deviceEntry->ext)) {
        return false;
    }
    deviceEntry->credential = devAuth->info.data.credential;
    deviceEntry->devType = devAuth->info.data.devType;
    deviceEntry->lastTm = devAuth->info.data.lastTm;
    return true;
}

static bool LoadDeviceDb(HCDataBaseV1 *db)
{
    uint32_t index;
    TlvDevAuthElement *devAuth = NULL;
    FOR_EACH_HC_VECTOR(db->devices.data, index, devAuth) {
        TrustedDeviceEntry authInfo;
        if (!GenerateDeviceEntryFromTlv(&authInfo, devAuth)) {
            DestroyDeviceEntryStruct(&authInfo);
            return false;
        }
        if (g_trustedDeviceTable.pushBack(&g_trustedDeviceTable, &authInfo) == NULL) {
            DestroyDeviceEntryStruct(&authInfo);
            return false;
        }
    }
    return true;
}

static bool LoadDbFromParcel(HcParcel *parcelIn)
{
    bool ret = false;
    HCDataBaseV1 dbv1;
    TLV_INIT(HCDataBaseV1, &dbv1);
    if (DecodeTlvMessage((TlvBase *)&dbv1, parcelIn, false)) {
        if (!LoadGroupDb(&dbv1)) {
            TLV_DEINIT(dbv1);
            return false;
        }
        if (!LoadDeviceDb(&dbv1)) {
            TLV_DEINIT(dbv1);
            return false;
        }
        ret = true;
    } else {
        LOGE("[DB]: Decode Tlv Message Failed!");
    }
    TLV_DEINIT(dbv1);
    return ret;
}

static bool SaveGroupDb(HCDataBaseV1 *db)
{
    uint32_t index;
    TrustedGroupEntry **entry;
    FOR_EACH_HC_VECTOR(g_trustedGroupTable, index, entry) {
        TlvGroupElement tmp;
        TlvGroupElement *element = db->groups.data.pushBack(&db->groups.data, &tmp);
        if (element == NULL) {
            return false;
        }
        TLV_INIT(TlvGroupElement, element);
        if (!SetGroupElement(element, entry)) {
            TLV_DEINIT((*element));
            return false;
        }
    }
    return true;
}

static bool SaveDeviceDb(HCDataBaseV1 *db)
{
    uint32_t index;
    TrustedDeviceEntry *entry = NULL;
    FOR_EACH_HC_VECTOR(g_trustedDeviceTable, index, entry) {
        TlvDevAuthElement tmp;
        TlvDevAuthElement *element = db->devices.data.pushBack(&db->devices.data, &tmp);
        if (element == NULL) {
            return false;
        }
        TLV_INIT(TlvDevAuthElement, element);
        if (!SetDeviceElement(element, entry)) {
            TLV_DEINIT((*element));
            return false;
        }
    }
    return true;
}

static bool SaveDBToParcel(HcParcel *parcelOut)
{
    int ret;
    HCDataBaseV1 dbv1;
    TLV_INIT(HCDataBaseV1, &dbv1);
    dbv1.version.data = 1;
    do {
        if (!SaveGroupDb(&dbv1)) {
            ret = false;
            break;
        }
        if (!SaveDeviceDb(&dbv1)) {
            ret = false;
            break;
        }
        if (!EncodeTlvMessage((TlvBase *)&dbv1, parcelOut)) {
            LOGE("[DB]: Encode Tlv Message failed!");
            ret = false;
            break;
        }
        ret = true;
    } while (0);
    TLV_DEINIT(dbv1);
    return ret;
}

static bool LoadDb(void)
{
    FileHandle file;
    int ret = HcFileOpen(FILE_ID_GROUP, MODE_FILE_READ, &file);
    if (ret != 0) {
        return false;
    }
    int fileSize = HcFileSize(file);
    if (fileSize <= 0) {
        HcFileClose(file);
        return false;
    }
    char *fileData = (char *)HcMalloc(fileSize, 0);
    if (fileData == NULL) {
        HcFileClose(file);
        return false;
    }
    if (HcFileRead(file, fileData, fileSize) != fileSize) {
        HcFileClose(file);
        HcFree(fileData);
        return false;
    }
    HcFileClose(file);
    HcParcel parcel = CreateParcel(0, 0);
    if (!ParcelWrite(&parcel, fileData, fileSize)) {
        HcFree(fileData);
        DeleteParcel(&parcel);
        return false;
    }
    ret = LoadDbFromParcel(&parcel);
    HcFree(fileData);
    DeleteParcel(&parcel);
    return ret;
}

static bool SaveDB(void)
{
    HcParcel parcel = CreateParcel(0, 0);
    if (!SaveDBToParcel(&parcel)) {
        DeleteParcel(&parcel);
        return false;
    }
    FileHandle file;
    int ret = HcFileOpen(FILE_ID_GROUP, MODE_FILE_WRITE, &file);
    if (ret != 0) {
        DeleteParcel(&parcel);
        return false;
    }
    int fileSize = (int)GetParcelDataSize(&parcel);
    const char *fileData = GetParcelData(&parcel);
    if (HcFileWrite(file, fileData, fileSize) == fileSize) {
        ret = true;
    } else {
        ret = false;
    }
    DeleteParcel(&parcel);
    HcFileClose(file);
    return ret;
}

static void CheckAndNotifyAfterDelDevice(const TrustedDeviceEntry *deviceEntry)
{
    const char *udid = StringGet(&deviceEntry->udid);
    if (udid == NULL) {
        return;
    }
    NotifyDeviceUnBound(deviceEntry);
    if (!HasDevEntryInSuchTypeGroup(udid, deviceEntry->groupEntry->type)) {
        NotifyLastGroupDeleted(udid, deviceEntry->groupEntry->type);
    }
    if (GetTrustedDeviceEntryById(udid, true, NULL) == NULL) {
        NotifyDeviceNotTrusted(udid);
        NotifyTrustedDeviceNumChanged(GetTrustedDeviceNum());
    }
}

static int32_t GenerateGroupEntryByInfo(const GroupInfo *groupInfo, TrustedGroupEntry *entry)
{
    if (!StringSet(&entry->name, groupInfo->name)) {
        LOGE("[DB]: Failed to copy groupName!");
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSet(&entry->id, groupInfo->id)) {
        LOGE("[DB]: Failed to copy groupId!");
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSet(&entry->userIdHash, groupInfo->userIdHash)) {
        LOGE("[DB]: Failed to copy userIdHash!");
        return HC_ERR_MEMORY_COPY;
    }
    entry->type = groupInfo->type;
    entry->visibility = groupInfo->visibility;
    entry->expireTime = groupInfo->expireTime;
    HcString ownerName = CreateString();
    if (!StringSet(&ownerName, groupInfo->ownerName)) {
        LOGE("[DB]: Failed to copy groupOwner!");
        DeleteString(&ownerName);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (entry->managers.pushBack(&entry->managers, &ownerName) == NULL) {
        LOGE("[DB]: Failed to push groupOwner to managers!");
        DeleteString(&ownerName);
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t GenerateDeviceEntryByInfo(const DeviceInfo *deviceInfo, const Uint8Buff *ext,
    TrustedDeviceEntry *deviceEntry)
{
    deviceEntry->udid = CreateString();
    deviceEntry->authId = CreateString();
    deviceEntry->serviceType = CreateString();
    deviceEntry->userIdHash = CreateString();
    /* reserved field */
    deviceEntry->ext = CreateParcel(0, 0);
    const char *groupId = StringGet(&deviceInfo->groupId);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from from deviceInfo!");
        return HC_ERR_NULL_PTR;
    }
    deviceEntry->groupEntry = GetGroupEntryById(groupId);
    if (deviceEntry->groupEntry == NULL) {
        LOGE("[DB]: The group corresponding to groupId cannot be found!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    if (!StringSet(&deviceEntry->udid, deviceInfo->udid)) {
        LOGE("[DB]: Failed to copy udid!");
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSet(&deviceEntry->authId, deviceInfo->authId)) {
        LOGE("[DB]: Failed to copy authId!");
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSet(&deviceEntry->serviceType, deviceInfo->serviceType)) {
        LOGE("[DB]: Failed to copy serviceType!");
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSet(&deviceEntry->userIdHash, deviceInfo->userIdHash)) {
        LOGE("[DB]: Failed to copy userIdHash!");
        return HC_ERR_MEMORY_COPY;
    }
    deviceEntry->credential = deviceInfo->credential;
    deviceEntry->devType = deviceInfo->devType;
    deviceEntry->lastTm = 0;
    if (ext != NULL && ext->val != NULL) {
        if (!ParcelWrite(&deviceEntry->ext, ext->val, ext->length)) {
            LOGE("[DB]: Failed to copy extern data!");
            return HC_ERR_MEMORY_COPY;
        }
    }
    return HC_SUCCESS;
}

static bool IsSatisfyGroup(const TrustedGroupEntry *entry, const GroupQueryParams *params)
{
    return (SatisfyType(entry->type, params->type) && SatisfyVisibility(entry->visibility, params->visibility));
}

static bool IsSatisfyUdidAndAuthId(const TrustedDeviceEntry *deviceEntry, const GroupQueryParams *params)
{
    if (params->udid != NULL) {
        const char *udid = StringGet(&deviceEntry->udid);
        if ((udid == NULL) || (strcmp(udid, params->udid) != 0)) {
            return false;
        }
    }
    if (params->authId != NULL) {
        const char *authId = StringGet(&deviceEntry->authId);
        if ((authId == NULL) || (strcmp(authId, params->authId) != 0)) {
            return false;
        }
    }
    return true;
}

static int32_t GetGroupInfoIfDevExistInner(const char *groupId, const char *udid, GroupInfo *returnGroupInfo)
{
    uint32_t index;
    TrustedGroupEntry **entry = NULL;
    FOR_EACH_HC_VECTOR(g_trustedGroupTable, index, entry) {
        if ((entry == NULL) || (*entry == NULL)) {
            continue;
        }
        if (IsGroupIdEquals(*entry, groupId)) {
            if ((udid != NULL) && (GetTrustedDeviceEntryById(udid, true, groupId) == NULL)) {
                LOGE("[DB]: The trusted device does not exist in the group!");
                return HC_ERR_DEVICE_NOT_EXIST;
            } else {
                return GenerateGroupInfoByEntry(*entry, groupId, NULL, returnGroupInfo);
            }
        }
    }
    LOGE("[DB]: The group does not exist!");
    return HC_ERR_GROUP_NOT_EXIST;
}

static void DelDeviceEntryByGroupId(const char *groupId)
{
    uint32_t devIndex = 0;
    TrustedDeviceEntry *deviceEntry = NULL;
    while (devIndex < g_trustedDeviceTable.size(&g_trustedDeviceTable)) {
        deviceEntry = g_trustedDeviceTable.getp(&g_trustedDeviceTable, devIndex);
        if ((deviceEntry == NULL) || (deviceEntry->groupEntry == NULL)) {
            devIndex++;
            continue;
        }
        const char *entryGroupId = StringGet(&deviceEntry->groupEntry->id);
        if ((entryGroupId == NULL) || (strcmp(entryGroupId, groupId) != 0)) {
            devIndex++;
            continue;
        }
        TrustedDeviceEntry tmpDeviceEntry;
        HC_VECTOR_POPELEMENT(&g_trustedDeviceTable, &tmpDeviceEntry, devIndex);
        CheckAndNotifyAfterDelDevice(&tmpDeviceEntry);
        DestroyDeviceEntryStruct(&tmpDeviceEntry);
    }
}

static void DelGroupEntryByGroupId(const char *groupId)
{
    TrustedGroupEntry **groupEntry = NULL;
    uint32_t groupIndex = 0;
    while (groupIndex < g_trustedGroupTable.size(&g_trustedGroupTable)) {
        groupEntry = g_trustedGroupTable.getp(&g_trustedGroupTable, groupIndex);
        if ((groupEntry == NULL) || (*groupEntry == NULL) || (!IsGroupIdEquals(*groupEntry, groupId))) {
            groupIndex++;
            continue;
        }
        TrustedGroupEntry *tmpEntry = NULL;
        HC_VECTOR_POPELEMENT(&g_trustedGroupTable, &tmpEntry, groupIndex);
        if (tmpEntry->type != ACROSS_ACCOUNT_AUTHORIZE_GROUP) {
            NotifyGroupDeleted(tmpEntry, NULL);
        } else {
            const char *sharedUserIdHash = NULL;
            if (GetSharedUserIdFromVecByGroupId(tmpEntry, groupId, &sharedUserIdHash) == HC_SUCCESS) {
                NotifyGroupDeleted(tmpEntry, sharedUserIdHash);
            }
        }
        DestroyGroupEntryStruct(tmpEntry);
        HcFree(tmpEntry);
        LOGI("[DB]: Delete a group from database successfully!");
        return;
    }
    LOGI("[DB]: The group does not exist!");
}

static void DeleteUserIdExpiredDeviceEntry(const char *curUserIdHash)
{
    uint32_t devIndex = 0;
    TrustedDeviceEntry *deviceEntry = NULL;
    while (devIndex < g_trustedDeviceTable.size(&g_trustedDeviceTable)) {
        deviceEntry = g_trustedDeviceTable.getp(&g_trustedDeviceTable, devIndex);
        if ((deviceEntry == NULL) || (deviceEntry->groupEntry == NULL)) {
            devIndex++;
            continue;
        }
        if (deviceEntry->groupEntry->type != ACROSS_ACCOUNT_AUTHORIZE_GROUP) {
            devIndex++;
            continue;
        }
        const char *userIdHash = StringGet(&deviceEntry->groupEntry->userIdHash);
        if ((userIdHash == NULL) || (strcmp(userIdHash, curUserIdHash) == 0)) {
            devIndex++;
            continue;
        }
        TrustedDeviceEntry tmpDeviceEntry;
        HC_VECTOR_POPELEMENT(&g_trustedDeviceTable, &tmpDeviceEntry, devIndex);
        CheckAndNotifyAfterDelDevice(&tmpDeviceEntry);
        DestroyDeviceEntryStruct(&tmpDeviceEntry);
    }
}

static void DeleteUserIdExpiredGroupEntry(const char *curUserIdHash)
{
    TrustedGroupEntry **groupEntry = NULL;
    uint32_t groupIndex = 0;
    while (groupIndex < g_trustedGroupTable.size(&g_trustedGroupTable)) {
        groupEntry = g_trustedGroupTable.getp(&g_trustedGroupTable, groupIndex);
        if ((groupEntry == NULL) || (*groupEntry == NULL)) {
            groupIndex++;
            continue;
        }
        if ((*groupEntry)->type != ACROSS_ACCOUNT_AUTHORIZE_GROUP) {
            groupIndex++;
            continue;
        }
        const char *userIdHash = StringGet(&(*groupEntry)->userIdHash);
        if ((userIdHash == NULL) || (strcmp(userIdHash, curUserIdHash) == 0)) {
            groupIndex++;
            continue;
        }
        TrustedGroupEntry *tmpEntry = NULL;
        HC_VECTOR_POPELEMENT(&g_trustedGroupTable, &tmpEntry, groupIndex);
        uint32_t tmpIndex;
        HcString *sharedUserIdHash = NULL;
        FOR_EACH_HC_VECTOR(tmpEntry->sharedUserIdHashVec, tmpIndex, sharedUserIdHash) {
            NotifyGroupDeleted(tmpEntry, StringGet(sharedUserIdHash));
        }
        DestroyGroupEntryStruct(tmpEntry);
        HcFree(tmpEntry);
    }
}

static void DeleteAccountDeviceEntry(void)
{
    uint32_t devIndex = 0;
    TrustedDeviceEntry *deviceEntry = NULL;
    while (devIndex < g_trustedDeviceTable.size(&g_trustedDeviceTable)) {
        deviceEntry = g_trustedDeviceTable.getp(&g_trustedDeviceTable, devIndex);
        if (deviceEntry == NULL) {
            devIndex++;
            continue;
        }
        if ((deviceEntry->groupEntry->type != IDENTICAL_ACCOUNT_GROUP) &&
            (deviceEntry->groupEntry->type != ACROSS_ACCOUNT_AUTHORIZE_GROUP)) {
            devIndex++;
            continue;
        }
        TrustedDeviceEntry tmpDeviceEntry;
        HC_VECTOR_POPELEMENT(&g_trustedDeviceTable, &tmpDeviceEntry, devIndex);
        CheckAndNotifyAfterDelDevice(&tmpDeviceEntry);
        DestroyDeviceEntryStruct(&tmpDeviceEntry);
    }
}

static void DeleteAccountGroupEntry(void)
{
    TrustedGroupEntry **groupEntry = NULL;
    uint32_t groupIndex = 0;
    while (groupIndex < g_trustedGroupTable.size(&g_trustedGroupTable)) {
        groupEntry = g_trustedGroupTable.getp(&g_trustedGroupTable, groupIndex);
        if ((groupEntry == NULL) || (*groupEntry == NULL)) {
            groupIndex++;
            continue;
        }
        if (((*groupEntry)->type != IDENTICAL_ACCOUNT_GROUP) &&
            ((*groupEntry)->type != ACROSS_ACCOUNT_AUTHORIZE_GROUP)) {
            groupIndex++;
            continue;
        }
        TrustedGroupEntry *tmpEntry = NULL;
        HC_VECTOR_POPELEMENT(&g_trustedGroupTable, &tmpEntry, groupIndex);
        if (tmpEntry->type == IDENTICAL_ACCOUNT_GROUP) {
            NotifyGroupDeleted(tmpEntry, NULL);
        } else {
            uint32_t tmpIndex;
            HcString *sharedUserIdHash = NULL;
            FOR_EACH_HC_VECTOR(tmpEntry->sharedUserIdHashVec, tmpIndex, sharedUserIdHash) {
                NotifyGroupDeleted(tmpEntry, StringGet(sharedUserIdHash));
            }
        }
        DestroyGroupEntryStruct(tmpEntry);
        HcFree(tmpEntry);
    }
}

static int32_t PushAcrossAccountGroupsToVec(const TrustedGroupEntry *entry, GroupInfoVec *groupInfoVec)
{
    uint32_t index;
    HcString *tmpSharedUserIdHash = NULL;
    FOR_EACH_HC_VECTOR(entry->sharedUserIdHashVec, index, tmpSharedUserIdHash) {
        const char *tmpSharedUserIdHashPtr = StringGet(tmpSharedUserIdHash);
        if (tmpSharedUserIdHashPtr == NULL) {
            LOGE("[DB]: Failed to get sharedUserIdHash from sharedUserIdHashVec!");
            return HC_ERR_LOST_DATA;
        }
        GroupInfo *groupInfo = CreateGroupInfoStruct();
        if (groupInfo == NULL) {
            LOGE("[DB]: Failed to allocate groupInfo memory!");
            return HC_ERR_ALLOC_MEMORY;
        }
        int32_t result = GenerateGroupInfoByEntry(entry, NULL, tmpSharedUserIdHashPtr, groupInfo);
        if (result != HC_SUCCESS) {
            DestroyGroupInfoStruct(groupInfo);
            return result;
        }
        if (groupInfoVec->pushBackT(groupInfoVec, groupInfo) == NULL) {
            LOGE("[DB]: Failed to push groupInfo to groupInfoVec!");
            DestroyGroupInfoStruct(groupInfo);
            return HC_ERR_MEMORY_COPY;
        }
    }
    return HC_SUCCESS;
}

static int32_t PushGroupInfoToVec(const TrustedGroupEntry *entry, const char *groupId,
    const char *sharedUserIdHash, GroupInfoVec *groupInfoVec)
{
    int32_t result;
    if ((entry->type == ACROSS_ACCOUNT_AUTHORIZE_GROUP) && (groupId == NULL) && (sharedUserIdHash == NULL)) {
        return PushAcrossAccountGroupsToVec(entry, groupInfoVec);
    }
    GroupInfo *groupInfo = CreateGroupInfoStruct();
    if (groupInfo == NULL) {
        LOGE("[DB]: Failed to allocate groupInfo memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    result = GenerateGroupInfoByEntry(entry, groupId, sharedUserIdHash, groupInfo);
    if (result != HC_SUCCESS) {
        DestroyGroupInfoStruct(groupInfo);
        return result;
    }
    if (groupInfoVec->pushBackT(groupInfoVec, groupInfo) == NULL) {
        LOGE("[DB]: Failed to push groupInfo to groupInfoVec!");
        DestroyGroupInfoStruct(groupInfo);
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t PushDevInfoToVec(const TrustedDeviceEntry *entry, const char *groupId, DeviceInfoVec *deviceInfoVec)
{
    DeviceInfo *deviceInfo = CreateDeviceInfoStruct();
    if (deviceInfo == NULL) {
        LOGE("[DB]: Failed to allocate deviceInfo memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t result = GenerateDeviceInfoByEntry(entry, groupId, deviceInfo);
    if (result != HC_SUCCESS) {
        DestroyDeviceInfoStruct(deviceInfo);
        return result;
    }
    if (deviceInfoVec->pushBackT(deviceInfoVec, deviceInfo) == NULL) {
        LOGE("[DB]: Failed to push deviceInfo to deviceInfoVec!");
        DestroyDeviceInfoStruct(deviceInfo);
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t AddGroup(const GroupInfo *groupInfo)
{
    LOGI("[DB]: Start to add a group to database!");
    if (groupInfo == NULL) {
        LOGE("[DB]: The input groupInfo is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    const char *groupId = StringGet(&groupInfo->id);
    if (groupId == NULL) {
        LOGE("[DB]: Failed to get groupId from groupInfo!");
        return HC_ERR_NULL_PTR;
    }
    g_databaseMutex->lock(g_databaseMutex);
    if (GetGroupEntryById(groupId) != NULL) {
        LOGE("[DB]: The group corresponding to the groupId already exists!");
        g_databaseMutex->unlock(g_databaseMutex);
        return HC_ERR_GROUP_DUPLICATE;
    }
    TrustedGroupEntry *entry = CreateGroupEntryStruct();
    if (entry == NULL) {
        LOGE("[DB]: Failed to allocate groupEntry memory!");
        g_databaseMutex->unlock(g_databaseMutex);
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t result = GenerateGroupEntryByInfo(groupInfo, entry);
    if (result != HC_SUCCESS) {
        DestroyGroupEntryStruct(entry);
        HcFree(entry);
        g_databaseMutex->unlock(g_databaseMutex);
        return result;
    }
    if (g_trustedGroupTable.pushBack(&g_trustedGroupTable, (const TrustedGroupEntry **)&entry) == NULL) {
        LOGE("[DB]: Failed to push groupEntry to groupTable!");
        DestroyGroupEntryStruct(entry);
        HcFree(entry);
        g_databaseMutex->unlock(g_databaseMutex);
        return HC_ERR_MEMORY_COPY;
    }
    if (!SaveDB()) {
        LOGE("[DB]: Failed to save database!");
        g_databaseMutex->unlock(g_databaseMutex);
        return HC_ERR_SAVE_DB_FAILED;
    }
    if (entry->type != ACROSS_ACCOUNT_AUTHORIZE_GROUP) {
        NotifyGroupCreated(entry, NULL);
    }
    LOGI("[DB]: Add a group to database successfully! [GroupType]: %d", groupInfo->type);
    g_databaseMutex->unlock(g_databaseMutex);
    return HC_SUCCESS;
}

int32_t DelGroupByGroupId(const char *groupId)
{
    LOGI("[DB]: Start to delete a group from database!");
    if (groupId == NULL) {
        LOGE("[DB]: The input groupId is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (strcmp(groupId, "") == 0) {
        LOGE("[DB]: The input groupId is empty string!");
        return HC_ERR_INVALID_PARAMS;
    }
    g_databaseMutex->lock(g_databaseMutex);
    DelDeviceEntryByGroupId(groupId);
    DelGroupEntryByGroupId(groupId);
    if (!SaveDB()) {
        LOGE("[DB]: Failed to save database!");
        g_databaseMutex->unlock(g_databaseMutex);
        return HC_ERR_SAVE_DB_FAILED;
    }
    g_databaseMutex->unlock(g_databaseMutex);
    return HC_SUCCESS;
}

int32_t AddTrustedDevice(const DeviceInfo *deviceInfo, const Uint8Buff *ext)
{
    LOGI("[DB]: Start to add a trusted device to database!");
    if (deviceInfo == NULL) {
        LOGE("[DB]: The input deviceInfo is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    const char *udid = StringGet(&(deviceInfo->udid));
    const char *groupId = StringGet(&(deviceInfo->groupId));
    if ((udid == NULL) || (groupId == NULL)) {
        LOGE("[DB]: The input udid or groupId is NULL!");
        return HC_ERR_NULL_PTR;
    }
    bool isTrustedDeviceNumChanged = false;
    g_databaseMutex->lock(g_databaseMutex);
    if (GetTrustedDeviceEntryById(udid, true, NULL) == NULL) {
        isTrustedDeviceNumChanged = true;
    }
    if (GetTrustedDeviceEntryById(udid, true, groupId) != NULL) {
        LOGE("[DB]: The device already exists in the group!");
        g_databaseMutex->unlock(g_databaseMutex);
        return HC_ERR_DEVICE_DUPLICATE;
    }
    TrustedDeviceEntry deviceEntry;
    int32_t result = GenerateDeviceEntryByInfo(deviceInfo, ext, &deviceEntry);
    if (result != HC_SUCCESS) {
        DestroyDeviceEntryStruct(&deviceEntry);
        g_databaseMutex->unlock(g_databaseMutex);
        return result;
    }
    if (g_trustedDeviceTable.pushBack(&g_trustedDeviceTable, &deviceEntry) == NULL) {
        LOGE("[DB]: Failed to push deviceEntry to deviceTable!");
        DestroyDeviceEntryStruct(&deviceEntry);
        g_databaseMutex->unlock(g_databaseMutex);
        return HC_ERR_MEMORY_COPY;
    }
    if (!SaveDB()) {
        LOGE("[DB]: Failed to save database!");
        g_databaseMutex->unlock(g_databaseMutex);
        return HC_ERR_SAVE_DB_FAILED;
    }
    if (isTrustedDeviceNumChanged) {
        NotifyTrustedDeviceNumChanged(GetTrustedDeviceNum());
    }
    NotifyDeviceBound(&deviceEntry);
    g_databaseMutex->unlock(g_databaseMutex);
    LOGI("[DB]: Add a trusted device to database successfully!");
    return HC_SUCCESS;
}

int32_t DelTrustedDevice(const char *deviceId, bool isUdid, const char *groupId)
{
    LOGI("[DB]: Start to delete a trusted device from database!");
    if ((deviceId == NULL) || (groupId == NULL)) {
        LOGE("[DB]: The input udid or groupId is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    uint32_t devIndex;
    TrustedDeviceEntry *deviceEntry = NULL;
    g_databaseMutex->lock(g_databaseMutex);
    FOR_EACH_HC_VECTOR(g_trustedDeviceTable, devIndex, deviceEntry) {
        if ((deviceEntry == NULL) || (deviceEntry->groupEntry == NULL)) {
            continue;
        }
        const char *entryDevId = isUdid ? StringGet(&deviceEntry->udid) : StringGet(&deviceEntry->authId);
        if ((entryDevId != NULL) && (strcmp(entryDevId, deviceId) == 0) &&
            (CompareGroupIdInDeviceEntryOrNull(deviceEntry, groupId))) {
            TrustedDeviceEntry tmpDeviceEntry;
            HC_VECTOR_POPELEMENT(&g_trustedDeviceTable, &tmpDeviceEntry, devIndex);
            if (!SaveDB()) {
                DestroyDeviceEntryStruct(&tmpDeviceEntry);
                LOGE("[DB]: Failed to save database!");
                g_databaseMutex->unlock(g_databaseMutex);
                return HC_ERR_SAVE_DB_FAILED;
            }
            CheckAndNotifyAfterDelDevice(&tmpDeviceEntry);
            DestroyDeviceEntryStruct(&tmpDeviceEntry);
            LOGI("[DB]: Delete a trusted device from database successfully!");
            g_databaseMutex->unlock(g_databaseMutex);
            return HC_SUCCESS;
        }
    }
    LOGE("[DB]: The trusted device is not found!");
    g_databaseMutex->unlock(g_databaseMutex);
    return HC_ERR_DEVICE_NOT_EXIST;
}

int32_t AddGroupRole(const char *groupId, GroupRole roleType, const char *appId)
{
    if ((groupId == NULL) || (appId == NULL)) {
        LOGE("[DB]: The input groupId or appId is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGI("[DB]: Start to add a role to the group! [AppId]: %s, [Role]: %d", appId, roleType);
    g_databaseMutex->lock(g_databaseMutex);
    TrustedGroupEntry *groupEntry = GetGroupEntryById(groupId);
    if (groupEntry == NULL) {
        LOGE("[DB]: The group does not exist!");
        g_databaseMutex->unlock(g_databaseMutex);
        return HC_ERR_GROUP_NOT_EXIST;
    }
    HcString roleStr = CreateString();
    if (!StringSetPointer(&roleStr, appId)) {
        LOGE("[DB]: Failed to copy roleStr!");
        DeleteString(&roleStr);
        g_databaseMutex->unlock(g_databaseMutex);
        return HC_ERR_MEMORY_COPY;
    }
    bool isOk = false;
    if (roleType == GROUP_MANAGER) {
        isOk = (groupEntry->managers.pushBackT(&groupEntry->managers, roleStr) == NULL) ? true : false;
    } else if (roleType == GROUP_FRIEND) {
        isOk = (groupEntry->friends.pushBackT(&groupEntry->friends, roleStr) == NULL) ? true : false;
    }
    if (!isOk) {
        LOGE("[DB]: Failed to copy roleStr!");
        DeleteString(&roleStr);
        g_databaseMutex->unlock(g_databaseMutex);
        return HC_ERR_MEMORY_COPY;
    }
    if (!SaveDB()) {
        LOGE("[DB]: Failed to save database!");
        g_databaseMutex->unlock(g_databaseMutex);
        return HC_ERR_SAVE_DB_FAILED;
    }
    LOGI("[DB]: Add a role to the group successfully!");
    g_databaseMutex->unlock(g_databaseMutex);
    return HC_SUCCESS;
}

int32_t RemoveGroupRole(const char *groupId, GroupRole roleType, const char *appId)
{
    if ((groupId == NULL) || (appId == NULL)) {
        LOGE("[DB]: The input groupId or appId is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGI("[DB]: Start to delete a role from the group! [AppId]: %s, [Role]: %d", appId, roleType);
    g_databaseMutex->lock(g_databaseMutex);
    TrustedGroupEntry *groupEntry = GetGroupEntryById(groupId);
    if (groupEntry == NULL) {
        LOGE("[DB]: The group does not exist!");
        g_databaseMutex->unlock(g_databaseMutex);
        return HC_ERR_GROUP_NOT_EXIST;
    }
    StringVector roleVec = (roleType == GROUP_MANAGER) ? groupEntry->managers : groupEntry->friends;
    HcString *roleEntry = NULL;
    uint32_t roleIndex;
    FOR_EACH_HC_VECTOR(roleVec, roleIndex, roleEntry) {
        if ((roleEntry == NULL) || ((roleType == GROUP_MANAGER) && (roleIndex == 0))) {
            continue;
        }
        const char *roleStr = StringGet(roleEntry);
        if ((roleStr == NULL) || (strcmp(roleStr, appId) != 0)) {
            continue;
        }
        HcString tmpRole;
        HC_VECTOR_POPELEMENT(&(roleVec), &tmpRole, roleIndex);
        DeleteString(&tmpRole);
        if (!SaveDB()) {
            LOGE("[DB]: Failed to save database!");
            g_databaseMutex->unlock(g_databaseMutex);
            return HC_ERR_SAVE_DB_FAILED;
        }
        LOGI("[DB]: Delete a role from the group successfully!");
        g_databaseMutex->unlock(g_databaseMutex);
        return HC_SUCCESS;
    }
    LOGE("[DB]: The role does not exist in the group!");
    g_databaseMutex->unlock(g_databaseMutex);
    return HC_ERR_ROLE_NOT_EXIST;
}

int32_t GetGroupRoles(const char *groupId, GroupRole roleType, CJson *returnRoles)
{
    if ((groupId == NULL) || (returnRoles == NULL)) {
        LOGE("[DB]: The input groupId or returnRoles is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGI("[DB]: Start to get roles from the group! [Role]: %d", roleType);
    g_databaseMutex->lock(g_databaseMutex);
    TrustedGroupEntry *groupEntry = GetGroupEntryById(groupId);
    if (groupEntry == NULL) {
        LOGE("[DB]: The group does not exist!");
        g_databaseMutex->unlock(g_databaseMutex);
        return HC_ERR_GROUP_NOT_EXIST;
    }
    StringVector roleVec = (roleType == GROUP_MANAGER) ? groupEntry->managers : groupEntry->friends;
    HcString *roleEntry = NULL;
    uint32_t roleIndex;
    FOR_EACH_HC_VECTOR(roleVec, roleIndex, roleEntry) {
        if (AddStringToArray(returnRoles, StringGet(roleEntry)) != HC_SUCCESS) {
            LOGD("[DB]: Failed to add role to returnRoles!");
        }
    }
    LOGI("[DB]: Get group roles from the group successfully!");
    g_databaseMutex->unlock(g_databaseMutex);
    return HC_SUCCESS;
}

int32_t CompareVisibility(const char *groupId, int groupVisibility)
{
    if (groupId == NULL) {
        LOGE("[DB]: The input groupId is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    g_databaseMutex->lock(g_databaseMutex);
    TrustedGroupEntry *groupEntry = GetGroupEntryById(groupId);
    if (groupEntry == NULL) {
        LOGE("[DB]: The group does not exist!");
        g_databaseMutex->unlock(g_databaseMutex);
        return HC_ERR_GROUP_NOT_EXIST;
    }
    int32_t result = (((uint32_t)(groupEntry->visibility) & (uint32_t)groupVisibility) == 0) ? HC_ERROR : HC_SUCCESS;
    g_databaseMutex->unlock(g_databaseMutex);
    return result;
}

bool IsTrustedDeviceExist(const char *udid)
{
    if (udid == NULL) {
        LOGE("[DB]: The input udid is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    g_databaseMutex->lock(g_databaseMutex);
    bool isExists = (GetTrustedDeviceEntryById(udid, true, NULL) != NULL) ? true : false;
    g_databaseMutex->unlock(g_databaseMutex);
    return isExists;
}

int32_t GetTrustedDevNumber(void)
{
    g_databaseMutex->lock(g_databaseMutex);
    int num = GetTrustedDeviceNum();
    g_databaseMutex->unlock(g_databaseMutex);
    return num;
}

int32_t DeleteUserIdExpiredGroups(const char *curUserIdHash)
{
    if (curUserIdHash == NULL) {
        LOGE("[DB]: The input curUserIdHash is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGI("[DB]: Start to delete all across account groups with expired userId!");
    g_databaseMutex->lock(g_databaseMutex);
    DeleteUserIdExpiredDeviceEntry(curUserIdHash);
    DeleteUserIdExpiredGroupEntry(curUserIdHash);
    if (!SaveDB()) {
        g_databaseMutex->unlock(g_databaseMutex);
        LOGE("[DB]: Failed to save database!");
        return HC_ERR_SAVE_DB_FAILED;
    }
    g_databaseMutex->unlock(g_databaseMutex);
    LOGI("[DB]: Delete all across account groups with expired userId successfully!");
    return HC_SUCCESS;
}

int32_t DeleteAllAccountGroup(void)
{
    LOGI("[DB]: Start to delete all account-related groups!");
    g_databaseMutex->lock(g_databaseMutex);
    DeleteAccountDeviceEntry();
    DeleteAccountGroupEntry();
    if (!SaveDB()) {
        g_databaseMutex->unlock(g_databaseMutex);
        LOGE("[DB]: Failed to save database!");
        return HC_ERR_SAVE_DB_FAILED;
    }
    g_databaseMutex->unlock(g_databaseMutex);
    LOGI("[DB]: Delete all account-related groups successfully!");
    return HC_SUCCESS;
}

int32_t OnlyAddSharedUserIdVec(const StringVector *sharedUserIdHashVec, CJson *groupIdList)
{
    if ((sharedUserIdHashVec == NULL) || (groupIdList == NULL)) {
        LOGE("[DB]: The input parameter contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGI("[DB]: Start to add shared userId list!");
    TrustedGroupEntry **entry = NULL;
    uint32_t index;
    g_databaseMutex->lock(g_databaseMutex);
    FOR_EACH_HC_VECTOR(g_trustedGroupTable, index, entry) {
        if ((entry != NULL) && (*entry != NULL) && ((*entry)->type == ACROSS_ACCOUNT_AUTHORIZE_GROUP)) {
            AddNewSharedUserId(sharedUserIdHashVec, *entry, groupIdList);
            LOGI("[DB]: Add new userIds successfully!");
            if (!SaveDB()) {
                g_databaseMutex->unlock(g_databaseMutex);
                LOGE("[DB]: Failed to save database!");
                return HC_ERR_SAVE_DB_FAILED;
            }
            g_databaseMutex->unlock(g_databaseMutex);
            LOGI("[DB]: Only add shared userId list successfully!");
            return HC_SUCCESS;
        }
    }
    g_databaseMutex->unlock(g_databaseMutex);
    LOGE("[DB]: The across account group does not exist!");
    return HC_ERR_GROUP_NOT_EXIST;
}

int32_t ChangeSharedUserIdVec(const StringVector *sharedUserIdHashVec)
{
    if (sharedUserIdHashVec == NULL) {
        LOGE("[DB]: The input sharedUserIdHashVec is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGI("[DB]: Start to change shared userId list!");
    TrustedGroupEntry **entry = NULL;
    uint32_t index;
    g_databaseMutex->lock(g_databaseMutex);
    FOR_EACH_HC_VECTOR(g_trustedGroupTable, index, entry) {
        if ((entry != NULL) && (*entry != NULL) && ((*entry)->type == ACROSS_ACCOUNT_AUTHORIZE_GROUP)) {
            DeleteExpiredSharedUserId(sharedUserIdHashVec, *entry);
            LOGI("[DB]: Delete expired local userIds successfully!");
            AddNewSharedUserId(sharedUserIdHashVec, *entry, NULL);
            LOGI("[DB]: Add new userIds successfully!");
            if (!SaveDB()) {
                g_databaseMutex->unlock(g_databaseMutex);
                LOGE("[DB]: Failed to save database!");
                return HC_ERR_SAVE_DB_FAILED;
            }
            g_databaseMutex->unlock(g_databaseMutex);
            LOGI("[DB]: Change shared userId list successfully!");
            return HC_SUCCESS;
        }
    }
    g_databaseMutex->unlock(g_databaseMutex);
    LOGE("[DB]: The across account group does not exist!");
    return HC_ERR_GROUP_NOT_EXIST;
}

bool IsTrustedDeviceInGroup(const char *groupId, const char *deviceId, bool isUdid)
{
    if ((groupId == NULL) || (deviceId == NULL)) {
        LOGE("[DB]: The input groupId or deviceId is NULL!");
        return false;
    }
    g_databaseMutex->lock(g_databaseMutex);
    bool isExists = (GetTrustedDeviceEntryById(deviceId, isUdid, groupId) != NULL) ? true : false;
    g_databaseMutex->unlock(g_databaseMutex);
    return isExists;
}

bool IsSameNameGroupExist(const char *ownerName, const char *groupName)
{
    if ((ownerName == NULL) || (groupName == NULL)) {
        LOGE("[DB]: The input ownerName or groupName is NULL!");
        return false;
    }
    uint32_t index;
    TrustedGroupEntry **entry = NULL;
    g_databaseMutex->lock(g_databaseMutex);
    FOR_EACH_HC_VECTOR(g_trustedGroupTable, index, entry) {
        if ((entry == NULL) || (*entry == NULL) ||
            (strcmp(StringGet(&(*entry)->name), groupName) != 0)) {
            continue;
        }
        if (HC_VECTOR_SIZE(&(*entry)->managers) > 0) {
            HcString entryOwner = HC_VECTOR_GET(&(*entry)->managers, 0);
            const char *entryOwnerName = StringGet(&entryOwner);
            if ((entryOwnerName != NULL) && (strcmp(entryOwnerName, ownerName) == 0)) {
                g_databaseMutex->unlock(g_databaseMutex);
                return true;
            }
        }
    }
    g_databaseMutex->unlock(g_databaseMutex);
    return false;
}

bool IsIdenticalGroupExist(void)
{
    uint32_t index;
    TrustedGroupEntry **entry = NULL;
    g_databaseMutex->lock(g_databaseMutex);
    FOR_EACH_HC_VECTOR(g_trustedGroupTable, index, entry) {
        if ((entry != NULL) && (*entry != NULL) && ((*entry)->type == IDENTICAL_ACCOUNT_GROUP)) {
            g_databaseMutex->unlock(g_databaseMutex);
            return true;
        }
    }
    g_databaseMutex->unlock(g_databaseMutex);
    return false;
}

bool IsAcrossAccountGroupExist(void)
{
    uint32_t index;
    TrustedGroupEntry **entry = NULL;
    g_databaseMutex->lock(g_databaseMutex);
    FOR_EACH_HC_VECTOR(g_trustedGroupTable, index, entry) {
        if ((entry != NULL) && (*entry != NULL) && ((*entry)->type == ACROSS_ACCOUNT_AUTHORIZE_GROUP)) {
            g_databaseMutex->unlock(g_databaseMutex);
            return true;
        }
    }
    g_databaseMutex->unlock(g_databaseMutex);
    return false;
}

bool IsGroupExistByGroupId(const char *groupId)
{
    if (groupId == NULL) {
        LOGE("[DB]: The input groupId is NULL!");
        return false;
    }
    g_databaseMutex->lock(g_databaseMutex);
    bool isExists = (GetGroupEntryById(groupId) == NULL) ? false : true;
    g_databaseMutex->unlock(g_databaseMutex);
    return isExists;
}

int32_t GetTrustedDevInfoById(const char *deviceId, bool isUdid, const char *groupId, DeviceInfo *deviceInfo)
{
    if ((deviceId == NULL) || (groupId == NULL) || (deviceInfo == NULL)) {
        LOGE("[DB]: The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGI("[DB]: Start to get device information of a specified group!");
    g_databaseMutex->lock(g_databaseMutex);
    TrustedDeviceEntry *deviceEntry = GetTrustedDeviceEntryById(deviceId, isUdid, groupId);
    if (deviceEntry == NULL) {
        LOGE("[DB]: The trusted device is not found!");
        g_databaseMutex->unlock(g_databaseMutex);
        return HC_ERR_DEVICE_NOT_EXIST;
    }
    int32_t result = GenerateDeviceInfoByEntry(deviceEntry, groupId, deviceInfo);
    g_databaseMutex->unlock(g_databaseMutex);
    return result;
}

int32_t GetGroupNumByOwner(const char *ownerName)
{
    if (ownerName == NULL) {
        LOGE("[DB]: The input ownerName is NULL!");
        return 0;
    }
    int count = 0;
    uint32_t index;
    TrustedGroupEntry **entry = NULL;
    g_databaseMutex->lock(g_databaseMutex);
    FOR_EACH_HC_VECTOR(g_trustedGroupTable, index, entry) {
        if ((entry != NULL) && (*entry != NULL) && (HC_VECTOR_SIZE(&(*entry)->managers) > 0)) {
            HcString entryOwner = HC_VECTOR_GET(&(*entry)->managers, 0);
            const char *entryOwnerName = StringGet(&entryOwner);
            if ((entryOwnerName != NULL) && (strcmp(entryOwnerName, ownerName) == 0)) {
                count++;
            }
        }
    }
    g_databaseMutex->unlock(g_databaseMutex);
    return count;
}

int32_t GetCurDeviceNumByGroupId(const char *groupId)
{
    if (groupId == NULL) {
        LOGE("[DB]: The input groupId is NULL!");
        return 0;
    }
    int count = 0;
    uint32_t index;
    TrustedDeviceEntry *deviceEntry = NULL;
    g_databaseMutex->lock(g_databaseMutex);
    FOR_EACH_HC_VECTOR(g_trustedDeviceTable, index, deviceEntry) {
        if ((deviceEntry != NULL) && (CompareGroupIdInDeviceEntryOrNull(deviceEntry, groupId))) {
            count++;
        }
    }
    g_databaseMutex->unlock(g_databaseMutex);
    return count;
}

int32_t GetGroupInfoIfDevExist(const char *groupId, const char *udid, GroupInfo *returnGroupInfo)
{
    if ((groupId == NULL) || (udid == NULL) || (returnGroupInfo == NULL)) {
        LOGE("[DB]: The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    g_databaseMutex->lock(g_databaseMutex);
    int32_t res = GetGroupInfoIfDevExistInner(groupId, udid, returnGroupInfo);
    g_databaseMutex->unlock(g_databaseMutex);
    return res;
}

int32_t GetGroupInfoById(const char *groupId, GroupInfo *returnGroupInfo)
{
    if ((groupId == NULL) || (returnGroupInfo == NULL)) {
        LOGE("[DB]: The input groupId or returnGroupInfo is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    g_databaseMutex->lock(g_databaseMutex);
    int32_t res = GetGroupInfoIfDevExistInner(groupId, NULL, returnGroupInfo);
    g_databaseMutex->unlock(g_databaseMutex);
    return res;
}

void CreateGroupInfoVecStruct(GroupInfoVec *vec)
{
    if (vec == NULL) {
        return;
    }
    *vec = CREATE_HC_VECTOR(GroupInfoVec)
}

void DestroyGroupInfoVecStruct(GroupInfoVec *vec)
{
    uint32_t index;
    void **entry = NULL;
    FOR_EACH_HC_VECTOR(*vec, index, entry) {
        if ((entry != NULL) && (*entry != NULL)) {
            DestroyGroupInfoStruct(*entry);
        }
    }
    DESTROY_HC_VECTOR(GroupInfoVec, vec)
}

void CreateDeviceInfoVecStruct(DeviceInfoVec *vec)
{
    if (vec == NULL) {
        return;
    }
    *vec = CREATE_HC_VECTOR(DeviceInfoVec)
}

void DestroyDeviceInfoVecStruct(DeviceInfoVec *vec)
{
    uint32_t index;
    void **entry = NULL;
    FOR_EACH_HC_VECTOR(*vec, index, entry) {
        if ((entry != NULL) && (*entry != NULL)) {
            DestroyDeviceInfoStruct(*entry);
        }
    }
    DESTROY_HC_VECTOR(DeviceInfoVec, vec)
}

int32_t GetJoinedGroupInfoVecByDevId(const GroupQueryParams *params, GroupInfoVec *vec)
{
    if ((params == NULL) || (vec == NULL)) {
        LOGE("[DB]: The input params or vec is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    if ((params->udid == NULL) && (params->authId == NULL)) {
        LOGE("[DB]: The input udid and authId cannot be NULL at the same time!");
        return HC_ERR_INVALID_PARAMS;
    }
    uint32_t index;
    TrustedDeviceEntry *entry = NULL;
    g_databaseMutex->lock(g_databaseMutex);
    FOR_EACH_HC_VECTOR(g_trustedDeviceTable, index, entry) {
        if ((entry == NULL) ||
            (!IsSatisfyGroup(entry->groupEntry, params)) ||
            (!IsSatisfyUdidAndAuthId(entry, params))) {
            continue;
        }
        int32_t result = PushGroupInfoToVec(entry->groupEntry, StringGet(&entry->serviceType), NULL, vec);
        if (result != HC_SUCCESS) {
            g_databaseMutex->unlock(g_databaseMutex);
            return result;
        }
    }
    if (vec->size(vec) == 0) {
        g_databaseMutex->unlock(g_databaseMutex);
        return HC_ERR_GROUP_NOT_EXIST;
    }
    g_databaseMutex->unlock(g_databaseMutex);
    return HC_SUCCESS;
}

bool IsGroupOwner(const char *groupId, const char *appId)
{
    if ((groupId == NULL) || (appId == NULL)) {
        LOGE("[DB]: The input parameter contains NULL value!");
        return false;
    }
    g_databaseMutex->lock(g_databaseMutex);
    TrustedGroupEntry *entry = GetGroupEntryById(groupId);
    if (entry == NULL) {
        g_databaseMutex->unlock(g_databaseMutex);
        LOGE("[DB]: The group cannot be found!");
        return false;
    }
    if (HC_VECTOR_SIZE(&(entry->managers)) <= 0) {
        g_databaseMutex->unlock(g_databaseMutex);
        LOGE("[DB]: The group does not have manager and owner!");
        return false;
    }
    HcString entryOwner = HC_VECTOR_GET(&(entry->managers), 0);
    bool isOwner = (strcmp(StringGet(&entryOwner), appId) == 0) ? true : false;
    g_databaseMutex->unlock(g_databaseMutex);
    return isOwner;
}

bool IsGroupAccessible(const char *groupId, const char *appId)
{
    if ((groupId == NULL) || (appId == NULL)) {
        LOGE("[DB]: The input groupId or appId is NULL!");
        return false;
    }
    g_databaseMutex->lock(g_databaseMutex);
    TrustedGroupEntry *entry = GetGroupEntryById(groupId);
    if (entry == NULL) {
        g_databaseMutex->unlock(g_databaseMutex);
        LOGE("[DB]: The group cannot be found!");
        return false;
    }
    if ((entry->visibility == GROUP_VISIBILITY_PUBLIC) ||
        (IsGroupManager(appId, entry)) ||
        (IsGroupFriend(appId, entry))) {
        g_databaseMutex->unlock(g_databaseMutex);
        return true;
    }
    g_databaseMutex->unlock(g_databaseMutex);
    return false;
}

bool IsGroupEditAllowed(const char *groupId, const char *appId)
{
    if ((groupId == NULL) || (appId == NULL)) {
        LOGE("[DB]: The input groupId or appId is NULL!");
        return false;
    }
    g_databaseMutex->lock(g_databaseMutex);
    TrustedGroupEntry *entry = GetGroupEntryById(groupId);
    if (entry == NULL) {
        g_databaseMutex->unlock(g_databaseMutex);
        LOGE("[DB]: The group cannot be found!");
        return false;
    }
    bool isManager = IsGroupManager(appId, entry) ? true : false;
    g_databaseMutex->unlock(g_databaseMutex);
    return isManager;
}

const char *GetLocalDevUdid(void)
{
    if (strcmp(g_localUdid, "") == 0) {
        int32_t res = HcGetUdid((uint8_t *)g_localUdid, INPUT_UDID_LEN);
        if (res != HC_SUCCESS) {
            LOGE("[DB]: Failed to get local udid! res: %d", res);
            return NULL;
        }
    }
    return g_localUdid;
}

int32_t GetGroupInfo(int groupType, const char *groupId, const char *groupName, const char *groupOwner,
    GroupInfoVec *groupInfoVec)
{
    /* Fuzzy query interfaces, so some parameters can be NULL. */
    if (groupInfoVec == NULL) {
        LOGE("[DB]: The input groupInfoVec is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t result;
    uint32_t index;
    TrustedGroupEntry **entry = NULL;
    g_databaseMutex->lock(g_databaseMutex);
    FOR_EACH_HC_VECTOR(g_trustedGroupTable, index, entry) {
        if ((entry == NULL) || (*entry == NULL) || (!CompareSearchParams(groupType, groupId, groupName,
            groupOwner, *entry))) {
            continue;
        }
        if (((*entry)->type != ACROSS_ACCOUNT_AUTHORIZE_GROUP) || ((groupId == NULL) && (groupName == NULL))) {
            result = PushGroupInfoToVec(*entry, NULL, NULL, groupInfoVec);
        } else {
            result = PushGroupInfoToVec(*entry, ((groupName != NULL) ? groupName : groupId), NULL, groupInfoVec);
        }
        if (result != HC_SUCCESS) {
            g_databaseMutex->unlock(g_databaseMutex);
            return result;
        }
    }
    g_databaseMutex->unlock(g_databaseMutex);
    return HC_SUCCESS;
}

int32_t GetJoinedGroups(int groupType, GroupInfoVec *groupInfoVec)
{
    int32_t result;
    uint32_t index;
    TrustedGroupEntry **entry = NULL;
    g_databaseMutex->lock(g_databaseMutex);
    FOR_EACH_HC_VECTOR(g_trustedGroupTable, index, entry) {
        if ((entry != NULL) && (*entry != NULL) && ((*entry)->type == groupType)) {
            result = PushGroupInfoToVec(*entry, NULL, NULL, groupInfoVec);
            if (result != HC_SUCCESS) {
                g_databaseMutex->unlock(g_databaseMutex);
                return result;
            }
        }
    }
    g_databaseMutex->unlock(g_databaseMutex);
    return HC_SUCCESS;
}

int32_t GetRelatedGroups(const char *peerDeviceId, bool isUdid, GroupInfoVec *groupInfoVec)
{
    int32_t result;
    uint32_t index;
    TrustedDeviceEntry *entry = NULL;
    g_databaseMutex->lock(g_databaseMutex);
    FOR_EACH_HC_VECTOR(g_trustedDeviceTable, index, entry) {
        if (entry == NULL) {
            continue;
        }
        const char *entryDevId = isUdid ? StringGet(&entry->udid) : StringGet(&entry->authId);
        const char *serviceType = StringGet(&entry->serviceType);
        if ((entryDevId == NULL) || (serviceType == NULL) || (strcmp(entryDevId, peerDeviceId) != 0)) {
            continue;
        }
        if (strcmp(serviceType, "") == 0) {
            result = PushGroupInfoToVec(entry->groupEntry, NULL, NULL, groupInfoVec);
        } else {
            result = PushGroupInfoToVec(entry->groupEntry, serviceType, NULL, groupInfoVec);
        }
        if (result != HC_SUCCESS) {
            g_databaseMutex->unlock(g_databaseMutex);
            return result;
        }
    }
    g_databaseMutex->unlock(g_databaseMutex);
    return HC_SUCCESS;
}

int32_t GetTrustedDevices(const char *groupId, DeviceInfoVec *deviceInfoVec)
{
    int32_t result;
    uint32_t index;
    TrustedDeviceEntry *entry = NULL;
    g_databaseMutex->lock(g_databaseMutex);
    FOR_EACH_HC_VECTOR(g_trustedDeviceTable, index, entry) {
        if ((entry != NULL) && (entry->groupEntry != NULL) && (CompareGroupIdInDeviceEntryOrNull(entry, groupId))) {
            result = PushDevInfoToVec(entry, groupId, deviceInfoVec);
            if (result != HC_SUCCESS) {
                g_databaseMutex->unlock(g_databaseMutex);
                return result;
            }
        }
    }
    g_databaseMutex->unlock(g_databaseMutex);
    return HC_SUCCESS;
}

int32_t InitDatabase(void)
{
    if (g_databaseMutex == NULL) {
        g_databaseMutex = (HcMutex *)HcMalloc(sizeof(HcMutex), 0);
        if (g_databaseMutex == NULL) {
            LOGE("[DB]: Alloc databaseMutex failed");
            return HC_ERR_ALLOC_MEMORY;
        }
        if (InitHcMutex(g_databaseMutex) != HC_SUCCESS) {
            LOGE("[DB]: Init mutex failed");
            HcFree(g_databaseMutex);
            g_databaseMutex = NULL;
            return HC_ERROR;
        }
    }
    g_trustedGroupTable = CREATE_HC_VECTOR(TrustedGroupTable);
    g_trustedDeviceTable = CREATE_HC_VECTOR(TrustedDeviceTable);
    SetFilePath(FILE_ID_GROUP, GetStoragePath());
    if (!LoadDb()) {
        LOGI("[DB]: Failed to load database, it may be the first time the database is read!");
    } else {
        LOGI("[DB]: Load database successfully!");
    }
    return HC_SUCCESS;
}

void DestroyDatabase(void)
{
    g_databaseMutex->lock(g_databaseMutex);
    DestroyTrustDeviceTable();
    DestroyGroupTable();
    g_databaseMutex->unlock(g_databaseMutex);
    if (g_databaseMutex != NULL) {
        DestroyHcMutex(g_databaseMutex);
        HcFree(g_databaseMutex);
        g_databaseMutex = NULL;
    }
}