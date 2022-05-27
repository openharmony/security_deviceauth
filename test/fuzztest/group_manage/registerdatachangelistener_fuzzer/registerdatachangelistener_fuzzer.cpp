/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "registerdatachangelistener_fuzzer.h"

namespace OHOS {
    void onGroupCreated(const char *groupInfo) {}

    void onGroupDeleted(const char *groupInfo) {}

    void onDeviceBound(const char *peerUdid, const char *groupInfo) {}

    void onDeviceUnBound(const char *peerUdid, const char *groupInfo) {}

    void onDeviceNotTrusted(const char *peerUdid) {}

    void onLastGroupDeleted(const char *peerUdid, int groupType) {}

    void onTrustedDeviceNumChanged(int curTrustedDeviceNum) {}

    bool FuzzDoRegDataChangeListener(const uint8_t* data, size_t size)
    {
        const DeviceGroupManager *gmInstance = GetGmInstance();
        if (gmInstance == nullptr) {
            return false;
        }
        if (data == nullptr) {
            return false;
        }
        const char *appId = reinterpret_cast<const char *>(data);
        DataChangeListener listener;
        listener.onGroupCreated = onGroupCreated;
        listener.onGroupDeleted = onGroupDeleted;
        listener.onDeviceBound = onDeviceBound;
        listener.onDeviceUnBound = onDeviceUnBound;
        listener.onDeviceNotTrusted = onDeviceNotTrusted;
        listener.onLastGroupDeleted = onLastGroupDeleted;
        listener.onTrustedDeviceNumChanged = onTrustedDeviceNumChanged;
        gmInstance->regDataChangeListener(appId, &listener);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoRegDataChangeListener(data, size);
    return 0;
}

