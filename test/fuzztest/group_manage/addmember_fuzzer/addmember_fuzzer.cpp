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

#include "addmember_fuzzer.h"

namespace OHOS {
    bool FuzzDoAddMemberToGroup(const uint8_t* data, size_t size)
    {
        const DeviceGroupManager *gmInstance = GetGmInstance();
        if (gmInstance == nullptr) {
            return false;
        }
        if (data == nullptr) {
            return false;
        }
        if (size <= sizeof(int32_t) + sizeof(int64_t)) {
            return false;
        }
        const int32_t *osAccountId = reinterpret_cast<const int32_t *>(data);
        const int64_t *requestId = reinterpret_cast<const int64_t *>(data + sizeof(int32_t));
        const char *appId = reinterpret_cast<const char *>(data + sizeof(int32_t) + sizeof(int64_t));
        const char *addParams = reinterpret_cast<const char *>(data + sizeof(int32_t) + sizeof(int64_t));
        gmInstance->addMemberToGroup(*osAccountId, *requestId, appId, addParams);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoAddMemberToGroup(data, size);
    return 0;
}

