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

#include "regCallback_fuzzer.h"

namespace OHOS {
    void OnError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn) {}

    void OnFinish(int64_t requestId, int operationCode, const char *authReturn) {}

    void OnSessionKeyReturned(int64_t requestId, const uint8_t *sessionKey, uint32_t sessionKeyLen) {}

    bool onTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
    {
        return true;
    }

    char *onRequest(int64_t requestId, int operationCode, const char* reqParam)
    {
        return nullptr;
    }

    bool FuzzDoRegisterCallback(const uint8_t* data, size_t size)
    {
        const DeviceGroupManager *gmInstance = GetGmInstance();
        if (gmInstance == nullptr) {
            return false;
        }
        if (data == nullptr) {
            return false;
        }
        const char *appId = reinterpret_cast<const char *>(data);
        DeviceAuthCallback callback;
        callback.onError = OnError;
        callback.onFinish = OnFinish;
        callback.onSessionKeyReturned = OnSessionKeyReturned;
        callback.onTransmit = onTransmit;
        callback.onRequest = onRequest;
        gmInstance->regCallback(appId, &callback);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoRegisterCallback(data, size);
    return 0;
}

