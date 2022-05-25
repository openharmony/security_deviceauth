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

#include "processData_fuzzer.h"

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

    bool FuzzDoProcessData(const uint8_t* data, size_t size)
    {
        const GroupAuthManager *gaInstance = GetGaInstance();
        if (gaInstance == nullptr) {
            return false;
        }
        if (data == nullptr) {
            return false;
        }
        if (size <= sizeof(int64_t)) {
            return false;
        }
        const int64_t *authReqId = reinterpret_cast<const int64_t *>(data);
        DeviceAuthCallback gaCallback;
        gaCallback.onError = OnError;
        gaCallback.onFinish = OnFinish;
        gaCallback.onSessionKeyReturned = OnSessionKeyReturned;
        gaCallback.onTransmit = onTransmit;
        gaCallback.onRequest = onRequest;
        gaInstance->processData(*authReqId, data + sizeof(int64_t), (uint32_t)(size - sizeof(int64_t)), &gaCallback);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoProcessData(data, size);
    return 0;
}

