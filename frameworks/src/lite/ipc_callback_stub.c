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

#include "ipc_callback_stub.h"
#include "common_defs.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "ipc_adapt.h"
#include "ipc_iface.h"
#include "ipc_skeleton.h"
#include "securec.h"

#ifdef __cplusplus
extern "C" {
#endif

static void DoCallBack(int32_t callbackId, uintptr_t cbHook, IpcIo *data, IpcIo *reply)
{
    int32_t ret;
    int32_t i;
    IpcDataInfo cbDataCache[MAX_REQUEST_PARAMS_NUM] = { { 0 } };

    if (cbHook == 0x0) {
        LOGE("Invalid call back hook");
        return;
    }

    uint32_t len = 0;
    ReadUint32(data, &len); /* skip flat object length information */
    for (i = 0; i < MAX_REQUEST_PARAMS_NUM; i++) {
        ret = DecodeIpcData((uintptr_t)(data), &(cbDataCache[i].type),
            &(cbDataCache[i].val), &(cbDataCache[i].valSz));
        if (ret != HC_SUCCESS) {
            LOGE("decode failed, ret %d", ret);
            return;
        }
    }
    ProcCbHook(callbackId, cbHook, cbDataCache, MAX_REQUEST_PARAMS_NUM, (uintptr_t)(reply));
    return;
}

int32_t CbStubOnRemoteRequest(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    int32_t callbackId;
    uintptr_t cbHook = 0x0;

    LOGI("enter invoking callback...");
    if (data == NULL) {
        LOGE("invalid param");
        return -1;
    }

    LOGI("receive ipc transact code(%u)", code);
    switch (code) {
        case DEV_AUTH_CALLBACK_REQUEST:
            ReadInt32(data, &callbackId);
            cbHook = ReadPointer(data);
            DoCallBack(callbackId, cbHook, data, reply);
            break;
        default:
            LOGE("Invoke callback cmd code(%u) error", code);
            break;
    }
    LOGI("Invoke callback done, result(%d)", HC_SUCCESS);
    return HC_SUCCESS;
}

#ifdef __cplusplus
}
#endif
