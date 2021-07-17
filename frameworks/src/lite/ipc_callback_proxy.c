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

#include "ipc_callback_proxy.h"
#include "hc_log.h"
#include "hc_types.h"
#include "ipc_adapt.h"
#include "liteipc_adapter.h"
#include "securec.h"

#ifdef __cplusplus
extern "C" {
#endif

void CbProxySendRequest(SvcIdentity sid, int32_t callbackId, uintptr_t cbHook, IpcIo *data, IpcIo *reply)
{
    int32_t ret;
    IpcIo *reqData = NULL;
    int32_t dataSz;
    uintptr_t outMsg = 0x0;
    IpcIo replyTmp;
    errno_t eno;

    ShowIpcSvcInfo(&(sid));
    reqData = (IpcIo *)InitIpcDataCache(IPC_DATA_BUFF_MAX_SZ);
    if (reqData == NULL) {
        return;
    }
    IpcIoPushInt32(reqData, callbackId);
    IpcIoPushUintptr(reqData, cbHook);
    dataSz = GetIpcIoDataLength((const IpcIo *)data);
    LOGI("to form callback params data length(%d)", dataSz);
    if (dataSz > 0) {
        IpcIoPushFlatObj(reqData, data->bufferBase + IpcIoBufferOffset(), dataSz);
    }
    if (!IpcIoAvailable(reqData)) {
        LOGE("form send data failed");
        HcFree((void *)reqData);
        return;
    }
    ret = SendRequest(NULL, sid, DEV_AUTH_CALLBACK_REQUEST, reqData, &replyTmp, 0, &outMsg);
    LOGI("SendRequest done, return(%d)", ret);
    if ((ret == 0) && (reply != NULL) && (IpcIoAvailable(&replyTmp))) {
        LOGI("with reply data, length(%zu), flag(%u)", replyTmp.bufferLeft, replyTmp.flag);
        eno = memcpy_s(reply->bufferCur, reply->bufferLeft, replyTmp.bufferCur, replyTmp.bufferLeft);
        if (eno != EOK) {
            reply->flag = 0;
            HcFree((void *)reqData);
            FreeBuffer(NULL, (void *)outMsg);
            LOGE("memory copy reply data failed");
            return;
        }
        reply->bufferLeft = replyTmp.bufferLeft;
        LOGI("out reply data, length(%zu), flag(%u)", reply->bufferLeft, reply->flag);
    }
    FreeBuffer(NULL, (void *)outMsg);
    HcFree((void *)reqData);
    return;
}

#ifdef __cplusplus
}
#endif
