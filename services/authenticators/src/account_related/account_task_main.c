/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "account_task_main.h"
#include "alg_defs.h"
#include "alg_loader.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "clib_error.h"
#include "hc_log.h"
#include "json_utils.h"
#include "account_version_util.h"

static void AccountSendErrMsgToSelf(CJson *out, int32_t errCode)
{
    CJson *sendToSelf = CreateJson();
    if (sendToSelf == NULL) {
        LOGE("Create sendToSelf json failed.");
        return;
    }
    if (AddIntToJson(sendToSelf, FIELD_ERROR_CODE, errCode) != CLIB_SUCCESS) {
        LOGE("Add errCode to self json failed.");
        FreeJson(sendToSelf);
        return;
    }
    if (AddObjToJson(out, FIELD_SEND_TO_SELF, sendToSelf) != CLIB_SUCCESS) {
        LOGE("Add sendToSelf obj to out json failed.");
        FreeJson(sendToSelf);
        return;
    }
    FreeJson(sendToSelf);
}

static void AccountSendErrMsgToOut(CJson *out, int32_t opCode, int32_t errCode)
{
    CJson *sendToSelf = CreateJson();
    if (sendToSelf == NULL) {
        LOGE("Create sendToSelf json failed.");
        return;
    }
    CJson *sendToPeer = CreateJson();
    if (sendToPeer == NULL) {
        LOGE("Create sendToPeer json failed.");
        FreeJson(sendToSelf);
        return;
    }
    if (opCode == OP_BIND) {
        if (AddIntToJson(sendToPeer, FIELD_MESSAGE, ERR_MSG) != CLIB_SUCCESS) {
            LOGE("Failed to add error message to json for bind.");
            goto CLEAN_UP;
        }
    } else {
        if (AddIntToJson(sendToPeer, FIELD_STEP, ERR_MSG) != CLIB_SUCCESS) {
            LOGE("Failed to add error message to json for auth.");
            goto CLEAN_UP;
        }
    }
    if (AddIntToJson(sendToPeer, FIELD_ERROR_CODE, errCode) != CLIB_SUCCESS) {
        LOGE("Add errCode to json failed.");
        goto CLEAN_UP;
    }
    if (AddIntToJson(sendToSelf, FIELD_AUTH_FORM, ACCOUNT_MODULE) != CLIB_SUCCESS) {
        LOGE("Add auth form to json failed.");
        goto CLEAN_UP;
    }
    if (AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer) != CLIB_SUCCESS) {
        LOGE("Add sendToPeer to json failed.");
        goto CLEAN_UP;
    }
    if (AddObjToJson(out, FIELD_SEND_TO_SELF, sendToSelf) != CLIB_SUCCESS) {
        LOGE("Add sendToSelf to json failed.");
        goto CLEAN_UP;
    }

CLEAN_UP:
    FreeJson(sendToPeer);
    FreeJson(sendToSelf);
    return;
}

static void DestroyTaskT(AccountTask *task)
{
    if (task == NULL) {
        return;
    }
    if (task->subTask != NULL) {
        task->subTask->destroyTask(task->subTask);
    }
    HcFree(task);
}

static bool IsPeerErrMessage(const CJson *in)
{
    int32_t res = 0;
    int32_t message = 0;
    if ((GetIntFromJson(in, FIELD_MESSAGE, &message) != CLIB_SUCCESS) &&
        (GetIntFromJson(in, FIELD_STEP, &message) != CLIB_SUCCESS)) {
        LOGD("There is no message code."); // The first message of the client has no message code
        return false;
    }
    if (message != ERR_MSG) {
        return false;
    }

    if (GetIntFromJson(in, FIELD_ERROR_CODE, &res) != CLIB_SUCCESS) {
        LOGE("Get peer error code failed.");
    }
    LOGE("Receive error message from peer, errCode: %x.", res);
    return true;
}

static int32_t MapSubTaskTypeToOpCode(AccountTaskType subTaskType)
{
    if (subTaskType >= TASK_TYPE_PAKE_V2_AUTH_CLIENT && subTaskType <= TASK_TYPE_ISO_AUTH_SERVER) {
        return AUTHENTICATE;
    }
    return CODE_NULL;
}

static int32_t ProcessTaskT(AccountTask *task, const CJson *in, CJson *out, int32_t *status)
{
    if (IsPeerErrMessage(in)) {
        AccountSendErrMsgToSelf(out, HC_ERR_PEER_ERROR);
        return HC_ERR_PEER_ERROR;
    }
    int32_t res = task->subTask->process(task->subTask, in, out, status);
    if (res != HC_SUCCESS) {
        LOGE("Process subTask failed, res: %x.", res);
        int32_t operationCode = MapSubTaskTypeToOpCode(task->subTask->getTaskType());
        AccountSendErrMsgToOut(out, operationCode, res);
    }
    return res;
}

static int32_t NegotiateAndCreateSubTask(AccountTask *task, const CJson *in, CJson *out)
{
    bool isClient = false;
    int32_t operationCode = 0;
    uint64_t versionNo = 0;
    if (GetBoolFromJson(in, FIELD_IS_CLIENT, &isClient) != CLIB_SUCCESS) {
        LOGI("There is no isClient in json.");
    }
    if (GetIntFromJson(in, FIELD_OPERATION_CODE, &operationCode) != CLIB_SUCCESS) {
        LOGE("Get operationCode from json failed.");
        return HC_ERR_JSON_GET;
    }
    if (isClient) {
        versionNo = GetSupportedVersionNo(operationCode);
    } else if (GetInt64FromJson(in, FIELD_SUPPORTED_VERSION, (int64_t *)&versionNo) != CLIB_SUCCESS) {
        LOGE("No peer supportedVersion for server.");
        return HC_ERR_BAD_MESSAGE;
    }
    const AccountVersionInfo *verInfo = GetNegotiatedVersionInfo(operationCode, versionNo);
    if (verInfo == NULL) {
        LOGE("Get Negotiated versionInfo failed.");
        return HC_ERR_UNSUPPORTED_VERSION;
    }
    task->subTask = verInfo->createTask(in, out, verInfo);
    if (task->subTask == NULL) {
        LOGE("Create sub task failed.");
        return HC_ERR_ALLOC_MEMORY;
    }
    task->versionStatus = VERSION_CONFIRMED;
    return HC_SUCCESS;
}

static void AccountSendCreateError(const CJson *in, CJson *out, int32_t errCode)
{
    bool isClient = false;
    if (GetBoolFromJson(in, FIELD_IS_CLIENT, &isClient) != CLIB_SUCCESS) {
        LOGE("Get isClient from json failed.");
    }
    if (isClient) {
        AccountSendErrMsgToSelf(out, errCode);
        return;
    }
    int32_t operationCode = CODE_NULL;
    if (GetIntFromJson(in, FIELD_OPERATION_CODE, &operationCode) != CLIB_SUCCESS) {
        LOGE("Get operationCode from json failed.");
    } else {
        AccountSendErrMsgToOut(out, operationCode, errCode);
    }
}

AccountTask *CreateAccountTaskT(int32_t *taskId, const CJson *in, CJson *out)
{
    int32_t res;
    AccountTask *task = (AccountTask *)HcMalloc(sizeof(AccountTask), 0);
    if (task == NULL) {
        LOGE("Malloc for account related task failed.");
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    task->destroyTask = DestroyTaskT;
    task->processTask = ProcessTaskT;
    task->versionStatus = VERSION_INITIAL;
    Uint8Buff taskIdBuf = { (uint8_t *)taskId, sizeof(int32_t) };
    res = GetLoaderInstance()->generateRandom(&taskIdBuf);
    if (res != HC_SUCCESS) {
        LOGE("Generate taskId failed, res: %d.", res);
        goto ERR;
    }
    task->taskId = *taskId;
    res = NegotiateAndCreateSubTask(task, in, out);
    if (res != HC_SUCCESS) {
        LOGE("NegotiateAndCreateSubTask failed, res: %d.", res);
        goto ERR;
    }
    return task;
ERR:
    AccountSendCreateError(in, out, res);
    DestroyTaskT(task);
    return NULL;
}
