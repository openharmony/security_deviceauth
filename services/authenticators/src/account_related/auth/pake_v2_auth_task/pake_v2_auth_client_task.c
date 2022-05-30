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

#include "pake_v2_auth_client_task.h"
#include "common_defs.h"
#include "device_auth_defines.h"
#include "hal_error.h"
#include "hc_types.h"
#include "hc_log.h"
#include "string_util.h"
#include "protocol_common.h"
#include "account_module.h"
#include "account_version_util.h"
#include "pake_v2_auth_task_common.h"
#include "pake_v2_protocol_common.h"

enum {
    TASK_STATUS_PAKE_MAIN_BEGIN = 0,
    TASK_STATUS_PAKE_MAIN_STEP_ONE = 1,
    TASK_STATUS_PAKE_MAIN_STEP_TWO = 2,
    TASK_STATUS_PAKE_MAIN_END = 3,
};

static AccountTaskType GetPakeV2AuthClientType(void)
{
    return TASK_TYPE_PAKE_V2_AUTH_CLIENT;
}

static int32_t DealClientStepOne(PakeAuthParams *params, const CJson *in)
{
    int32_t res = ExtractSelfDevId(params, in);
    if (res != HC_SUCCESS) {
        LOGE("ExtractSelfDevId failed for client.");
    }
    return res;
}

static int32_t AsyAuthClientStepOne(TaskBase *task, const CJson *in, CJson *out, int32_t *status)
{
    PakeV2AuthClientTask *innerTask = (PakeV2AuthClientTask *)task;
    CJson *sendToPeer = CreateJson();
    if (sendToPeer == NULL) {
        LOGE("Failed to create sendToPeer json.");
        return HC_ERR_JSON_CREATE;
    }
    CJson *data = CreateJson();
    if (data == NULL) {
        LOGE("Failed to create data json.");
        FreeJson(sendToPeer);
        return HC_ERR_JSON_CREATE;
    }
    uint64_t versionNo = GetSupportedVersionNo(AUTHENTICATE);

    GOTO_IF_ERR(GetIntFromJson(in, FIELD_AUTH_FORM, &innerTask->params.authForm));
    GOTO_IF_ERR(ExtractSelfDeviceId(&innerTask->params, in, true));
    GOTO_IF_ERR(DealClientStepOne(&innerTask->params, in));

    GOTO_IF_ERR(AddInt64StringToJson(sendToPeer, FIELD_SUPPORTED_VERSION, versionNo));
    GOTO_IF_ERR(AddIntToJson(sendToPeer, FIELD_AUTH_FORM, innerTask->params.authForm));
    GOTO_IF_ERR(AddStringToJson(sendToPeer, FIELD_USER_ID, (const char *)innerTask->params.userIdSelf));
    GOTO_IF_ERR(AddIntToJson(sendToPeer, FIELD_STEP, CMD_PAKE_AUTH_MAIN_ONE));
    GOTO_IF_ERR(AddStringToJson(sendToPeer, FIELD_DEVICE_ID, (const char *)innerTask->params.deviceIdSelf.val));
    GOTO_IF_ERR(AddStringToJson(sendToPeer, FIELD_DEV_ID, (const char *)innerTask->params.devIdSelf.val));

    GOTO_IF_ERR(AddIntToJson(data, FIELD_AUTH_KEY_ALG_ENCODE, ALG_ECC));
    GOTO_IF_ERR(AddStringToJson(data, FIELD_AUTH_PK_INFO, (const char *)innerTask->params.pkInfoSelf.val));
    GOTO_IF_ERR(AddByteToJson(data, FIELD_AUTH_PK_INFO_SIGN, innerTask->params.pkInfoSignSelf.val,
        innerTask->params.pkInfoSignSelf.length));
    GOTO_IF_ERR(AddObjToJson(sendToPeer, FIELD_DATA, data));
    GOTO_IF_ERR(AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer));
    innerTask->taskBase.taskStatus = TASK_STATUS_PAKE_MAIN_STEP_ONE;
    *status = CONTINUE;
    FreeJson(sendToPeer);
    FreeJson(data);
    return HC_SUCCESS;
ERR:
    LOGE("Client step one failed.");
    FreeJson(sendToPeer);
    FreeJson(data);
    return HC_ERR_AUTH_INTERNAL;
}

static int32_t DealAsyStepTwoData(PakeV2AuthClientTask *task)
{
    if (ExtractPakeSelfId(&task->params) != HC_SUCCESS) {
        LOGE("ExtractPakeSelfId failed for client.");
        return HC_ERR_AUTH_INTERNAL;
    }
    if (VerifyPkSignPeer(&task->params) != HC_SUCCESS) {
        LOGE("VerifyPkSignPeer failed for client.");
        return HC_ERR_ACCOUNT_VERIFY_PK_SIGN;
    }
    if (GenerateEcdhSharedKey(&task->params) != HC_SUCCESS) {
        LOGE("Generate ecdh shared key failed for client.");
        return HC_ERR_ACCOUNT_ECDH_FAIL;
    }
    if (ClientConfirmPakeV2Protocol(&task->params.pakeParams)) {
        LOGE("ClientConfirmPakeV2Protocol failed.");
        return HC_ERR_CLIENT_CONFIRM_PROTOCOL;
    }
    return HC_SUCCESS;
}

static int32_t PrepareAsyClientStepTwoData(const PakeV2AuthClientTask *innerTask, CJson *out)
{
    CJson *sendToPeer = CreateJson();
    if (sendToPeer == NULL) {
        LOGE("Create sendToPeer json NULL.");
        return HC_ERR_JSON_CREATE;
    }
    CJson *data = CreateJson();
    if (data == NULL) {
        LOGE("Create data json NULL.");
        FreeJson(sendToPeer);
        return HC_ERR_JSON_CREATE;
    }
    int32_t ret = HC_SUCCESS;
    GOTO_ERR_AND_SET_RET(AddIntToJson(sendToPeer, FIELD_AUTH_FORM, innerTask->params.authForm), ret);
    GOTO_ERR_AND_SET_RET(AddIntToJson(sendToPeer, FIELD_STEP, CMD_PAKE_AUTH_MAIN_TWO), ret);
    GOTO_ERR_AND_SET_RET(AddByteToJson(data, FIELD_KCF_DATA, innerTask->params.pakeParams.kcfData.val,
        innerTask->params.pakeParams.kcfData.length), ret);
    GOTO_ERR_AND_SET_RET(AddStringToJson(data, FIELD_DEVICE_ID,
        (const char *)innerTask->params.deviceIdSelf.val), ret);
    GOTO_ERR_AND_SET_RET(AddByteToJson(data, FIELD_EPK, innerTask->params.pakeParams.epkSelf.val,
        innerTask->params.pakeParams.epkSelf.length), ret);
    GOTO_ERR_AND_SET_RET(AddObjToJson(sendToPeer, FIELD_DATA, data), ret);
    GOTO_ERR_AND_SET_RET(AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer), ret);
ERR:
    FreeJson(sendToPeer);
    FreeJson(data);
    return ret;
}

static int32_t AsyAuthClientStepTwo(TaskBase *task, const CJson *in, CJson *out, int32_t *status)
{
    PakeV2AuthClientTask *innerTask = (PakeV2AuthClientTask *)task;
    if (innerTask->taskBase.taskStatus != TASK_STATUS_PAKE_MAIN_STEP_ONE) {
        LOGE("Client step two status error.");
        return HC_ERR_AUTH_STATUS;
    }
    const char *userIdPeer = GetStringFromJson(in, FIELD_USER_ID);
    uint32_t userIdPeerLen = HcStrlen(userIdPeer) + 1;
    if (userIdPeer == NULL || userIdPeerLen > DEV_AUTH_USER_ID_SIZE) {
        LOGE("Payload not contain peer userId or userId len is invalid.");
        return HC_ERR_BAD_MESSAGE;
    }
    GOTO_IF_ERR(strcpy_s((char *)innerTask->params.userIdPeer, userIdPeerLen, userIdPeer));
    GOTO_IF_ERR(GetPkInfoPeer(&innerTask->params, in));
    GOTO_IF_ERR(ExtractPeerDeviceId(&innerTask->params, in));
    GOTO_IF_ERR(ExtractPeerDevId(&innerTask->params, in));
    GOTO_IF_ERR(ExtractPakePeerId(&innerTask->params, in));
    GOTO_IF_ERR(GetByteFromJson(in, FIELD_AUTH_PK_INFO_SIGN, innerTask->params.pkInfoSignPeer.val,
        innerTask->params.pkInfoSignPeer.length));
    const char *pkInfoSignPeerStr = GetStringFromJson(in, FIELD_AUTH_PK_INFO_SIGN);
    if (pkInfoSignPeerStr == NULL) {
        LOGE("pkInfoSignPeer in client is null.");
        return HC_ERR_NULL_PTR;
    }
    innerTask->params.pkInfoSignPeer.length = HcStrlen(pkInfoSignPeerStr) / BYTE_TO_HEX_OPER_LENGTH;
    GOTO_IF_ERR(GetByteFromJson(in, FIELD_SALT, innerTask->params.pakeParams.salt.val,
        innerTask->params.pakeParams.salt.length));
    GOTO_IF_ERR(GetByteFromJson(in, FIELD_EPK, innerTask->params.pakeParams.epkPeer.val,
        innerTask->params.pakeParams.epkPeer.length));

    GOTO_IF_ERR(DealAsyStepTwoData(innerTask));

    GOTO_IF_ERR(PrepareAsyClientStepTwoData(innerTask, out));

    innerTask->taskBase.taskStatus = TASK_STATUS_PAKE_MAIN_STEP_TWO;
    *status = CONTINUE;
    return HC_SUCCESS;
ERR:
    LOGE("Client step two failed");
    return HC_ERR_AUTH_INTERNAL;
}

static int32_t DealAsyStepThreeData(PakeAuthParams *params)
{
    int32_t res = ClientVerifyConfirmPakeV2Protocol(&params->pakeParams);
    if (res != HC_SUCCESS) {
        LOGE("Client Verify ConfirmPakeV2Protocol failed.");
    }
    return res;
}

static int32_t SendFinalToOut(PakeV2AuthClientTask *task, CJson *out)
{
    CJson *sendToSelf = CreateJson();
    if (sendToSelf == NULL) {
        LOGE("Create sendToSelf json NULL.");
        return HC_ERR_JSON_CREATE;
    }
    GOTO_IF_ERR(AddStringToJson(sendToSelf, FIELD_USER_ID, (const char *)task->params.userIdPeer));
    GOTO_IF_ERR(AddByteToJson(sendToSelf,
        FIELD_SESSION_KEY, task->params.pakeParams.sessionKey.val, task->params.pakeParams.sessionKey.length));
    GOTO_IF_ERR(AddStringToJson(sendToSelf, FIELD_DEVICE_ID, (const char *)task->params.deviceIdSelf.val));
    GOTO_IF_ERR(AddStringToJson(sendToSelf, FIELD_DEV_ID, (const char *)task->params.devIdPeer.val));
    GOTO_IF_ERR(AddObjToJson(out, FIELD_SEND_TO_SELF, sendToSelf));
    FreeJson(sendToSelf);
    FreeAndCleanKey(&task->params.pakeParams.sessionKey);
    return HC_SUCCESS;
ERR:
    FreeAndCleanKey(&task->params.pakeParams.sessionKey);
    FreeJson(sendToSelf);
    LOGE("SendFinalToOut failed");
    return HC_ERR_AUTH_INTERNAL;
}

static int32_t AsyAuthClientStepThree(TaskBase *task, const CJson *in, CJson *out, int32_t *status)
{
    PakeV2AuthClientTask *innerTask = (PakeV2AuthClientTask *)task;
    if (innerTask->taskBase.taskStatus != TASK_STATUS_PAKE_MAIN_STEP_TWO) {
        LOGE("Client step three status error.");
        return HC_ERR_AUTH_STATUS;
    }
    GOTO_IF_ERR(GetByteFromJson(in, FIELD_KCF_DATA,
        innerTask->params.pakeParams.kcfDataPeer.val, innerTask->params.pakeParams.kcfDataPeer.length));
    GOTO_IF_ERR(DealAsyStepThreeData(&innerTask->params));
    GOTO_IF_ERR(SendFinalToOut(innerTask, out));
    innerTask->taskBase.taskStatus = TASK_STATUS_PAKE_MAIN_END;
    *status = FINISH;
    return HC_SUCCESS;
ERR:
    LOGE("Client step three failed");
    return HC_ERR_AUTH_INTERNAL;
}

static int32_t ProcessClientTask(TaskBase *task, const CJson *in, CJson *out, int32_t *status)
{
    LOGI("Start process client pake v2 auth task.");
    if (task == NULL || in == NULL || out == NULL || status == NULL) {
        LOGE("ProcessClientTask in params NULL.");
        return HC_ERR_INVALID_PARAMS;
    }

    if (task->taskStatus == TASK_STATUS_PAKE_MAIN_BEGIN) {
        return AsyAuthClientStepOne(task, in, out, status);
    }
    int32_t step = 0; // step comes from opposite device
    if (GetIntFromJson(in, FIELD_STEP, &step) != HC_SUCCESS) {
        LOGE("Get no auth step.");
        return HC_ERR_JSON_GET;
    }
    int32_t res;
    switch (step) {
        case RET_PAKE_AUTH_FOLLOWER_ONE: // the step name of the opposite
            res = AsyAuthClientStepTwo(task, in, out, status);
            break;
        case RET_PAKE_AUTH_FOLLOWER_TWO:
            res = AsyAuthClientStepThree(task, in, out, status);
            break;
        case ERR_MSG:
            return HC_ERR_PEER_ERROR;
        default:
            res = HC_ERR_BAD_MESSAGE;
            break;
    }
    if (res != HC_SUCCESS) {
        LOGE("error occurred and send error");
        return res;
    }
    LOGI("End process client, step = %d", step);
    return HC_SUCCESS;
}

static void DestroyAuthClientAuthTask(TaskBase *task)
{
    if (task == NULL) {
        LOGD("Task is NULL");
        return;
    }
    PakeV2AuthClientTask *innerTask = (PakeV2AuthClientTask *)task;
    DestroyPakeAuthParams(&(innerTask->params));
    HcFree(innerTask);
}

TaskBase *CreatePakeV2AuthClientTask(const CJson *in, CJson *out, const AccountVersionInfo *verInfo)
{
    if (in == NULL || out == NULL || verInfo == NULL) {
        LOGE("Params is null for create client pake v2 auth task.");
        return NULL;
    }
    PakeV2AuthClientTask *taskParams = (PakeV2AuthClientTask *)HcMalloc(sizeof(PakeV2AuthClientTask), 0);
    if (taskParams == NULL) {
        LOGE("Malloc for PakeV2AuthClientTask failed.");
        return NULL;
    }
    taskParams->taskBase.getTaskType = GetPakeV2AuthClientType;
    taskParams->taskBase.destroyTask = DestroyAuthClientAuthTask;
    taskParams->taskBase.process = ProcessClientTask;
    int32_t res = InitPakeAuthParams(in, &(taskParams->params), verInfo);
    if (res != HC_SUCCESS) {
        DestroyAuthClientAuthTask((TaskBase *)taskParams);
        LOGE("InitPakeAuthParams failed");
        return NULL;
    }

    taskParams->taskBase.taskStatus = TASK_STATUS_PAKE_MAIN_BEGIN;
    return (TaskBase *)taskParams;
}