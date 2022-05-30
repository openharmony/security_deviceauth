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

#include "pake_v2_auth_server_task.h"

#include "account_module.h"
#include "asy_token_manager.h"
#include "common_defs.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_types.h"
#include "pake_v2_auth_task_common.h"
#include "pake_v2_protocol_common.h"
#include "protocol_common.h"
#include "account_version_util.h"

enum {
    TASK_STATUS_PAKE_FOLLOW_BEGIN = 0,
    TASK_STATUS_PAKE_FOLLOW_STEP_ONE = 1,
    TASK_STATUS_PAKE_FOLLOW_STEP_TWO = 2,
    TASK_STATUS_PAKE_FOLLOW_END = 3,
};

static AccountTaskType GetPakeV2AuthServerType(void)
{
    return TASK_TYPE_PAKE_V2_AUTH_SERVER;
}

static void DestroyAuthServerAuthTask(TaskBase *task)
{
    if (task == NULL) {
        LOGD("NULL pointer and return");
        return;
    }
    PakeV2AuthServerTask *innerTask = (PakeV2AuthServerTask *)task;
    DestroyPakeAuthParams(&(innerTask->params));
    HcFree(innerTask);
}

static int32_t DealAsyStepOneData(PakeV2AuthServerTask *task, const CJson *in)
{
    int32_t res = ExtractSelfDevId(&task->params, in);
    if (res != HC_SUCCESS) {
        LOGE("ExtractSelfDevId failed for server.");
        return res;
    }
    if (VerifyPkSignPeer(&task->params) != HC_SUCCESS) {
        LOGE("Step one: VerifyPkSignPeer failed for server.");
        return HC_ERR_ACCOUNT_VERIFY_PK_SIGN;
    }
    if (GenerateEcdhSharedKey(&task->params) != HC_SUCCESS) {
        LOGE("Step one: Generate ecdh shared key failed for server.");
        return HC_ERR_ACCOUNT_ECDH_FAIL;
    }
    res = ServerResponsePakeV2Protocol(&task->params.pakeParams);
    if (res != HC_SUCCESS) {
        LOGE("Step one: ServerResponsePakeV2Protocol failed.");
        return res;
    }
    if (ExtractPakeSelfId(&task->params) != HC_SUCCESS) {
        LOGE("ConstructPayLoad peer failed.");
        return HC_ERR_AUTH_INTERNAL;
    }
    return HC_SUCCESS;
}

static int32_t GetNegotiatedVersionForServer(const CJson *in, uint64_t *negotiatedVersionNo)
{
    uint64_t peerSupportedVersion = 0;
    if (GetInt64FromJson(in, FIELD_SUPPORTED_VERSION, (int64_t *)&peerSupportedVersion) != HC_SUCCESS) {
        LOGE("Get version from client failed.");
        return HC_ERR_JSON_GET;
    }
    const AccountVersionInfo *verInfo = GetNegotiatedVersionInfo(AUTHENTICATE, peerSupportedVersion);
    if (verInfo == NULL) {
        LOGE("Get negotiated VersionInfo failed for server.");
        return HC_ERR_UNSUPPORTED_VERSION;
    }
    *negotiatedVersionNo = verInfo->versionNo;
    return HC_SUCCESS;
}

static int32_t PrepareAsyServerStepOneData(const PakeV2AuthServerTask *innerTask, const CJson *in, CJson *out)
{
    uint64_t negotiatedVersionNo = 0;
    if (GetNegotiatedVersionForServer(in, &negotiatedVersionNo) != HC_SUCCESS) {
        return HC_ERR_AUTH_INTERNAL;
    }
    CJson *sendToPeer = CreateJson();
    if (sendToPeer == NULL) {
        LOGE("Create json NULL.");
        return HC_ERR_JSON_CREATE;
    }
    CJson *data = CreateJson();
    if (data == NULL) {
        LOGE("Create json NULL.");
        FreeJson(sendToPeer);
        return HC_ERR_JSON_CREATE;
    }
    int32_t ret = HC_SUCCESS;
    GOTO_ERR_AND_SET_RET(AddInt64StringToJson(sendToPeer, FIELD_SUPPORTED_VERSION, negotiatedVersionNo), ret);
    GOTO_ERR_AND_SET_RET(AddStringToJson(sendToPeer, FIELD_USER_ID,
        (const char *)innerTask->params.userIdSelf), ret);
    GOTO_ERR_AND_SET_RET(AddIntToJson(sendToPeer, FIELD_STEP, RET_PAKE_AUTH_FOLLOWER_ONE), ret);
    GOTO_ERR_AND_SET_RET(AddStringToJson(sendToPeer, FIELD_DEVICE_ID,
        (const char *)innerTask->params.deviceIdSelf.val), ret);
    GOTO_ERR_AND_SET_RET(AddIntToJson(sendToPeer, FIELD_AUTH_FORM, 1), ret);
    GOTO_ERR_AND_SET_RET(AddStringToJson(sendToPeer, FIELD_DEV_ID, (const char *)innerTask->params.devIdSelf.val), ret);

    GOTO_ERR_AND_SET_RET(AddIntToJson(data, FIELD_AUTH_KEY_ALG_ENCODE, innerTask->params.authKeyAlgEncode), ret);
    GOTO_ERR_AND_SET_RET(AddStringToJson(data, FIELD_AUTH_PK_INFO,
        (const char *)innerTask->params.pkInfoSelf.val), ret);
    GOTO_ERR_AND_SET_RET(AddByteToJson(data, FIELD_AUTH_PK_INFO_SIGN, innerTask->params.pkInfoSignSelf.val,
        innerTask->params.pkInfoSignSelf.length), ret);
    GOTO_ERR_AND_SET_RET(AddByteToJson(data, FIELD_EPK, innerTask->params.pakeParams.epkSelf.val,
        innerTask->params.pakeParams.epkSelf.length), ret);
    GOTO_ERR_AND_SET_RET(AddByteToJson(data, FIELD_SALT, innerTask->params.pakeParams.salt.val,
        innerTask->params.pakeParams.salt.length), ret);
    GOTO_ERR_AND_SET_RET(AddObjToJson(sendToPeer, FIELD_DATA, data), ret);
    GOTO_ERR_AND_SET_RET(AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer), ret);
ERR:
    FreeJson(sendToPeer);
    FreeJson(data);
    return ret;
}

static int32_t AsyAuthServerStepOne(TaskBase *task, const CJson *in, CJson *out, int32_t *status)
{
    PakeV2AuthServerTask *innerTask = (PakeV2AuthServerTask *)task;
    if (innerTask->taskBase.taskStatus != TASK_STATUS_PAKE_FOLLOW_STEP_ONE) {
        LOGE("Server step one task status error.");
        return HC_ERR_AUTH_STATUS;
    }
    GOTO_IF_ERR(GetIntFromJson(in, FIELD_AUTH_FORM, &innerTask->params.authForm));
    const char *userIdPeer = GetStringFromJson(in, FIELD_USER_ID);
    uint32_t userIdPeerLen = HcStrlen(userIdPeer) + 1;
    if (userIdPeer == NULL || userIdPeerLen > DEV_AUTH_USER_ID_SIZE) {
        LOGE("Payload not contain peer userId or userId len is invalid.");
        return HC_ERR_BAD_MESSAGE;
    }
    GOTO_IF_ERR(strcpy_s((char *)innerTask->params.userIdPeer, userIdPeerLen, userIdPeer));
    GOTO_IF_ERR(ExtractSelfDeviceId(&innerTask->params, in, true));
    GOTO_IF_ERR(ExtractPeerDeviceId(&innerTask->params, in));
    GOTO_IF_ERR(ExtractPeerDevId(&innerTask->params, in));
    GOTO_IF_ERR(GetIntFromJson(in, FIELD_AUTH_KEY_ALG_ENCODE, &innerTask->params.authKeyAlgEncode));
    GOTO_IF_ERR(GetPkInfoPeer(&innerTask->params, in));
    GOTO_IF_ERR(GetByteFromJson(in, FIELD_AUTH_PK_INFO_SIGN, innerTask->params.pkInfoSignPeer.val,
        innerTask->params.pkInfoSignPeer.length));
    const char *pkInfoSignPeerStr = GetStringFromJson(in, FIELD_AUTH_PK_INFO_SIGN);
    if (pkInfoSignPeerStr == NULL) {
        LOGE("pkInfoSignPeer in server is null.");
        return HC_ERR_NULL_PTR;
    }
    innerTask->params.pkInfoSignPeer.length = HcStrlen(pkInfoSignPeerStr) / BYTE_TO_HEX_OPER_LENGTH;
    GOTO_IF_ERR(DealAsyStepOneData(innerTask, in));
    GOTO_IF_ERR(PrepareAsyServerStepOneData(innerTask, in, out));

    innerTask->taskBase.taskStatus = TASK_STATUS_PAKE_FOLLOW_STEP_TWO;
    *status = CONTINUE;
    return HC_SUCCESS;
ERR:
    LOGE("Server step one failed.");
    return HC_ERR_AUTH_INTERNAL;
}

static int32_t DealAsyStepTwoData(PakeV2AuthServerTask *task)
{
    if (ServerConfirmPakeV2Protocol(&task->params.pakeParams) != HC_SUCCESS) {
        LOGE("Server ConfirmPakeV2Protocol failed.");
        return HC_ERR_SERVER_CONFIRM_PROTOCOL;
    }
    return HC_SUCCESS;
}

static int32_t SendFinalToOut(PakeV2AuthServerTask *task, CJson *out)
{
    CJson *sendToSelf = CreateJson();
    if (sendToSelf == NULL) {
        LOGE("Create json sendToSelf failed.");
        return HC_ERR_JSON_CREATE;
    }
    CJson *sendToPeer = CreateJson();
    if (sendToPeer == NULL) {
        LOGE("Create json sendToPeer failed.");
        FreeJson(sendToSelf);
        return HC_ERR_JSON_CREATE;
    }
    CJson *sendToPeerData = CreateJson();
    if (sendToPeerData == NULL) {
        LOGE("Create json sendToPeerData failed.");
        FreeJson(sendToPeer);
        FreeJson(sendToSelf);
        return HC_ERR_JSON_CREATE;
    }
    GOTO_IF_ERR(AddStringToJson(sendToSelf, FIELD_USER_ID, (const char *)task->params.userIdPeer));
    GOTO_IF_ERR(AddByteToJson(sendToSelf, FIELD_SESSION_KEY,
        task->params.pakeParams.sessionKey.val, task->params.pakeParams.sessionKey.length));
    GOTO_IF_ERR(AddStringToJson(sendToSelf, FIELD_DEVICE_ID, (const char *)task->params.deviceIdSelf.val));
    GOTO_IF_ERR(AddStringToJson(sendToSelf, FIELD_DEV_ID, (const char *)task->params.devIdPeer.val));

    GOTO_IF_ERR(AddIntToJson(sendToPeer, FIELD_AUTH_FORM, 1));
    GOTO_IF_ERR(AddIntToJson(sendToPeer, FIELD_STEP, RET_PAKE_AUTH_FOLLOWER_TWO));

    GOTO_IF_ERR(AddByteToJson(sendToPeerData,
        FIELD_KCF_DATA, task->params.pakeParams.kcfData.val, task->params.pakeParams.kcfData.length));
    GOTO_IF_ERR(AddObjToJson(out, FIELD_SEND_TO_SELF, sendToSelf));
    GOTO_IF_ERR(AddObjToJson(sendToPeer, FIELD_DATA, sendToPeerData));
    GOTO_IF_ERR(AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer));
    FreeJson(sendToPeer);
    FreeJson(sendToSelf);
    FreeJson(sendToPeerData);
    FreeAndCleanKey(&task->params.pakeParams.sessionKey);
    return HC_SUCCESS;
ERR:
    LOGE("Server send final failed");
    FreeJson(sendToPeer);
    FreeJson(sendToSelf);
    FreeJson(sendToPeerData);
    FreeAndCleanKey(&task->params.pakeParams.sessionKey);
    return HC_ERR_AUTH_INTERNAL;
}

static int32_t AsyAuthServerStepTwo(TaskBase *task, const CJson *in, CJson *out, int32_t *status)
{
    PakeV2AuthServerTask *innerTask = (PakeV2AuthServerTask *)task;
    if (innerTask->taskBase.taskStatus != TASK_STATUS_PAKE_FOLLOW_STEP_TWO) {
        LOGE("Server task status error");
        return HC_ERR_AUTH_STATUS;
    }
    GOTO_IF_ERR(GetByteFromJson(in,
        FIELD_EPK, innerTask->params.pakeParams.epkPeer.val, innerTask->params.pakeParams.epkPeer.length));
    GOTO_IF_ERR(GetByteFromJson(in,
        FIELD_KCF_DATA, innerTask->params.pakeParams.kcfDataPeer.val, innerTask->params.pakeParams.kcfDataPeer.length));
    GOTO_IF_ERR(ExtractPakePeerId(&innerTask->params, in));
    GOTO_IF_ERR(DealAsyStepTwoData(innerTask));
    GOTO_IF_ERR(SendFinalToOut(innerTask, out));
    innerTask->taskBase.taskStatus = TASK_STATUS_PAKE_FOLLOW_END;
    *status = FINISH;
    return HC_SUCCESS;
ERR:
    LOGE("server AsyAuthServerStepTwo failed");
    return HC_ERR_AUTH_INTERNAL;
}

static int32_t ProcessServerTask(TaskBase *task, const CJson *in, CJson *out, int32_t *status)
{
    if ((task == NULL) || (in == NULL) || (out == NULL) || (status == NULL)) {
        LOGE("invalid param");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t step = 0;
    if (GetIntFromJson(in, FIELD_STEP, &step) != HC_SUCCESS) {
        LOGE("server no auth step");
        return HC_ERR_JSON_GET;
    }
    LOGI("ProcessServerTask step: %d", step);
    int32_t res;
    switch (step) {
        case CMD_PAKE_AUTH_MAIN_ONE:
            res = AsyAuthServerStepOne(task, in, out, status);
            break;
        case CMD_PAKE_AUTH_MAIN_TWO:
            res = AsyAuthServerStepTwo(task, in, out, status);
            break;
        case ERR_MSG:
            return HC_ERR_PEER_ERROR;
        default:
            res = HC_ERR_BAD_MESSAGE;
            break;
    }
    if (res != HC_SUCCESS) {
        LOGE("Server ProcessServerTask failed, step: %d.", step);
    }
    return res;
}

TaskBase *CreatePakeV2AuthServerTask(const CJson *in, CJson *out, const AccountVersionInfo *verInfo)
{
    if (in == NULL || out == NULL || verInfo == NULL) {
        LOGE("Params is null.");
        return NULL;
    }
    PakeV2AuthServerTask *taskParams = (PakeV2AuthServerTask *)HcMalloc(sizeof(PakeV2AuthServerTask), 0);
    if (taskParams == NULL) {
        LOGE("Malloc taskParams failed");
        return NULL;
    }
    (void)memset_s(taskParams, sizeof(PakeV2AuthServerTask), 0, sizeof(PakeV2AuthServerTask));
    taskParams->taskBase.getTaskType = GetPakeV2AuthServerType;
    taskParams->taskBase.process = ProcessServerTask;
    taskParams->taskBase.destroyTask = DestroyAuthServerAuthTask;

    if (InitPakeAuthParams(in, &(taskParams->params), verInfo) != HC_SUCCESS) {
        LOGE("InitPakeAuthParams error.");
        DestroyAuthServerAuthTask((TaskBase *)taskParams);
        return NULL;
    }

    taskParams->taskBase.taskStatus = TASK_STATUS_PAKE_FOLLOW_STEP_ONE;
    return (TaskBase *)taskParams;
}