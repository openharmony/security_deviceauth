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

#include "account_module.h"
#include "account_module_defines.h"
#include "account_multi_task_manager.h"
#include "account_version_util.h"
#include "alg_loader.h"
#include "asy_token_manager.h"
#include "clib_error.h"
#include "clib_types.h"
#include "common_defs.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "json_utils.h"
#include "pake_v2_auth_client_task.h"
#include "pake_v2_auth_server_task.h"
#include "sym_token_manager.h"

#define ACCOUNT_CLIENT_FIRST_MESSAGE 0x0000
#define ACCOUNT_CLIENT_STEP_MASK 0x000F

typedef struct {
    AuthModuleBase moduleBase;
} AccountModule;

static AccountModule g_module;

int32_t CheckAccountMsgRepeatability(const CJson *in)
{
    int32_t opCode;
    if (GetIntFromJson(in, FIELD_OPERATION_CODE, &opCode) != CLIB_SUCCESS) {
        LOGE("Get opCode failed.");
        return HC_ERR_JSON_GET;
    }
    const char *key = NULL;
    if (opCode == OP_BIND) {
        key = FIELD_MESSAGE;
    } else if (opCode == AUTHENTICATE) {
        key = FIELD_STEP;
    } else {
        LOGE("Invalid opCode: %d.", opCode);
        return HC_ERR_INVALID_PARAMS;
    }
    uint32_t message;
    if (GetIntFromJson(in, key, (int32_t *)&message) != CLIB_SUCCESS) {
        LOGD("There is no message code."); // The first message of the client has no message code
        return HC_SUCCESS;
    }
    if ((message & ACCOUNT_CLIENT_STEP_MASK) == ACCOUNT_CLIENT_FIRST_MESSAGE) {
        return HC_SUCCESS;
    }

    LOGI("The message is repeated, ignore it, code: %u", message);
    return HC_ERR_IGNORE_MSG;
}

static int32_t CreateAccountTask(int32_t *taskId, const CJson *in, CJson *out)
{
    if (taskId == NULL || in == NULL || out == NULL) {
        LOGE("Params is null in account task.");
        return HC_ERR_NULL_PTR;
    }
    int32_t res = CheckAccountMsgRepeatability(in);
    if (res != HC_SUCCESS) {
        LOGE("The result of  CheckAccountMsgRepeatability is %x.", res);
        return res;
    }
    AccountMultiTaskManager *authManager = GetAccountMultiTaskManager();
    if (authManager == NULL) {
        LOGE("Get multi auth manager instance failed.");
        return HC_ERROR;
    }
    if (authManager->isTaskNumUpToMax() == true) {
        LOGE("Account auth task is full.");
        return HC_ERR_ACCOUNT_TASK_IS_FULL;
    }
    AccountTask *newTask = CreateAccountTaskT(taskId, in, out);
    if (newTask == NULL) {
        LOGE("Create account related task failed.");
        return HC_ERR_ALLOC_MEMORY;
    }
    res = authManager->addTaskToManager(newTask);
    if (res != HC_SUCCESS) {
        LOGE("Add new task into task manager failed, res: %d.", res);
        newTask->destroyTask(newTask);
    }
    return res;
}

static int32_t ProcessAccountTask(int32_t taskId, const CJson *in, CJson *out, int32_t *status)
{
    AccountMultiTaskManager *authManager = GetAccountMultiTaskManager();
    if (authManager == NULL) {
        LOGE("Get multi auth manager instance failed.");
        return HC_ERROR;
    }
    AccountTask *currentTask = authManager->getTaskFromManager(taskId);
    if (currentTask == NULL) {
        LOGE("Get task from manager failed, taskId: %d.", taskId);
        return HC_ERR_TASK_ID_IS_NOT_MATCH;
    }
    LOGD("Begin process account related task, taskId: %d.", taskId);
    return currentTask->processTask(currentTask, in, out, status);
}

static void DestroyAccountTask(int32_t taskId)
{
    AccountMultiTaskManager *authManager = GetAccountMultiTaskManager();
    if (authManager == NULL) {
        LOGE("Get multi auth manager instance failed.");
        return;
    }
    LOGI("Delete taskId:%d from task manager.", taskId);
    authManager->deleteTaskFromManager(taskId);
}

static int32_t ProcessAsyTokens(int32_t osAccountId, int32_t opCode, CJson *in, CJson *out)
{
    switch (opCode) {
        case IMPORT_SELF_CREDENTIAL:
            return GetAccountAuthTokenManager()->addToken(osAccountId, in, out);
        case DELETE_SELF_CREDENTIAL: {
            const char *userId = GetStringFromJson(in, FIELD_USER_ID);
            if (userId == NULL) {
                LOGE("Failed to get user id.");
                return HC_ERR_JSON_GET;
            }
            return GetAccountAuthTokenManager()->deleteToken(osAccountId, userId);
        }
        case REQUEST_SIGNATURE:
            if (out == NULL) {
                LOGE("Params: out is null.");
                return HC_ERR_NULL_PTR;
            }
            return GetAccountAuthTokenManager()->getRegisterProof(in, out);
        default:
            LOGE("Operation is not supported for: %d.", opCode);
            return HC_ERR_NOT_SUPPORT;
    }
}

static int32_t ProcessSymTokens(int32_t osAccountId, int32_t opCode, CJson *in, CJson *out)
{
    switch (opCode) {
        case IMPORT_SELF_CREDENTIAL:
        case IMPORT_TRUSTED_CREDENTIALS:
            return GetSymTokenManager()->addToken(osAccountId, in);
        case DELETE_SELF_CREDENTIAL:
        case DELETE_TRUSTED_CREDENTIALS: {
            const char *userId = GetStringFromJson(in, FIELD_USER_ID);
            if (userId == NULL) {
                LOGE("Failed to get userId from json!");
                return HC_ERR_JSON_GET;
            }
            const char *deviceId = GetStringFromJson(in, FIELD_DEVICE_ID);
            if (deviceId == NULL) {
                LOGE("Failed to get deviceId from json!");
                return HC_ERR_JSON_GET;
            }
            return GetSymTokenManager()->deleteToken(osAccountId, userId, deviceId);
        }
        default:
            LOGE("Operation is not supported for: %d.", opCode);
            return HC_ERR_NOT_SUPPORT;
    }
}

static void DestroyAccountModule(AuthModuleBase *module)
{
    DestroyAccountMultiTaskManager();
    DestroyTokenManager();
    DestroySymTokenManager();
    DestroyVersionInfos();
    (void)memset_s(module, sizeof(AccountModule), 0, sizeof(AccountModule));
}

AuthModuleBase *CreateAccountModule(void)
{
    g_module.moduleBase.moduleType = ACCOUNT_MODULE;
    g_module.moduleBase.createTask = CreateAccountTask;
    g_module.moduleBase.processTask = ProcessAccountTask;
    g_module.moduleBase.destroyTask = DestroyAccountTask;
    g_module.moduleBase.destroyModule = DestroyAccountModule;

    InitVersionInfos();
    InitAccountMultiTaskManager();
    InitTokenManager();
    InitSymTokenManager();
    return (AuthModuleBase *)&g_module;
}

bool IsAccountSupported(void)
{
    return true;
}

int32_t ProcessAccountCredentials(int32_t osAccountId, int32_t opCode, CJson *in, CJson *out)
{
    if (in == NULL) {
        LOGE("The input param: in is null.");
        return HC_ERR_NULL_PTR;
    }
    int32_t credentialType = INVALID_CRED;
    if (GetIntFromJson(in, FIELD_CREDENTIAL_TYPE, &credentialType) != HC_SUCCESS) {
        LOGE("Failed to get credentialType from json!");
        return HC_ERR_JSON_GET;
    }
    if (credentialType == ASYMMETRIC_CRED) {
        return ProcessAsyTokens(osAccountId, opCode, in, out);
    } else if (credentialType == SYMMETRIC_CRED) {
        return ProcessSymTokens(osAccountId, opCode, in, out);
    } else {
        LOGE("Invalid credential type! [CredType]: %d", credentialType);
        return HC_ERR_NOT_SUPPORT;
    }
}
