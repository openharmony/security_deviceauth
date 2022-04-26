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

#include "account_multi_task_manager.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_types.h"

static AccountMultiTaskManager g_taskManager;

static bool IsManagerHasTaskId(int32_t taskId)
{
    for (uint32_t i = 0; i < ACCOUNT_MULTI_TASK_MAX_SIZE; ++i) {
        if (g_taskManager.taskArray[i] != NULL && taskId == g_taskManager.taskArray[i]->taskId) {
            LOGD("Task already exists, taskId: %d.", taskId);
            return true;
        }
    }
    LOGD("Multi auth manager do not has task id(%d).", taskId);
    return false;
}

static bool IsTaskNumUpToMax(void)
{
    if (g_taskManager.count >= ACCOUNT_MULTI_TASK_MAX_SIZE) {
        LOGD("The number of tasks reaches maximun.");
        return true;
    }
    return false;
}

static bool CanAddTaskInManager(int32_t taskId)
{
    if (IsTaskNumUpToMax()) {
        LOGE("Task number is up to limit.");
        return false;
    }
    if (IsManagerHasTaskId(taskId)) {
        LOGE("Task id is already in exist.");
        return false;
    }
    return true;
}

static int32_t AddTaskToManager(AccountTask *task)
{
    if (task == NULL) {
        LOGE("Task is null.");
        return HC_ERR_NULL_PTR;
    }

    if (!CanAddTaskInManager(task->taskId)) {
        LOGE("Can not add task into manager.");
        return HC_ERR_ADD_ACCOUNT_TASK;
    }
    for (uint32_t i = 0; i < ACCOUNT_MULTI_TASK_MAX_SIZE; ++i) {
        if (g_taskManager.taskArray[i] == NULL) {
            g_taskManager.taskArray[i] = task;
            g_taskManager.count++;
            return HC_SUCCESS;
        }
    }
    LOGE("There is no empty space in the task manager.");
    return HC_ERR_OUT_OF_LIMIT;
}

static AccountTask *GetTaskFromManager(int32_t taskId)
{
    for (uint32_t i = 0; i < ACCOUNT_MULTI_TASK_MAX_SIZE; ++i) {
        if ((g_taskManager.taskArray[i] != NULL) && (g_taskManager.taskArray[i]->taskId == taskId)) {
            return g_taskManager.taskArray[i];
        }
    }
    LOGE("Task does not exist, taskId: %d.", taskId);
    return NULL;
}

static void DeleteTaskFromManager(int32_t taskId)
{
    for (uint32_t i = 0; i < ACCOUNT_MULTI_TASK_MAX_SIZE; ++i) {
        if ((g_taskManager.taskArray[i] != NULL) && (g_taskManager.taskArray[i]->taskId == taskId)) {
            g_taskManager.taskArray[i]->destroyTask(g_taskManager.taskArray[i]);
            g_taskManager.taskArray[i] = NULL;
            g_taskManager.count--;
        }
    }
}

void InitAccountMultiTaskManager(void)
{
    DestroyAccountMultiTaskManager();
    g_taskManager.count = 0;
    g_taskManager.isTaskNumUpToMax = IsTaskNumUpToMax;
    g_taskManager.addTaskToManager = AddTaskToManager;
    g_taskManager.getTaskFromManager = GetTaskFromManager;
    g_taskManager.deleteTaskFromManager = DeleteTaskFromManager;
}

AccountMultiTaskManager *GetAccountMultiTaskManager(void)
{
    return &g_taskManager;
}

void DestroyAccountMultiTaskManager(void)
{
    for (uint32_t i = 0; i < ACCOUNT_MULTI_TASK_MAX_SIZE; ++i) {
        if (g_taskManager.taskArray[i] != NULL) {
            if (g_taskManager.taskArray[i]->destroyTask != NULL) {
                g_taskManager.taskArray[i]->destroyTask(g_taskManager.taskArray[i]);
            }
            g_taskManager.taskArray[i] = NULL;
        }
    }
    (void)memset_s(&g_taskManager, sizeof(AccountMultiTaskManager), 0, sizeof(AccountMultiTaskManager));
}