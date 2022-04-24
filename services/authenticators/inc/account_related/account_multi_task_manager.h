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

#ifndef ACCOUNT_MULTI_TASK_MANAGER_H
#define ACCOUNT_MULTI_TASK_MANAGER_H

#include "account_task_main.h"

#define ACCOUNT_MULTI_TASK_MAX_SIZE 64

typedef struct {
    int32_t count;
    AccountTask *taskArray[ACCOUNT_MULTI_TASK_MAX_SIZE];
    bool (*isTaskNumUpToMax)(void);
    int32_t (*addTaskToManager)(AccountTask *taskBase);
    AccountTask *(*getTaskFromManager)(int32_t taskId);
    void (*deleteTaskFromManager)(int32_t taskId);
} AccountMultiTaskManager;

#ifdef __cplusplus
extern "C" {
#endif

AccountMultiTaskManager *GetAccountMultiTaskManager(void);

void InitAccountMultiTaskManager(void);

void DestroyAccountMultiTaskManager(void);

#ifdef __cplusplus
}
#endif

#endif
