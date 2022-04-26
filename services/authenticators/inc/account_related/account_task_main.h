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

#ifndef ACCOUNT_TASK_MAIN_H
#define ACCOUNT_TASK_MAIN_H

#include "json_utils.h"
#include "account_module_defines.h"

typedef struct TaskBaseT {
    AccountTaskType (*getTaskType)(void);
    void (*destroyTask)(struct TaskBaseT *);
    int32_t (*process)(struct TaskBaseT *, const CJson *in, CJson *out, int32_t *status);
    int32_t taskStatus;
} TaskBase;

typedef struct AccountTaskT {
    int32_t taskId;
    void (*destroyTask)(struct AccountTaskT *);
    int32_t (*processTask)(struct AccountTaskT *, const CJson *in, CJson *out, int32_t *status);
    int32_t versionStatus;
    TaskBase *subTask;
} AccountTask;

AccountTask *CreateAccountTaskT(int32_t *taskId, const CJson *in, CJson *out);

#endif
