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

#ifndef PAKE_V2_AUTH_CLIENT_TASK_H
#define PAKE_V2_AUTH_CLIENT_TASK_H

#include "json_utils.h"
#include "pake_v2_auth_task_common.h"
#include "account_task_main.h"
#include "account_version_util.h"

typedef struct {
    TaskBase taskBase;
    PakeAuthParams params;
} PakeV2AuthClientTask;

#ifdef __cplusplus
extern "C" {
#endif

TaskBase *CreatePakeV2AuthClientTask(const CJson *in, CJson *out, const AccountVersionInfo *verInfo);

#ifdef __cplusplus
}
#endif

#endif