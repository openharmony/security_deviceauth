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

#ifndef SYM_TOKEN_MANAGER_H
#define SYM_TOKEN_MANAGER_H

#include <stdint.h>
#include "account_module_defines.h"
#include "common_defs.h"
#include "string_util.h"

typedef struct {
    char userId[DEV_AUTH_USER_ID_SIZE];
    char deviceId[DEV_AUTH_DEVICE_ID_SIZE];
    int32_t authCodeId;
} SymToken;
DECLARE_HC_VECTOR(SymTokenVec, SymToken*)

typedef struct {
    int32_t (*addToken)(int32_t osAccountId, CJson *in);
    int32_t (*deleteToken)(int32_t osAccountId, const char *userId, const char *deviceId);
} SymTokenManager;

#ifdef __cplusplus
extern "C" {
#endif

SymTokenManager *GetSymTokenManager(void);

void InitSymTokenManager(void);
void DestroySymTokenManager(void);

SymTokenVec CreateSymTokenVec(void);
void ClearSymTokenVec(SymTokenVec *vec);

#ifdef __cplusplus
}
#endif

#endif