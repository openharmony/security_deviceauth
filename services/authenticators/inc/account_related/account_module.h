/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef ACCOUNT_MODULE_H
#define ACCOUNT_MODULE_H

#include "dev_auth_module_manager.h"
#include "json_utils.h"

typedef enum {
    IMPORT_SELF_CREDENTIAL = 0,
    DELETE_SELF_CREDENTIAL = 1,
    QUERY_SELF_CREDENTIAL_INFO = 2,
    IMPORT_TRUSTED_CREDENTIALS = 3,
    DELETE_TRUSTED_CREDENTIALS = 4,
    QUERY_TRUSTED_CREDENTIALS = 5,
    REQUEST_SIGNATURE = 6,
} CredentialCode;

int32_t CheckAccountMsgRepeatability(const CJson *in);
bool IsAccountSupported(void);
AuthModuleBase *CreateAccountModule(void);
int32_t ProcessAccountCredentials(int32_t osAccountId, int32_t opCode, CJson *in, CJson *out);

#endif
