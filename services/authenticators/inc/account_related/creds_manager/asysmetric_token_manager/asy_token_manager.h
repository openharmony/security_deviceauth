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

#ifndef ASY_TOKEN_MANAGER_H
#define ASY_TOKEN_MANAGER_H

#include <stdint.h>
#include "alg_defs.h"
#include "common_defs.h"
#include "string_util.h"

#define SELF_ECC_KEY_LEN 32

#define COPY_STRING_GOTO_ERR_IF_FAIL(src, dest, tag) \
    do { \
        if ((src) == NULL) { \
            LOGE("%s is NULL", tag); \
            goto ERR; \
        } \
        if (memcpy_s((dest), sizeof(dest), src, HcStrlen(src) + 1) != EOK) { \
            LOGE("%s copy failed", tag); \
            goto ERR; \
        } \
    } while (0)

typedef struct {
    Uint8Buff version;
    Uint8Buff userId;
    Uint8Buff deviceId;
    Uint8Buff devicePk;
} PkInfo;

typedef struct {
    Uint8Buff pkInfoStr;
    PkInfo pkInfo;
    Uint8Buff pkInfoSignature;
    Uint8Buff serverPk;
} AccountToken;
DECLARE_HC_VECTOR(AccountTokenVec, AccountToken*)

typedef struct {
    int32_t (*addToken)(int32_t osAccountId, const CJson *in, CJson *out);
    int32_t (*getToken)(int32_t osAccountId, AccountToken *token, const char *userId);
    int32_t (*deleteToken)(int32_t osAccountId, const char *userId);
    int32_t (*getRegisterProof)(const CJson *in, CJson *out);
    int32_t (*getServerPublicKey)(int32_t osAccountId, const char *userId, Uint8Buff *serverPk);
    int32_t (*generateKeyAlias)(const char *userId, const char *deviceId,
        Uint8Buff *keyAlias, bool isServerPkAlias);
    Algorithm (*getAlgVersion)(int32_t osAccountId, const char *userId);
} AccountAuthTokenManager;

#ifdef __cplusplus
extern "C" {
#endif

AccountAuthTokenManager *GetAccountAuthTokenManager(void);

void InitTokenManager(void);
void DestroyTokenManager(void);

AccountToken *CreateAccountToken(void);
void DestroyAccountToken(AccountToken *token);

AccountTokenVec CreateAccountTokenVec(void);
void ClearAccountTokenVec(AccountTokenVec *vec);

#ifdef __cplusplus
}
#endif

#endif