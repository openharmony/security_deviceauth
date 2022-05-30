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

#ifndef PAKE_V2_AUTH_TASK_COMMON_H
#define PAKE_V2_AUTH_TASK_COMMON_H

#include "json_utils.h"
#include "pake_defs.h"
#include "string_util.h"
#include "account_module_defines.h"
#include "account_task_main.h"
#include "account_version_util.h"

typedef struct {
    PakeBaseParams pakeParams;
    uint64_t versionNo;
    int32_t authForm;
    int32_t osAccountId;
    int32_t authKeyAlgEncode;
    Uint8Buff deviceIdSelf;
    Uint8Buff deviceIdPeer;
    Uint8Buff devIdSelf;
    Uint8Buff devIdPeer;
    uint8_t pkCloud[SERVER_PK_SIZE];
    uint8_t userIdSelf[DEV_AUTH_USER_ID_SIZE];
    uint8_t userIdPeer[DEV_AUTH_USER_ID_SIZE];
    uint8_t pkSelf[PK_SIZE];
    Uint8Buff pkInfoSelf;
    Uint8Buff pkInfoSignSelf;
    uint8_t pkPeer[PK_SIZE];
    Uint8Buff pkInfoPeer;
    Uint8Buff pkInfoSignPeer;
} PakeAuthParams;

#ifdef __cplusplus
extern "C" {
#endif
bool IsPakeV2AuthTaskSupported(void);

TaskBase *CreatePakeV2AuthTask(const CJson *in, CJson *out, const AccountVersionInfo *verInfo);

int32_t VerifyPkSignPeer(const PakeAuthParams *params);

int32_t GenerateEcdhSharedKey(PakeAuthParams *params);

int32_t GetPkInfoPeer(PakeAuthParams *params, const CJson *in);

int32_t InitPakeAuthParams(const CJson *in, PakeAuthParams *params, const AccountVersionInfo *verInfo);

void DestroyPakeAuthParams(PakeAuthParams *params);

int32_t ExtractPakePeerId(PakeAuthParams *params, const CJson *in);

int32_t ExtractPakeSelfId(PakeAuthParams *params);

int32_t ExtractSelfDeviceId(PakeAuthParams *params, const CJson *in, bool useSelfPrefix);

int32_t ExtractPeerDeviceId(PakeAuthParams *params, const CJson *in);

int32_t ExtractSelfDevId(PakeAuthParams *params, const CJson *in);

int32_t ExtractPeerDevId(PakeAuthParams *params, const CJson *in);

#ifdef __cplusplus
}
#endif

#endif
