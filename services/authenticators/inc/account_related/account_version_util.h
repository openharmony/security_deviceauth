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

#ifndef ACCOUNT_VERSION_UTIL_H
#define ACCOUNT_VERSION_UTIL_H

#include "alg_defs.h"
#include "json_utils.h"
#include "pake_defs.h"
#include "protocol_common.h"
#include "account_task_main.h"

typedef enum {
    BIND_VERSION_NO_NONE = 0,
    BIND_PAKE_V2_DL = 0x0001,
    BIND_PAKE_V2_EC_P256 = 0x0002,
    BIND_PAKE_V2_EC_P256_WITH_PROOF = 0x0004,
    BIND_PAKE_V2_EC_X25519 = 0x0008,
    BIND_PAKE_V1_DL = 0x0010,
} BindVersionNo;

typedef enum {
    AUTH_VERSION_NO_NONE = 0,
    AUTH_PAKE_V2_EC_P256 = 0x0001,
    AUTH_ISO = 0x0002,
} AuthVersionNo;

typedef enum {
    VERSION_INITIAL = 0,
    VERSION_NEGOTIATION = 1,
    VERSION_CONFIRMED = 2,
} AccountVersionStatus;

typedef struct _AccountVersionInfo {
    uint64_t versionNo;
    ProtocolType protocolType;
    PakeAlgType pakeAlgType;
    CurveType curveType;
    bool withExtraOperation;
    bool (*isTaskSupported)(void);
    TaskBase *(*createTask)(const CJson *, CJson *, const struct _AccountVersionInfo *);
} AccountVersionInfo;

void InitVersionInfos(void);
void DestroyVersionInfos(void);
uint64_t GetSupportedVersionNo(int32_t operationCode);
const AccountVersionInfo *GetNegotiatedVersionInfo(int32_t operationCode, uint64_t versionNo);

#endif
