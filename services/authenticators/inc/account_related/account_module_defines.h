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

#ifndef ACCOUNT_MODULE_DEFINES_H
#define ACCOUNT_MODULE_DEFINES_H

#define SEED_SIZE 32
#define USER_ID_SIZE 65
#define PK_SIZE 128
#define PK_VERSION_SIZE 256
#define DEVICE_ID_SIZE 256
#define SIGNATURE_SIZE 128
#define PUBLIC_KEY_INFO_SIZE 1024
#define SERVER_PK_SIZE 128

typedef enum {
    TASK_TYPE_DEFAULT = 0,
    TASK_TYPE_PAKE_V2_AUTH_CLIENT = 5,
    TASK_TYPE_PAKE_V2_AUTH_SERVER = 6,
    TASK_TYPE_ISO_AUTH_CLIENT = 7,
    TASK_TYPE_ISO_AUTH_SERVER = 8,
} AccountTaskType;

typedef enum {
    CMD_PAKE_AUTH_MAIN_ONE = 0x0030,
    RET_PAKE_AUTH_FOLLOWER_ONE = 0x0031,
    CMD_PAKE_AUTH_MAIN_TWO = 0x0032,
    RET_PAKE_AUTH_FOLLOWER_TWO = 0x0033,
    ERR_MSG = 0x8080,
} MessageStepCode;

typedef enum {
    ALG_ECC = 0x0000,
    ALG_RSA = 0x0001,
    ALG_HKDF = 0x0002,
    ALG_HMAC = 0x0003,
    ALG_AES = 0x0004,
    ALG_PBKDF2 = 0x0005,
    ALG_ECDH = 0x0006,
    ALG_X25519 = 0x0007,
    ALG_ED25519 = 0x0008,
} KeyAlgEncode;

#endif