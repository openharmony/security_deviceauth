/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "hks_types.h"
#include "hks_file_api.h"
#include "hks_hardware_api.h"
#include "huks_adapter.h"
#include "hichain.h"
#include "securec.h"
#include "pake_server.h"
#include "sts_server.h"
#include "parsedata.h"

#define AUTH_AD_MAX_NUM10
#define LOG(format,...) (printf(format"\n",##__VA_ARGS__))

using namespace std;
using namespace testing::ext;

namespace {
const int KEY_LEN = 32;

class DeviceAuthTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DeviceAuthTest::SetUpTestCase(void)
{
}

void DeviceAuthTest::TearDownTestCase(void)
{
}

void DeviceAuthTest::SetUp()
{
}

void DeviceAuthTest::TearDown()
{
}

static struct session_identity serverIdentity = {
    0,
    {strlen("testServer"), "testServer"},
    {strlen("testServer"), "testServer"},
    0
};
static struct hc_pin testPin = {strlen("123456789012345"), "123456789012345"};
static struct hc_auth_id testClientAuthId = {strlen("authClient"), "authClient"};
static struct hc_auth_id testServerAuthId = {strlen("authServer"), "authServer"};

static void Transmit(const struct session_identity *identity, const void *data, uint32_t length)
{
    LOG("--------Transmit--------");
    LOG("identity session_id[%d] package_name[%s]", identity->session_id, identity->package_name.name);
    LOG("data[%s]", data);
    LOG("length[%d]", length);
    LOG("--------Transmit--------");
}

static void GetProtocolParams(const struct session_identity *identity, int32_t operationCode,
    struct hc_pin *pin, struct operation_parameter *para)
{
    LOG("--------GetProtocolParams--------");
    LOG("identity session_id[%d] package_name[%s]", identity->session_id, identity->package_name.name);
    LOG("operationCode[%d]", operationCode);
    *pin = testPin;
    para->self_auth_id = testServerAuthId;
    para->peer_auth_id = testClientAuthId;
    para->key_length = KEY_LEN;
    LOG("--------GetProtocolParams--------");
}

static void SetSessionKey(const struct session_identity *identity, const struct hc_session_key *sessionKey)
{
    LOG("--------SetSessionKey--------");
    LOG("identity session_id[%d] package_name[%s]", identity->session_id, identity->package_name.name);
    LOG("sessionKey[%s]", sessionKey->session_key);
    LOG("--------SetSessionKey--------");
}

static void SetServiceResult(const struct session_identity *identity, int32_t result)
{
    LOG("--------SetServiceResult--------");
    LOG("identity session_id[%d] package_name[%s]", identity->session_id, identity->package_name.name);
    LOG("result[%d]", result);
    LOG("--------SetServiceResult--------");
}

static int32_t ConfirmReceiveRequest(const struct session_identity *identity, int32_t operationCode)
{
    LOG("--------ConfirmReceiveRequest--------");
    LOG("identity session_id[%d] package_name[%s]", identity->session_id, identity->package_name.name);
    LOG("operationCode[%d]", operationCode);
    LOG("--------ConfirmReceiveRequest--------");
    return HC_OK;
}

static int32_t FileRead(const char *fileName, uint32_t offset, uint8_t *buf, uint32_t len)
{
    (void)offset;
    FILE *fp = NULL;
    size_t size;

    if (fileName == NULL || buf == NULL) {
        return -1;
    }

    fp = fopen(fileName, "rb");
    if (fp == NULL) {
        return -1;
    }

    size = fread(buf, 1, (size_t)len, fp);
    fclose(fp);

    if (size == 0) {
        return -1;
    }

    return (int32_t)size;
}

static int32_t FileWrite(const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len)
{
    (void)offset;
    printf("FileWrite begin\n");
    FILE *fp = NULL;
    size_t size;

    if (fileName == NULL || buf == NULL) {
        printf("FileWrite fileName or buf is null\n");
        return -1;
    }

    fp = fopen(fileName, "wb+");
    if (fp == NULL) {
        return -1;
    }

    size = fwrite(buf, 1, (uint32_t)len, fp);
    printf("FileWrite size = %d\n", size);
    fclose(fp);

    if (size != len) {
        return -1;
    }

    return ERROR_CODE_SUCCESS;
}

static int32_t FileSize(const char *fileName)
{
    FILE *fp = NULL;
    int32_t size;

    if (fileName == NULL) {
        return -1;
    }

    fp = fopen(fileName, "rb");
    if (fp == NULL) {
        return -1;
    }

    if (fseek(fp, 0L, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    size = ftell(fp);
    fclose(fp);

    return size;
}

static int32_t HksStorageTestRegisterFileCallbacks()
{
    int32_t status;
    struct hks_file_callbacks fileCallbacks;

    fileCallbacks.read = FileRead;
    fileCallbacks.write = FileWrite;
    fileCallbacks.file_size = FileSize;

    status = hks_register_file_callbacks(&fileCallbacks);

    return (int32_t)status;
}

static int32_t GetHardwareUdidCallback(uint8_t *udid, uint32_t udidLen)
{
    uint32_t len = strlen("abcdabcd");
    if (memcpy_s(udid, udidLen, "abcdabcd", len) != 0) {
        return -1;
    }
    return 0;
}

static int32_t HksTestRegisterGetHardwareUdidCallback()
{
    int32_t status = hks_register_get_hardware_udid_callback(&GetHardwareUdidCallback);
    return status;
}

static hc_handle GetInstance(const struct session_identity *identity, enum hc_type type,
    const struct hc_call_back *callBack)
{
    (void)HksStorageTestRegisterFileCallbacks();
    (void)HksTestRegisterGetHardwareUdidCallback();
    hc_handle handle = get_instance(identity, type, callBack);
    return handle;
}

static HWTEST_F(DeviceAuthTest, Test001, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test001--------");
    LOG("--------get_instance--------");
    struct hc_call_back callBack = {
        Transmit,
	GetProtocolParams,
	SetSessionKey,
	SetServiceResult,
	ConfirmReceiveRequest
    };
    hc_handle server = GetInstance(&serverIdentity, HC_ACCESSORY, &callBack);
    ASSERT_TRUE(server != NULL);
    destroy(&server);
    LOG("--------DeviceAuthTest Test001--------");
}

static HWTEST_F(DeviceAuthTest, Test002, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test002--------");
    LOG("--------start_pake--------");
    struct hc_call_back callBack = {
        Transmit,
	GetProtocolParams,
	SetSessionKey,
	SetServiceResult,
	ConfirmReceiveRequest
    };
    hc_handle server = GetInstance(&serverIdentity, HC_ACCESSORY, &callBack);
    const struct operation_parameter params = {testServerAuthId, testClientAuthId, KEY_LEN};
    int32_t ret = start_pake(server, &params);
    ASSERT_EQ(ret, HC_OK);
    destroy(&server);
    LOG("--------DeviceAuthTest Test002--------");
}

static HWTEST_F(DeviceAuthTest, Test003, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test003--------");
    LOG("--------is_trust_peer--------");
    struct hc_call_back callBack = {
        Transmit,
	GetProtocolParams,
	SetSessionKey,
	SetServiceResult,
	ConfirmReceiveRequest
    };
    hc_handle server = GetInstance(&serverIdentity, HC_ACCESSORY, &callBack);
    struct hc_user_info userInfo = {testServerAuthId, 1};
    int32_t ret = is_trust_peer(server, &userInfo);
    ASSERT_EQ(ret, HC_OK);
    destroy(&server);
    LOG("--------DeviceAuthTest Test003--------");
}
}
