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

#include "deviceauth_standard_test.h"
#include <ctime>
#include <cstdint>
#include "common_defs.h"
#include "deviceauth_test_mock.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "json_utils.h"

using namespace std;
using namespace testing::ext;

/* test suit - GET_INSTANCE */
class GET_INSTANCE : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    virtual void SetUp()
    {
        int32_t ret = InitDeviceAuthService();
        EXPECT_EQ(ret == HC_SUCCESS, true);
    }
    virtual void TearDown()
    {
        DestroyDeviceAuthService();
    }
};

/* start cases */
TEST_F(GET_INSTANCE, TC_GET_GM_INSTANCE)
{
    const DeviceGroupManager *gm = GetGmInstance();
    EXPECT_NE(gm, nullptr);
}

TEST_F(GET_INSTANCE, TC_GET_GA_INSTANCE)
{
    const GroupAuthManager *ga = GetGaInstance();
    EXPECT_NE(ga, nullptr);
}
