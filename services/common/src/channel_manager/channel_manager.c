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

#include "channel_manager.h"

#include "callback_manager.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_types.h"
#include "soft_bus_channel.h"

int32_t InitChannelManager(void)
{
    return IsSoftBusChannelSupported() ? InitSoftBusChannelModule() : HC_SUCCESS;
}

void DestroyChannelManager(void)
{
    if (IsSoftBusChannelSupported()) {
        DestroySoftBusChannelModule();
    }
}

ChannelType GetChannelType(const DeviceAuthCallback *callback)
{
    if ((callback != NULL) && (callback->onTransmit != NULL)) {
        return SERVICE_CHANNEL;
    }
    return IsSoftBusChannelSupported() ? SOFT_BUS : NO_CHANNEL;
}

bool CanFindValidChannel(ChannelType channelType, const CJson *jsonParams, const DeviceAuthCallback *callback)
{
    if (channelType == SERVICE_CHANNEL) {
        if ((callback == NULL) || (callback->onTransmit != NULL)) {
            LOGE("The service channel is unavailable!");
            return false;
        }
        return true;
    } else if (channelType == SOFT_BUS) {
        const char *connectParams = GetStringFromJson(jsonParams, FIELD_CONNECT_PARAMS);
        if (connectParams == NULL) {
            LOGE("Failed to get connectParams from jsonParams!");
            return false;
        }
        return true;
    } else {
        LOGE("No channel is available!");
        return false;
    }
}

int32_t OpenChannel(ChannelType channelType, const CJson *jsonParams, int64_t requestId, int64_t *returnChannelId)
{
    if (channelType == SERVICE_CHANNEL) {
        *returnChannelId = DEFAULT_CHANNEL_ID;
        return HC_SUCCESS;
    } else if (channelType == SOFT_BUS) {
        const char *connectParams = GetStringFromJson(jsonParams, FIELD_CONNECT_PARAMS);
        if (connectParams == NULL) {
            LOGE("Failed to get connectParams from jsonParams!");
            return HC_ERR_JSON_GET;
        }
        int64_t channelId = DEFAULT_CHANNEL_ID;
        int32_t result = GetSoftBusInstance()->openChannel(connectParams, requestId, &channelId);
        if (result != HC_SUCCESS) {
            return HC_ERR_CHANNEL_NOT_EXIST;
        }
        *returnChannelId = channelId;
        return HC_SUCCESS;
    } else {
        return HC_ERR_CHANNEL_NOT_EXIST;
    }
}

void CloseChannel(ChannelType channelType, int64_t channelId)
{
    if (channelType == SOFT_BUS) {
        GetSoftBusInstance()->closeChannel(channelId);
    }
}

int32_t SendMsg(ChannelType channelType, int64_t requestId, int64_t channelId,
    const DeviceAuthCallback *callback, const char *data)
{
    if (channelType == SERVICE_CHANNEL) {
        if (ProcessTransmitCallback(requestId, (uint8_t *)data, HcStrlen(data) + 1, callback)) {
            return HC_SUCCESS;
        }
        return HC_ERR_TRANSMIT_FAIL;
    } else if (channelType == SOFT_BUS) {
        return GetSoftBusInstance()->sendMsg(channelId, (uint8_t *)data, HcStrlen(data) + 1);
    } else {
        return HC_ERR_CHANNEL_NOT_EXIST;
    }
}

void SetAuthResult(ChannelType channelType, int64_t channelId)
{
    if (channelType == SOFT_BUS) {
        GetSoftBusInstance()->notifyResult(channelId);
    }
}

int32_t GetLocalConnectInfo(char *jsonAddrInfo, int32_t bufLen)
{
    if ((jsonAddrInfo == NULL) || (bufLen == 0) || (bufLen > MAX_DATA_BUFFER_SIZE)) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGD("[Start]: GetLocalConnectInfo!");
    if (!IsSoftBusChannelSupported()) {
        LOGE("Soft bus not supported!");
        return HC_ERR_NOT_SUPPORT;
    }
    int32_t res = GetSoftBusInstance()->getLocalConnectInfo(jsonAddrInfo, bufLen);
    LOGD("[End]: GetLocalConnectInfo!");
    return res == HC_SUCCESS ? HC_SUCCESS : HC_ERR_SOFT_BUS;
}
