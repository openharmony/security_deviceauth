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

#ifndef HC_LOG_H
#define HC_LOG_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif
const char *HcFmtLogData(const char *funName, char *out, int32_t outSz, const char *fmtStr, ...);

#ifdef __cplusplus
}
#endif

#ifdef HILOG_ENABLE

#include "hilog/log.h"

#ifndef LITE_DEVICE
#define DEVAUTH_FMT_BUFFSZ 1024

#define LOGD(fmt, ...) do { \
    char fmtCache[DEVAUTH_FMT_BUFFSZ]; \
    fmtCache[0] = 0; \
    const char *fmtInfo = HcFmtLogData(__FUNCTION__, fmtCache, sizeof(fmtCache), fmt, ##__VA_ARGS__); \
    fmtInfo ? (void)HiLogPrint(LOG_CORE, LOG_DEBUG, LOG_DOMAIN, "[DEVAUTH]", "%{public}s", fmtCache) : \
        (void)HiLogPrint(LOG_CORE, LOG_DEBUG, LOG_DOMAIN, \
            "[DEVAUTH]", "%{public}s: " fmt, __FUNCTION__, ##__VA_ARGS__); \
} while (0)

#define LOGE(fmt, ...) do { \
    char fmtCache[DEVAUTH_FMT_BUFFSZ]; \
    fmtCache[0] = 0; \
    const char *fmtInfo = HcFmtLogData(__FUNCTION__, fmtCache, sizeof(fmtCache), fmt, ##__VA_ARGS__); \
    fmtInfo ? (void)HiLogPrint(LOG_CORE, LOG_ERROR, LOG_DOMAIN, "[DEVAUTH]", "%{public}s", fmtCache) : \
        (void)HiLogPrint(LOG_CORE, LOG_ERROR, LOG_DOMAIN, \
            "[DEVAUTH]", "%{public}s: " fmt, __FUNCTION__, ##__VA_ARGS__); \
} while (0)

#define LOGI(fmt, ...) do { \
    char fmtCache[DEVAUTH_FMT_BUFFSZ]; \
    fmtCache[0] = 0; \
    const char *fmtInfo = HcFmtLogData(__FUNCTION__, fmtCache, sizeof(fmtCache), fmt, ##__VA_ARGS__); \
    fmtInfo ? (void)HiLogPrint(LOG_CORE, LOG_INFO, LOG_DOMAIN, "[DEVAUTH]", "%{public}s", fmtCache) : \
        (void)HiLogPrint(LOG_CORE, LOG_INFO, LOG_DOMAIN, \
            "[DEVAUTH]", "%{public}s: " fmt, __FUNCTION__, ##__VA_ARGS__); \
} while (0)

#define LOGW(fmt, ...) do { \
    char fmtCache[DEVAUTH_FMT_BUFFSZ]; \
    fmtCache[0] = 0; \
    const char *fmtInfo = HcFmtLogData(__FUNCTION__, fmtCache, sizeof(fmtCache), fmt, ##__VA_ARGS__); \
    fmtInfo ? (void)HiLogPrint(LOG_CORE, LOG_WARN, LOG_DOMAIN, "[DEVAUTH]", "%{public}s", fmtCache) : \
        (void)HiLogPrint(LOG_CORE, LOG_WARN, LOG_DOMAIN, \
            "[DEVAUTH]", "%{public}s: " fmt, __FUNCTION__, ##__VA_ARGS__); \
} while (0)
#else
#define LOGD(fmt, ...) ((void)HiLogPrint(LOG_CORE, LOG_DEBUG, LOG_DOMAIN, \
    "[DEVAUTH]", "%{public}s: " fmt, __FUNCTION__, ##__VA_ARGS__))
#define LOGE(fmt, ...) ((void)HiLogPrint(LOG_CORE, LOG_ERROR, LOG_DOMAIN, \
    "[DEVAUTH]", "%{public}s: " fmt, __FUNCTION__, ##__VA_ARGS__))
#define LOGI(fmt, ...) ((void)HiLogPrint(LOG_CORE, LOG_INFO, LOG_DOMAIN, \
    "[DEVAUTH]", "%{public}s: " fmt, __FUNCTION__, ##__VA_ARGS__))
#define LOGW(fmt, ...) ((void)HiLogPrint(LOG_CORE, LOG_WARN, LOG_DOMAIN, \
    "[DEVAUTH]", "%{public}s: " fmt, __FUNCTION__, ##__VA_ARGS__))
#endif

#else

#include <stdio.h>
#include <stdlib.h>

#define LOGD(fmt, ...) printf("[D][DEVAUTH]%s: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOGE(fmt, ...) printf("[E][DEVAUTH]%s: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOGI(fmt, ...) printf("[I][DEVAUTH]%s: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOGW(fmt, ...) printf("[W][DEVAUTH]%s: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#endif

#endif
