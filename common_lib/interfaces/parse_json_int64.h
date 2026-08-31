/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PARSE_JSON_INT64_H
#define PARSE_JSON_INT64_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Parse a decimal int64 from an untrusted JSON string field.
 * Whole-token: reject empty, overflow, leftover junk such as "123abc",
 * leading whitespace, '+', hex, and floats. A leading '-' is allowed.
 */
bool ParseJsonInt64(const char *text, int64_t *out);

#ifdef __cplusplus
}
#endif

#endif /* PARSE_JSON_INT64_H */
