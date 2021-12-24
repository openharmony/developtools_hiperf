/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef HIPERF_HILOG
#define HIPERF_HILOG

#ifndef CONFIG_NO_HILOG
#define HILOG_PUBLIC  "{public}"
#define HILOG_NEWLINE ""
#else
#define HILOG_PUBLIC  ""
#define HILOG_NEWLINE "\n"
#endif

#define FILENAME                                                                                   \
    (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

#define FORMATED(fmt, ...)                                                                         \
    "[%" HILOG_PUBLIC "s:%" HILOG_PUBLIC "d] %" HILOG_PUBLIC "s# " fmt HILOG_NEWLINE, FILENAME,    \
        __LINE__, __FUNCTION__, ##__VA_ARGS__

#ifndef CONFIG_NO_HILOG
#include "hilog/log.h"

#ifdef HIPERF_HILOGF
#undef HIPERF_HILOGF
#endif

#ifdef HIPERF_HILOGE
#undef HIPERF_HILOGE
#endif

#ifdef HIPERF_HILOGW
#undef HIPERF_HILOGW
#endif

#ifdef HIPERF_HILOGI
#undef HIPERF_HILOGI
#endif

#ifdef HIPERF_HILOGD
#undef HIPERF_HILOGD
#endif

// param of log interface, such as HIPERF_HILOGF.
enum HiperfModule {
    MODULE_DEFAULT = 0,
    MODULE_JS_NAPI,
    MODULE_CPP_API,
};

static constexpr unsigned int BASE_HIPERF_DOMAIN_ID = 0xD000000;
static constexpr unsigned int BYTRACE_TAG = 0xd03301;

static constexpr OHOS::HiviewDFX::HiLogLabel HIPERF_HILOG_LABLE[] = {
    {LOG_CORE, BYTRACE_TAG, "hiperf"},
    {LOG_CORE, BYTRACE_TAG, "HiperfJSNAPI"},
    {LOG_CORE, BYTRACE_TAG, "HiperfCPPAPI"},
};

// In order to improve performance, do not check the module range

#define HIPERF_HILOGF(module, ...)                                                                 \
    (void)OHOS::HiviewDFX::HiLog::Fatal(HIPERF_HILOG_LABLE[module], FORMATED(__VA_ARGS__))
#define HIPERF_HILOGE(module, ...)                                                                 \
    (void)OHOS::HiviewDFX::HiLog::Error(HIPERF_HILOG_LABLE[module], FORMATED(__VA_ARGS__))
#define HIPERF_HILOGW(module, ...)                                                                 \
    (void)OHOS::HiviewDFX::HiLog::Warn(HIPERF_HILOG_LABLE[module], FORMATED(__VA_ARGS__))
#define HIPERF_HILOGI(module, ...)                                                                 \
    (void)OHOS::HiviewDFX::HiLog::Info(HIPERF_HILOG_LABLE[module], FORMATED(__VA_ARGS__))
#define HIPERF_HILOGD(module, ...)                                                                 \
    (void)OHOS::HiviewDFX::HiLog::Debug(HIPERF_HILOG_LABLE[module], FORMATED(__VA_ARGS__))
#else

#define HIPERF_HILOGF(module, ...) printf(FORMATED(__VA_ARGS__))
#define HIPERF_HILOGE(module, ...) printf(FORMATED(__VA_ARGS__))
#define HIPERF_HILOGW(module, ...) printf(FORMATED(__VA_ARGS__))
#define HIPERF_HILOGI(module, ...) printf(FORMATED(__VA_ARGS__))
#define HIPERF_HILOGD(module, ...) printf(FORMATED(__VA_ARGS__))

#endif // CONFIG_NO_HILOG

#endif // HIPERF_HILOG
