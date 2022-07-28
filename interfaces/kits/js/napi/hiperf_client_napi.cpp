/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "hiperf_client_napi.h"
#include <cstdio>
#include <string>
#include "hiperf_hilog.h"
#include "hiperf_client.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
namespace HiperfClient {
static std::unique_ptr<HiperfClient::Client> g_hiperfClient =
    std::make_unique<HiperfClient::Client>();

static std::unique_ptr<HiperfClient::RecordOption> g_hiperfRecordOption =
    std::make_unique<HiperfClient::RecordOption>();

static std::vector<std::string> StringSplit(std::string source, std::string split = ",")
{
    size_t pos = 0;
    std::vector<std::string> result;

    // find
    while ((pos = source.find(split)) != std::string::npos) {
        // split
        std::string token = source.substr(0, pos);
        if (!token.empty()) {
            result.push_back(token);
        }
        source.erase(0, pos + split.length());
    }
    // add last token
    if (!source.empty()) {
        result.push_back(source);
    }
    return result;
}

static std::vector<int> StringSplitToInt(std::string source, std::string split = ",")
{
    size_t pos = 0;
    std::vector<int> result;

    // find
    while ((pos = source.find(split)) != std::string::npos) {
        // split
        std::string token = source.substr(0, pos);
        if (!token.empty()) {
            result.push_back(std::stoi(token));
        }
        source.erase(0, pos + split.length());
    }
    // add last token
    if (!source.empty()) {
        result.push_back(std::stoi(source));
    }
    return result;
}

static std::string GetJsStringFromOption(const napi_env &env, const napi_callback_info &info)
{
    size_t argc = 1;
    napi_value args[1] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr), "");
    NAPI_ASSERT_BASE(env, argc == 1, "requires 1 parameter", "");

    napi_valuetype inputType = napi_undefined;
    napi_typeof(env, args[0], &inputType);
    NAPI_ASSERT_BASE(env, inputType == napi_string, "type mismatch for parameter path", "");

    char value[PATH_MAX] = {0};
    size_t valueLen = 0;
    napi_get_value_string_utf8(env, args[0], value, sizeof(value), &valueLen);
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}s", value);
    return std::string(value);
}

static bool GetBoolFromOption(const napi_env &env, const napi_callback_info &info)
{
    size_t argc = 1;
    napi_value args[1] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr), false);
    NAPI_ASSERT_BASE(env, argc == 1, "requires 1 parameter", false);

    napi_valuetype inputType = napi_undefined;
    napi_typeof(env, args[0], &inputType);
    NAPI_ASSERT_BASE(env, (inputType == napi_boolean), "type mismatch for parameter path", false);

    bool result = false;
    napi_get_value_bool(env, args[0], &result);
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return result;
}

static uint32_t GetUintFromOption(const napi_env &env, const napi_callback_info &info)
{
    size_t argc = 1;
    napi_value args[1] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr), 0);
    NAPI_ASSERT_BASE(env, argc == 1, "requires 1 parameter", 0);

    napi_valuetype inputType = napi_undefined;
    napi_typeof(env, args[0], &inputType);
    NAPI_ASSERT_BASE(env, (inputType == napi_number), "type mismatch for parameter path", false);

    uint32_t result = 0;
    napi_get_value_uint32(env, args[0], &result);
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return result;
}

static napi_value ResetOption(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    g_hiperfRecordOption = std::make_unique<HiperfClient::RecordOption>();

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetOutputFilename(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    const std::string option = GetJsStringFromOption(env, info);
    g_hiperfRecordOption->SetOutputFilename(option);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value GetOutputFileName(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    std::string result = g_hiperfRecordOption->GetOutputFileName();
    NAPI_CALL(env, napi_create_string_utf8(env, result.c_str(), result.size(), &napiValue));

    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}s", result.c_str());
    return napiValue;
}

static napi_value SetTargetSystemWide(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    bool enable = GetBoolFromOption(env, info);
    g_hiperfRecordOption->SetTargetSystemWide(enable);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetCompressData(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    bool enable = GetBoolFromOption(env, info);
    g_hiperfRecordOption->SetCompressData(enable);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetSelectCpus(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    std::string option = GetJsStringFromOption(env, info);
    g_hiperfRecordOption->SetSelectCpus(StringSplitToInt(option));

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetTimeStopSec(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    uint32_t option = GetUintFromOption(env, info);
    g_hiperfRecordOption->SetTimeStopSec(option);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetFrequency(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    uint32_t option = GetUintFromOption(env, info);
    g_hiperfRecordOption->SetFrequency(option);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetPeriod(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    uint32_t option = GetUintFromOption(env, info);
    g_hiperfRecordOption->SetPeriod(option);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetSelectEvents(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    std::string option = GetJsStringFromOption(env, info);
    g_hiperfRecordOption->SetSelectEvents(StringSplit(option));

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}
static napi_value SetSelectGroups(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    std::string option = GetJsStringFromOption(env, info);
    g_hiperfRecordOption->SetSelectGroups(StringSplit(option));

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}
static napi_value SetNoInherit(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    bool enable = GetBoolFromOption(env, info);
    g_hiperfRecordOption->SetNoInherit(enable);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}
static napi_value SetSelectPids(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    std::string option = GetJsStringFromOption(env, info);
    g_hiperfRecordOption->SetSelectPids(StringSplitToInt(option));

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
};
static napi_value SetSelectTids(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    std::string option = GetJsStringFromOption(env, info);
    g_hiperfRecordOption->SetSelectTids(StringSplitToInt(option));

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetExcludePerf(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    bool enable = GetBoolFromOption(env, info);
    g_hiperfRecordOption->SetExcludePerf(enable);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetCpuPercent(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    uint32_t option = GetUintFromOption(env, info);
    g_hiperfRecordOption->SetCpuPercent(option);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetOffCPU(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    bool enable = GetBoolFromOption(env, info);
    g_hiperfRecordOption->SetOffCPU(enable);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetCallGraph(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    std::string option = GetJsStringFromOption(env, info);
    g_hiperfRecordOption->SetCallGraph((option));

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetDelayUnwind(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    bool enable = GetBoolFromOption(env, info);
    g_hiperfRecordOption->SetDelayUnwind(enable);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetDisableUnwind(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    bool enable = GetBoolFromOption(env, info);
    g_hiperfRecordOption->SetDisableUnwind(enable);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetDisableCallstackMerge(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    bool enable = GetBoolFromOption(env, info);
    g_hiperfRecordOption->SetDisableCallstackMerge(enable);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetSymbolDir(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    std::string option = GetJsStringFromOption(env, info);
    g_hiperfRecordOption->SetSymbolDir(option);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetDataLimit(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    std::string option = GetJsStringFromOption(env, info);
    g_hiperfRecordOption->SetDataLimit(option);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetAppPackage(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    std::string option = GetJsStringFromOption(env, info);
    g_hiperfRecordOption->SetAppPackage(option);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetClockId(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    std::string option = GetJsStringFromOption(env, info);
    g_hiperfRecordOption->SetClockId(option);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetVecBranchSampleTypes(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    std::string option = GetJsStringFromOption(env, info);
    g_hiperfRecordOption->SetVecBranchSampleTypes(StringSplit(option));

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value SetMmapPages(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;
    uint32_t option = GetUintFromOption(env, info);
    g_hiperfRecordOption->SetMmapPages(option);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value GetOptionVecString(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    const std::vector<std::string> items = g_hiperfRecordOption->GetOptionVecString();
    std::string result;
    const std::string split = ",";
    for (auto item : items) {
        if (!result.empty())
            result.append(split);
        result.append(item);
    }
    if (result.empty()) {
        result.append("<empty>");
    }

    NAPI_CALL(env, napi_create_string_utf8(env, result.c_str(), result.size(), &napiValue));

    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}s", result.c_str());
    return napiValue;
}

static napi_value StartWithOption(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;

    // for js api , we always use hilog
    g_hiperfClient->EnableHilog();

    bool result = g_hiperfClient->Setup(g_hiperfRecordOption->GetOutputFileName());
    if (result) {
        const HiperfClient::RecordOption *option = g_hiperfRecordOption.get();
        result = g_hiperfClient->Start(*option);
    }
    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value Start(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;

    // for js api , we always use hilog
    g_hiperfClient->EnableHilog();

    bool result = g_hiperfClient->Start();

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value Setup(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;

    std::string outputPath = GetJsStringFromOption(env, info);

    // for js api , we always use hilog
    g_hiperfClient->EnableHilog();
    bool result = g_hiperfClient->Setup(outputPath);

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value IsReady(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = g_hiperfClient->IsReady();

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));

    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value Stop(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = g_hiperfClient->Stop();

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));

    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value Pause(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = g_hiperfClient->Pause();

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));

    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value Resume(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = g_hiperfClient->Resume();

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));

    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}

static napi_value GetOutputDir(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    std::string result = g_hiperfClient->GetOutputDir();

    NAPI_CALL(env, napi_create_string_utf8(env, result.c_str(), result.size(), &napiValue));

    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}s", result.c_str());
    return napiValue;
}

static napi_value GetCommandPath(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    std::string result = g_hiperfClient->GetCommandPath();

    NAPI_CALL(env, napi_create_string_utf8(env, result.c_str(), result.size(), &napiValue));

    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}s", result.c_str());
    return napiValue;
}

static napi_value GetOutputPerfDataPath(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    std::string result = g_hiperfClient->GetOutputPerfDataPath();

    NAPI_CALL(env, napi_create_string_utf8(env, result.c_str(), result.size(), &napiValue));

    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}s", result.c_str());
    return napiValue;
}

static napi_value SetDebugMode(napi_env env, napi_callback_info info)
{
    napi_value napiValue = nullptr;
    bool result = true;

    g_hiperfClient->SetDebugMode();

    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));

    HIPERF_HILOGD(MODULE_JS_NAPI, "%{public}d", result);
    return napiValue;
}
} // namespace HiperfClient
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS

using namespace OHOS::Developtools::HiPerf::HiperfClient;

EXTERN_C_START
/*
 * function for module exports
 */
static napi_value HiperfClientInit(napi_env env, napi_value exports)
{
    HIPERF_HILOGD(MODULE_JS_NAPI, "enter");

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("isReady", IsReady),
        DECLARE_NAPI_FUNCTION("setup", Setup),
        DECLARE_NAPI_FUNCTION("start", Start),
        DECLARE_NAPI_FUNCTION("stop", Stop),
        DECLARE_NAPI_FUNCTION("pause", Pause),
        DECLARE_NAPI_FUNCTION("resume", Resume),
        DECLARE_NAPI_FUNCTION("getOutputDir", GetOutputDir),
        DECLARE_NAPI_FUNCTION("getOutputPerfDataPath", GetOutputPerfDataPath),
        DECLARE_NAPI_FUNCTION("getCommandPath", GetCommandPath),
        DECLARE_NAPI_FUNCTION("setDebugMode", SetDebugMode),
        // Option:
        DECLARE_NAPI_FUNCTION("startWithOption", StartWithOption),
        DECLARE_NAPI_FUNCTION("resetOption", ResetOption),
        DECLARE_NAPI_FUNCTION("setOutputFilename", SetOutputFilename),
        DECLARE_NAPI_FUNCTION("getOutputFileName", GetOutputFileName),
        DECLARE_NAPI_FUNCTION("setTargetSystemWide", SetTargetSystemWide),
        DECLARE_NAPI_FUNCTION("setCompressData", SetCompressData),
        DECLARE_NAPI_FUNCTION("setSelectCpus", SetSelectCpus),
        DECLARE_NAPI_FUNCTION("setTimeStopSec", SetTimeStopSec),
        DECLARE_NAPI_FUNCTION("setFrequency", SetFrequency),
        DECLARE_NAPI_FUNCTION("setPeriod", SetPeriod),
        DECLARE_NAPI_FUNCTION("setSelectEvents", SetSelectEvents),
        DECLARE_NAPI_FUNCTION("setSelectGroups", SetSelectGroups),
        DECLARE_NAPI_FUNCTION("setNoInherit", SetNoInherit),
        DECLARE_NAPI_FUNCTION("setSelectPids", SetSelectPids),
        DECLARE_NAPI_FUNCTION("setSelectTids", SetSelectTids),
        DECLARE_NAPI_FUNCTION("setExcludePerf", SetExcludePerf),
        DECLARE_NAPI_FUNCTION("setCpuPercent", SetCpuPercent),
        DECLARE_NAPI_FUNCTION("setOffCPU", SetOffCPU),
        DECLARE_NAPI_FUNCTION("setCallGraph", SetCallGraph),
        DECLARE_NAPI_FUNCTION("setDelayUnwind", SetDelayUnwind),
        DECLARE_NAPI_FUNCTION("setDisableUnwind", SetDisableUnwind),
        DECLARE_NAPI_FUNCTION("setDisableCallstackMerge", SetDisableCallstackMerge),
        DECLARE_NAPI_FUNCTION("setSymbolDir", SetSymbolDir),
        DECLARE_NAPI_FUNCTION("setDataLimit", SetDataLimit),
        DECLARE_NAPI_FUNCTION("setAppPackage", SetAppPackage),
        DECLARE_NAPI_FUNCTION("setClockId", SetClockId),
        DECLARE_NAPI_FUNCTION("setVecBranchSampleTypes", SetVecBranchSampleTypes),
        DECLARE_NAPI_FUNCTION("setMmapPages", SetMmapPages),
        DECLARE_NAPI_FUNCTION("getOptionVecString", GetOptionVecString),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    HIPERF_HILOGD(MODULE_JS_NAPI, "exit");
    return exports;
}
EXTERN_C_END

/*
 * Module definition
 */
static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = HiperfClientInit,
    .nm_modname = "hiperf",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

/*
 * Module registration
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&g_module);
}
