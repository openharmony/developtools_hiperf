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

#include "option_debug.h"
namespace OHOS {
namespace Developtools {
namespace HiPerf {
static bool OnVerboseLevel(const std::vector<std::string> &debugLevel)
{
    DebugLogger::GetInstance()->SetLogLevel(LEVEL_VERBOSE);
    DebugLogger::GetInstance()->Disable(false);
    return true;
}

static bool OnMuchLevel(const std::vector<std::string> &debugLevel)
{
    DebugLogger::GetInstance()->SetLogLevel(LEVEL_MUCH);
    DebugLogger::GetInstance()->Disable(false);
    return true;
}

static bool OnDebugLevel(const std::vector<std::string> &debugLevel)
{
    DebugLogger::GetInstance()->SetLogLevel(LEVEL_DEBUG);
    DebugLogger::GetInstance()->Disable(false);
    return true;
}

static bool OnNoDebug(const std::vector<std::string> &debugLevel)
{
    DebugLogger::GetInstance()->Disable();
    return true;
}

static bool OnMixLogOutput(const std::vector<std::string> &debugLevel)
{
    DebugLogger::GetInstance()->SetMixLogOutput(true);
    return true;
}

static bool OnLogPath(std::vector<std::string> &args)
{
    if (args.size() > 0) {
        DebugLogger::GetInstance()->SetLogPath(args[0]);
        args.erase(args.begin());
    }
    return true;
}

static bool OnLogTag(std::vector<std::string> &args)
{
    if (args.size() > 0) {
        DebugLogger::GetInstance()->SetLogTags(args[0]);
        args.erase(args.begin());
    }
    return true;
}
#if is_ohos && !is_double_framework
static bool OnHiLog(const std::vector<std::string> &args)
{
    DebugLogger::GetInstance()->EnableHiLog();
    return true;
}
#endif
void RegisterMainCommandDebug()
{
    Option::RegisterMainOption("--nodebug", "disbale debug log", OnNoDebug);
    Option::RegisterMainOption("--debug", "show debug log", OnDebugLevel);
    Option::RegisterMainOption("--verbose", "show debug log", OnVerboseLevel);
    Option::RegisterMainOption("--much", "show extremely much debug log", OnMuchLevel);
    Option::RegisterMainOption("--mixlog", "mix the log in output", OnMixLogOutput);
    Option::RegisterMainOption("--logpath", "log file name full path", OnLogPath);
    Option::RegisterMainOption(
        "--logtag", "enable log level for HILOG_TAG, usage format: <tag>[:level][,<tag>[:level]]",
        OnLogTag);
#if is_ohos && !is_double_framework
    Option::RegisterMainOption("--hilog", "use hilog not file to record log", OnHiLog);
#endif
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS