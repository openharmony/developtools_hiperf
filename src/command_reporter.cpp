/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "command_reporter.h"

#if defined(is_ohos) && is_ohos
#include "hiperf_hilog.h"
#include "hisysevent.h"
#include "utilities.h"
#endif

namespace OHOS::Developtools::HiPerf {

CommandReporter::CommandReporter(const std::string& fullArgument) : subCommand_(fullArgument)
{
#if defined(is_ohos) && is_ohos
    caller_ = GetProcessName(getppid());
#endif
}

CommandReporter::~CommandReporter()
{
    ReportCommand();
}

void CommandReporter::ReportCommand()
{
#if defined(is_ohos) && is_ohos
    if (isReported_) {
        HIPERF_HILOGD(MODULE_DEFAULT, "command has been reported");
        return;
    }

    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::PROFILER, "HIPERF_USAGE",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "MAIN_CMD", mainCommand_,
        "SUB_CMD", subCommand_,
        "CALLER", caller_,
        "TARGET_PROCESS", targetProcess_,
        "ERROR_CODE", errorCode_,
        "ERROR_MESSAGE", errorMessage_);
    if (ret != 0) {
        HIPERF_HILOGE(MODULE_DEFAULT, "hisysevent report failed, err:%{public}d", ret);
    }
#endif
    isReported_ = true;
}

} // namespace OHOS::Developtools::HiPerf
