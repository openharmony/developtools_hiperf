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
#ifndef COMMAND_REPORTER_H_
#define COMMAND_REPORTER_H_

#include <string>
namespace OHOS::Developtools::HiPerf {

class CommandReporter {
public:
    explicit CommandReporter(const std::string& fullArgument);
    ~CommandReporter();

    void ReportCommand();

    std::string mainCommand_ = "";
    std::string subCommand_ = "";
    std::string caller_ = "";
    std::string targetProcess_ = "";
    int32_t errorCode_ = 0;
    std::string errorMessage_ = "";

private:
    bool isReported_ = false;

    CommandReporter(const CommandReporter&) = delete;
    CommandReporter& operator=(const CommandReporter&) = delete;
    CommandReporter(CommandReporter&&) = delete;
    CommandReporter& operator=(CommandReporter&&) = delete;
};

} // namespace OHOS::Developtools::HiPerf

#endif // COMMAND_REPORTER_H_