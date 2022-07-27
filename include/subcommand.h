/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef HIPERF_SUBCOMMAND_H_
#define HIPERF_SUBCOMMAND_H_
#include <string>
#include "utilities.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
class SubCommand {
public:
    SubCommand(const std::string &name, const std::string &brief, const std::string &help)
        : name_(name), brief_(brief), help_(help)
    {
    }

    virtual ~SubCommand() {}

    const std::string &Name() const
    {
        return name_;
    }
    const std::string &Brief() const
    {
        return brief_;
    }
    const std::string &Help() const
    {
        return help_;
    }

    // parse option first
    bool OnSubCommandOptions(std::vector<std::string> args);

    // some help cmd
    bool OnPreSubCommand()
    {
        if (showHelp_) {
            printf("%s\n", Help().c_str());
            return true;
        }
        return false;
    };

    virtual void DumpOptions() const {}

    // args should be empty after all the args processed
    virtual bool ParseOption(std::vector<std::string> &args)
    {
        args.clear(); // all the args is processed
        return true;
    }

    // return false means cmd failed
    virtual bool OnSubCommand(std::vector<std::string> &args) = 0;
    // some test code will use this for simple
    bool OnSubCommand(std::string stringArgs)
    {
        auto args = StringSplit(stringArgs, " ");
        return OnSubCommand(args);
    };

    // called from main
    static bool RegisterSubCommand(std::string, std::unique_ptr<SubCommand>);

    // get some cmd
    static const std::map<std::string, std::unique_ptr<SubCommand>> &GetSubCommands();
    static SubCommand *FindSubCommand(std::string);

    // for test code
    static void ClearSubCommands();

protected:
    const std::string name_;
    const std::string brief_;
    std::string help_;
    bool dumpOptions_ = false;
    bool showHelp_ = false;
};
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_SUBCOMMAND_H_
