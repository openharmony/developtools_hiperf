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

#include "subcommand.h"

#include "debug_logger.h"
#include "option.h"
#include "subcommand_help.h"
#include "utilities.h"

using namespace std;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
static std::map<std::string, std::unique_ptr<SubCommand>> g_SubCommandsMap;

// parse option first
bool SubCommand::OnSubCommandOptions(std::vector<std::string> args)
{
    // parse common first
    if (!Option::GetOptionValue(args, "--dumpoptions", dumpOptions_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--help", showHelp_)
        || !Option::GetOptionValue(args, "-h", showHelp_)) {
        return false;
    }

    if (showHelp_) {
        if (!args.empty()) {
            printf("unknown option '%s'\n", args.front().c_str());
            return false;
        }
        if (OnPreSubCommand()) {
            return false;
        }
    }

    if (ParseOption(args)) {
        if (dumpOptions_) {
            DumpOptions();
        }
        HLOGD(" args left over: (%zu): %s", args.size(), VectorToString(args).c_str());
        if (!args.empty()) {
            printf("unknown option '%s'\n", args.front().c_str());
            return false;
        }
    } else {
        HLOGD("incorrect option(s)\n");
        return false;
    }
    return true;
}

bool SubCommand::RegisterSubCommand(std::string cmdName, std::unique_ptr<SubCommand> subCommand)
{
    HLOGV("%s", cmdName.c_str());
    if (cmdName.empty()) {
        HLOGE("unable to register empty subcommand!");
        return false;
    }
    if (cmdName.front() == '-') {
        HLOGE("unable use '-' at the begin of subcommand '%s'", cmdName.c_str());
        return false;
    }

    if (g_SubCommandsMap.count(cmdName) == 0) {
        g_SubCommandsMap.insert(std::make_pair(cmdName, std::move(subCommand)));
        return true;
    } else {
        HLOGE("subcommand '%s' already registered!", cmdName.c_str());
        return false;
    }
}

void SubCommand::ClearSubCommands()
{
    g_SubCommandsMap.clear();
}

const std::map<std::string, std::unique_ptr<SubCommand>> &SubCommand::GetSubCommands()
{
    HLOGV("enter");
    return g_SubCommandsMap;
}

SubCommand *SubCommand::FindSubCommand(std::string cmdName)
{
    HLOGV("%s", cmdName.c_str());
    auto found = g_SubCommandsMap.find(cmdName);
    if (found != g_SubCommandsMap.end()) {
        // remove the subcmd itself
        return found->second.get();
    } else {
        return nullptr;
    }
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
