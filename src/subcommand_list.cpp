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

#include "subcommand_list.h"

using namespace std;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
bool SubCommandList::OnSubCommand(vector<string> &args)
{
    HLOGV("enter");
    vector<perf_type_id> requestEventTypes;

    if (args.empty()) {
        // all the list
        for (auto it : PERF_TYPES) {
            requestEventTypes.push_back(it.first);
        }
    } else {
        string requestEventType = args.front().c_str();
        auto it = SUPPORT_NAME_OPTIONS.find(requestEventType);
        if (it == SUPPORT_NAME_OPTIONS.end()) {
            printf("not support option: '%s'\n", requestEventType.c_str());
            return false;
        } else {
            requestEventTypes.push_back(it->second);
        }
    }
    ShowSupportEventsTypes(requestEventTypes);
    return true;
}
bool SubCommandList::ShowSupportEventsTypes(vector<perf_type_id> requestEventTypes)
{
    // each type
    for (perf_type_id id : requestEventTypes) {
        // each config
        auto configs = perfEvents_.GetSupportEvents(id);
        printf("\nSupported events for %s:\n", PERF_TYPES.at(id).c_str());
        for (auto config : configs) {
            printf("\t%s\n", config.second.c_str());
        }
        if (configs.size() == 0) {
            return false; // support nothing
        }
    }
    std::cout << std::endl;
    return true;
};

void SubCommandList::RegisterSubCommandList()
{
    HLOGV("enter");
    SubCommand::RegisterSubCommand("list", make_unique<SubCommandList>());
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
