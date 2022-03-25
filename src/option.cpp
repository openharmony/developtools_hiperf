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

#include "option.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
namespace Option {
static std::map<std::string, std::unique_ptr<MainOption>> g_MainOptions;

bool CheckOptionFormat(const std::string &optionName)
{
    if (optionName.empty()) {
        HLOGE("unable to use empty option name!");
        return false;
    }
    if (optionName.front() != '-') {
        HLOGE("must use '-' at the begin of option name!");
        return false;
    }

    return true;
}

const std::map<std::string, std::unique_ptr<MainOption>> &GetMainOptions()
{
    return g_MainOptions;
}

const MainOption *FindMainOption(std::string argName)
{
    HLOGV("%s", argName.c_str());
    auto found = g_MainOptions.find(argName);
    if (found != g_MainOptions.end()) {
        // remove the subcmd itself
        return found->second.get();
    } else {
        return nullptr;
    }
}

std::vector<std::string>::iterator FindOption(std::vector<std::string> &args,
                                              const std::string &optionName)
{
    HLOGV("try find '%s' in args: %s", optionName.c_str(), VectorToString(args).c_str());
    auto tmpit = args.begin();
    std::string::size_type position;
    for (; tmpit != args.end(); tmpit++) {
        position = (*tmpit).find("hiperf");
        if (position != (*tmpit).npos && (*tmpit)[(position + strlen("hiperf"))] == '\0') {
            break;
        }
    }
    auto it = find(args.begin(), args.end(), optionName);
    if (it != args.end()) {
        if (tmpit != args.end() && it > tmpit) {
            it = args.end();
        } else {
            // we found it , we remove it for next process
            HLOGD("have found '%s'", optionName.c_str());
        }
    }
    return it;
}

bool GetValueFromString(const std::string &optionValue, const std::string &optionName, bool &value)
{
    value = true;
    HLOGD("get bool result:'%s':'%d'", optionName.c_str(), value);
    return true;
}

bool GetValueFromString(const std::string &optionValue, const std::string &optionName, int &value)
{
    try {
        value = std::stoi(optionValue);
        HLOGD("get int result:'%s':'%d'", optionName.c_str(), value);
        return true;
    } catch (...) {
        // what can we do here ?
    }
    return false;
}

bool GetValueFromString(const std::string &optionValue, const std::string &optionName, float &value)
{
    try {
        value = std::stof(optionValue);
        HLOGD("get float result:'%s':'%f'", optionName.c_str(), value);
        return true;
    } catch (...) {
        // what can we do here ?
    }
    return false;
}

bool GetValueFromString(const std::string &optionValue, const std::string &optionName,
                        std::string &value)
{
    value = optionValue;
    return true; // every thing done
}

bool GetValueFromString(const std::string &optionValue, const std::string &optionName,
                        std::vector<int> &values)
{
    std::vector<std::string> stringValues = StringSplit(optionValue, ",");
    HLOGD("split int result:'%s':'%s'", optionName.c_str(), VectorToString(stringValues).c_str());
    try {
        while (!stringValues.empty()) {
            values.push_back(std::stoi(stringValues.front()));
            stringValues.erase(stringValues.begin()); // remove for next process
        }
        return values.size() > 0; // convert successed ?
    } catch (...) {
        // what can we do here ?
        HLOGD("stoi failed with %s", stringValues.front().c_str());
    }
    return false;
}

bool GetValueFromString(const std::string &optionValue, const std::string &optionName,
                        std::vector<std::string> &values)
{
    values = StringSplit(optionValue, ",");
    HLOGD("split string result:'%s':'%s' from '%s'", optionName.c_str(),
          VectorToString(values).c_str(), optionValue.c_str());
    return values.size() > 0; // convert successed ?
}

bool GetOptionTrackedCommand(std::vector<std::string> &args,
                             std::vector<std::string> &trackedCommand)
{
    if (!args.empty()) {
        trackedCommand.insert(trackedCommand.begin(), args.begin(), args.end());
        args.clear();
    }
    return true;
}

void ClearMainOptions()
{
    g_MainOptions.clear();
}

bool RegisterMainOption(const std::string &optionName, const std::string &help,
                        std::function<bool(std::vector<std::string> &)> callBackFunction)
{
    HLOGV("%s", optionName.c_str());
    if (!CheckOptionFormat(optionName)) {
        return false;
    }

    if (g_MainOptions.count(optionName) == 0) {
        g_MainOptions[optionName] = std::make_unique<MainOption>();
        g_MainOptions[optionName].get()->help = help;
        g_MainOptions[optionName].get()->callBackFunction = std::move(callBackFunction);
        return true;
    } else {
        HLOGE("main args %s already registered!", optionName.c_str());
        return false;
    }
}
} // namespace Option
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
