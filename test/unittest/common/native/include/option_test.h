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

#ifndef HIPERF_OPTION_TEST_H
#define HIPERF_OPTION_TEST_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "option.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
static std::string TEST_OPTION_CMD_EMPTY = "";
static std::string TEST_OPTION_CMD_NO_PREFIX = "TEST_OPTION_CMD";
static std::string TEST_OPTION_CMD_ERR_PREFIX = "TEST_OPTION_CMD";
static std::string TEST_OPTION_CMD_1 = "-TEST_OPTION_CMD_1";
static std::string TEST_OPTION_CMD_2 = "-TEST_OPTION_CMD_2";
static std::string TEST_OPTION_CMD_3 = "-TEST_OPTION_CMD_3";
static std::string TEST_NO_OPTION_CMD = "TEST_NO_OPTION_CMD";
static std::string TEST_OPTION_BRIEF = " TEST_BRIEF\n";
static std::string TEST_OPTION_HELP = " TEST_HELP\n";

static std::string OPTION_NAME = "--debug";
static std::string OPTION_ERROR_NAME = "--nodebug";
static std::string OPTION_NAME_ONLY = "--nameonly";
static std::string OPTION_NAME_VOID = "--void";
static std::string OPTION_ILLEGAL_NAME = "illegal";
static std::string OPTION_STRING_VALUE = "3";
static std::string OPTION_STRING_THREE_VALUES = "1,2,3";
static std::string OPTION_STRING_THREE_ILLEGAL_VALUES = "1,a,3";
static std::string OPTION_ERROR_VALUE = "4";
static const std::string OPTION_ILLEGAL_INT = "illegal_int";
static const int OPTION_INT_VALUE = std::stoi(OPTION_STRING_VALUE);

static const std::vector<std::string> ONE_ARGS = {OPTION_NAME};
static const std::vector<std::string> ONE_ARGS_WITH_VALUE = {OPTION_NAME, OPTION_STRING_VALUE};

static const std::vector<std::string> TWO_ARGS = {OPTION_NAME, OPTION_NAME};
static const std::vector<std::string> TWO_ARGS_WITH_VALUE = {
    OPTION_NAME,
    OPTION_STRING_VALUE,
    OPTION_NAME,
    OPTION_STRING_VALUE,
};

static const std::vector<std::string> TWO_ERROR_ARGS = {OPTION_ERROR_NAME, OPTION_ERROR_NAME};
static const std::vector<std::string> TWO_ERROR_WITH_VALUE = {
    OPTION_ERROR_NAME,
    OPTION_STRING_VALUE,
    OPTION_ERROR_NAME,
    OPTION_STRING_VALUE,
};

static const std::vector<std::string> MIX_ARGS_1 = {
    OPTION_NAME,
    OPTION_ERROR_NAME,
};
static const std::vector<std::string> MIX_ARGS_1_WITH_VALUE = {
    OPTION_NAME,
    OPTION_STRING_VALUE,
    OPTION_ERROR_NAME,
    OPTION_STRING_VALUE,
};
static const std::vector<std::string> MIX_ARGS_2 = {
    OPTION_ERROR_NAME,
    OPTION_NAME,
};
static const std::vector<std::string> MIX_ARGS_2_WITH_VALUE = {
    OPTION_ERROR_NAME,
    OPTION_STRING_VALUE,
    OPTION_NAME,
    OPTION_STRING_VALUE,
};

static const std::vector<std::string> MIX_ARGS_2_WITH_ILLEGAL_VALUE = {
    OPTION_ERROR_NAME,
    OPTION_ILLEGAL_INT,
    OPTION_NAME,
    OPTION_ILLEGAL_INT,
};

static bool OptionAlwaysFalse(const std::vector<std::string> &args)
{
    printf("'%s'\n", __FUNCTION__);
    return false;
}
static bool OptionAlwaysTrue(const std::vector<std::string> &args)
{
    return true;
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_OPTION_TEST_H