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

#ifndef HIPERF_SUBCOMMAND_TEST_H
#define HIPERF_SUBCOMMAND_TEST_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "subcommand.h"
namespace OHOS {
namespace Developtools {
namespace HiPerf {
static std::string TEST_CMD_1 = "TEST_CMD_1";
static std::string TEST_CMD_2 = "TEST_CMD_2";
static std::string TEST_CMD_3 = "TEST_CMD_3";
static std::string TEST_NOREG_CMD = "TEST_NOREG_CMD";
static std::string TEST_BRIEF = " TEST_BRIEF\n";
static std::string TEST_HELP = " TEST_HELP\n";

static const std::vector<std::string> EMPTY_ARGS = {""};
static const std::vector<std::string> TEST_REG_ARG_1 = {TEST_CMD_1};
static const std::vector<std::string> TEST_REG_ARG_2 = {TEST_CMD_2};
static const std::vector<std::string> TEST_REG_ARG_3 = {TEST_CMD_3};
static const std::vector<std::string> TEST_REG_ARG_3S = {TEST_CMD_3, TEST_CMD_2, TEST_CMD_1};
static const std::vector<std::string> TEST_NOREG_ARG_1 = {TEST_NOREG_CMD};

class SubCommandTest : public SubCommand {
public:
    explicit SubCommandTest(std::string name) : SubCommand(name, TEST_BRIEF, TEST_HELP) {}

    bool OnSubCommand(std::vector<std::string> &args) override
    {
        return true;
    }
};

using ::testing::_;
using ::testing::Return;

class MockSubCommand : public SubCommand {
public:
    explicit MockSubCommand(std::string name) : SubCommand(name, TEST_BRIEF, TEST_HELP) {}
    MockSubCommand() : MockSubCommand("mock") {}
    MOCK_METHOD1(OnSubCommand, bool(std::vector<std::string> &args));
};
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_SUBCOMMAND_TEST_H
