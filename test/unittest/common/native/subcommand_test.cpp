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

#include "subcommand_test.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <hilog/log.h>

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class HiPerfSubcommandTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class SubcommandObj : public SubCommand {
public:
    SubcommandObj() : SubCommand("subcomm", "test subcomm", "ut test subcomm") {}
    bool OnSubCommand(std::vector<std::string> &args) override
    {
        return true;
    }
};

void HiPerfSubcommandTest::SetUpTestCase() {}

void HiPerfSubcommandTest::TearDownTestCase() {}

void HiPerfSubcommandTest::SetUp()
{
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
    SubCommand::RegisterSubCommand(TEST_CMD_1, std::make_unique<SubCommandTest>(TEST_CMD_1));
    SubCommand::RegisterSubCommand(TEST_CMD_2, std::make_unique<SubCommandTest>(TEST_CMD_2));
    SubCommand::RegisterSubCommand(TEST_CMD_3, std::make_unique<SubCommandTest>(TEST_CMD_3));
}

void HiPerfSubcommandTest::TearDown()
{
    SubCommand::ClearSubCommands();
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
}

/**
 * @tc.name: TestRegisterSubCommand
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, TestRegisterSubCommand, TestSize.Level1)
{
    EXPECT_EQ(SubCommand::RegisterSubCommand("", std::make_unique<SubCommandTest>(TEST_CMD_1)),
              false);
    EXPECT_EQ(SubCommand::RegisterSubCommand("t", std::make_unique<SubCommandTest>(TEST_CMD_1)),
              true);
    EXPECT_EQ(SubCommand::RegisterSubCommand("-t", std::make_unique<SubCommandTest>(TEST_CMD_1)),
              false);
    EXPECT_EQ(SubCommand::RegisterSubCommand("--t", std::make_unique<SubCommandTest>(TEST_CMD_1)),
              false);
    EXPECT_EQ(SubCommand::RegisterSubCommand("test", std::make_unique<SubCommandTest>(TEST_CMD_1)),
              true);
    EXPECT_EQ(SubCommand::RegisterSubCommand("test", std::make_unique<SubCommandTest>(TEST_CMD_1)),
              false);
}

/**
 * @tc.name: TestGetSubCommands
 * @tc.desc: also test SubCommand::ClearSubCommands()
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, TestGetSubCommands, TestSize.Level1)
{
    EXPECT_EQ(SubCommand::GetSubCommands().size(), 3u);
    SubCommand::ClearSubCommands();
    EXPECT_EQ(SubCommand::GetSubCommands().size(), 0u);
}

/**
 * @tc.name: TestFindSubCommand
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, TestFindSubCommand, TestSize.Level1)
{
    ASSERT_NE(SubCommand::FindSubCommand(TEST_CMD_1), nullptr);
    EXPECT_EQ(SubCommand::FindSubCommand(TEST_CMD_1)->Name(), TEST_CMD_1);
    EXPECT_EQ(SubCommand::FindSubCommand(TEST_CMD_1)->Brief(), TEST_BRIEF);
    EXPECT_EQ(SubCommand::FindSubCommand(TEST_CMD_1)->Help(), TEST_HELP);

    ASSERT_NE(SubCommand::FindSubCommand(TEST_CMD_2), nullptr);
    EXPECT_EQ(SubCommand::FindSubCommand(TEST_CMD_2)->Name(), TEST_CMD_2);
    EXPECT_EQ(SubCommand::FindSubCommand(TEST_CMD_2)->Brief(), TEST_BRIEF);
    EXPECT_EQ(SubCommand::FindSubCommand(TEST_CMD_2)->Help(), TEST_HELP);

    ASSERT_NE(SubCommand::FindSubCommand(TEST_CMD_3), nullptr);
    EXPECT_EQ(SubCommand::FindSubCommand(TEST_CMD_3)->Name(), TEST_CMD_3);
    EXPECT_EQ(SubCommand::FindSubCommand(TEST_CMD_3)->Brief(), TEST_BRIEF);
    EXPECT_EQ(SubCommand::FindSubCommand(TEST_CMD_3)->Help(), TEST_HELP);

    EXPECT_EQ(SubCommand::FindSubCommand(TEST_NOREG_CMD), nullptr);
}

/**
 * @tc.name: TestFindSubCommand
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, TestOnSubCommandOptionsDump, TestSize.Level1)
{
    std::vector<std::string> args;
    SubcommandObj subcomm;
    args = {"test"};
    EXPECT_EQ(subcomm.OnSubCommandOptions(args), true);
    args = {"--dumpoption"};
    EXPECT_EQ(subcomm.OnSubCommandOptions(args), true);
    args = {"--dumpoption", "opt"};
    EXPECT_EQ(subcomm.OnSubCommandOptions(args), true);
    args = {"--dumpoption", " "};
    EXPECT_EQ(subcomm.OnSubCommandOptions(args), true);
    args = {"-dumpoption", "opt"};
    EXPECT_EQ(subcomm.OnSubCommandOptions(args), true);
    args = {"--test"};
    EXPECT_EQ(subcomm.OnSubCommandOptions(args), true);
    args = {"--help"};
    EXPECT_EQ(subcomm.OnSubCommandOptions(args), false);
    args = {"--help", "opt"};
    EXPECT_EQ(subcomm.OnSubCommandOptions(args), false);
    args = {"--help", " "};
    EXPECT_EQ(subcomm.OnSubCommandOptions(args), false);
    args = {"-help"};
    EXPECT_EQ(subcomm.OnSubCommandOptions(args), false);
    args = {"-help"};
    EXPECT_EQ(subcomm.OnSubCommandOptions(args), false);
    args = {"-help", "opt"};
    EXPECT_EQ(subcomm.OnSubCommandOptions(args), false);
}

/**
 * @tc.name: TestFindSubCommand
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, TestOnPreSubCommand, TestSize.Level1)
{
    std::vector<std::string> args;
    SubcommandObj subcomm;
    EXPECT_EQ(subcomm.OnPreSubCommand(), false);
    args = {"--help"};
    subcomm.OnSubCommandOptions(args);
    EXPECT_EQ(subcomm.OnPreSubCommand(), true);
}

/**
 * @tc.name: TestFindSubCommand
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, TestClearSubCommands, TestSize.Level1)
{
    SubCommand::ClearSubCommands();
    EXPECT_EQ(SubCommand::GetSubCommands().size(), 0u);
}

/**
 * @tc.name: TestDumpOptions
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, TestDumpOptions, TestSize.Level1)
{
    SubcommandObj subcomm;
    subcomm.DumpOptions();
    EXPECT_EQ(1, 1);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
