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

#include "subcommand_help_test.h"

#include "debug_logger.h"
#include "subcommand.h"
#include "subcommand_help.h"
#include "utilities.h"

using namespace testing::ext;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class SubCommandHelpTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    SubCommandHelp subCommandHelp;
};

class SubCommandTmp : public SubCommand {
public:
    explicit SubCommandTmp(std::string name)
        : SubCommand(TEST_CMD_HLP, TEST_HLP_BRIEF, TEST_HLP_HELP)
    {
    }

    bool OnSubCommand(std::vector<std::string> &args) override
    {
        return true;
    }
};

void SubCommandHelpTest::SetUpTestCase()
{
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
    SubCommand::RegisterSubCommand("help", std::make_unique<SubCommandHelp>());
}

void SubCommandHelpTest::TearDownTestCase()
{
    SubCommand::ClearSubCommands();
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
}

void SubCommandHelpTest::SetUp() {}

void SubCommandHelpTest::TearDown() {}

/**
 * @tc.name: TestOnSubCommand
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandHelpTest, TestOnSubCommand, TestSize.Level1)
{
    std::vector<std::string> args;

    args = {"--help"};
    EXPECT_EQ(subCommandHelp.OnSubCommand(args), true);
}

/**
 * @tc.name: TestOnHelpAll
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandHelpTest, TestOnHelpAll, TestSize.Level1)
{
    std::vector<std::string> args;

    EXPECT_EQ(subCommandHelp.OnHelp(args), true);
}

/**
 * @tc.name: TestOnHelpRegCmd
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandHelpTest, TestOnHelpRegCmd, TestSize.Level1)
{
    std::vector<std::string> args;
    SubCommand::RegisterSubCommand(TEST_CMD_HLP, std::make_unique<SubCommandTmp>(TEST_CMD_HLP));
    args = {"TEST_CMD_HLP"};
    EXPECT_EQ(subCommandHelp.OnHelp(args), true);
}

/**
 * @tc.name: TestOnHelpUnknownCmd
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandHelpTest, TestOnHelpUnknownCmd, TestSize.Level1)
{
    std::vector<std::string> args;

    args = {"unknowcmd"};
    EXPECT_EQ(subCommandHelp.OnHelp(args), false);
}

/**
 * @tc.name: GetInstance
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandHelpTest, GetInstance, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    EXPECT_EQ(SubCommandHelp::GetInstance().Name(), "help");
}

/**
 * @tc.name: GetInstance
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandHelpTest, RegisterSubCommandHelp, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    Option::ClearMainOptions();
    ASSERT_EQ(Option::GetMainOptions().size(), 0u);

    SubCommandHelp::RegisterSubCommandHelp();
    const std::map<std::string, std::unique_ptr<Option::MainOption>>& optionMap = Option::GetMainOptions();
    EXPECT_TRUE(optionMap.find("--help") != optionMap.end());
    EXPECT_TRUE(optionMap.find("-h") != optionMap.end());
    std::string help = "help";
    EXPECT_TRUE(SubCommand::FindSubCommand(help) != nullptr);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
