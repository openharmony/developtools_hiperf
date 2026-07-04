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

#include <gtest/gtest.h>
#include <hilog/log.h>

#include "option_debug.h"
#include "subcommand_help.h"
#include "utilities.h"
#if SUPPORT_PERF_EVENT
#include "subcommand_list.h"
#include "subcommand_record.h"
#include "subcommand_stat.h"
#endif
#include "subcommand_dump.h"
#include "subcommand_report.h"

using namespace testing::ext;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class HiPerfSubcommandTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    bool RegisterCommandComponent();
};

class SubcommandObj : public SubCommand {
public:
    SubcommandObj() : SubCommand("subcomm", "test subcomm", "ut test subcomm") {}
    HiperfError OnSubCommand(std::vector<std::string>& args) override
    {
        return HiperfError::NO_ERR;
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

bool HiPerfSubcommandTest::RegisterCommandComponent()
{
    // register all the main command
#ifdef HIPERF_DEBUG
    RegisterMainCommandDebug();
#endif

    // register all the sub command
    SubCommandHelp::RegisterSubCommandHelp();
#if SUPPORT_PERF_EVENT
    if (!RegisterSubCommandStat()) {
        return false;
    }
    SubCommandList::RegisterSubCommandList();
    if (!SubCommandRecord::RegisterSubCommandRecord()) {
        return false;
    }
#endif

    if (!SubCommandDump::RegisterSubCommandDump()) {
        return false;
    }
    if (!SubCommandReport::RegisterSubCommandReport()) {
        return false;
    }
    return true;
}

/**
 * @tc.name: TestRegisterSubCommand
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, TestRegisterSubCommand, TestSize.Level0)
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
HWTEST_F(HiPerfSubcommandTest, TestOnPreSubCommand, TestSize.Level3)
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
HWTEST_F(HiPerfSubcommandTest, TestClearSubCommands, TestSize.Level2)
{
    SubCommand::ClearSubCommands();
    EXPECT_EQ(SubCommand::GetSubCommands().size(), 0u);
}

/**
 * @tc.name: TestRegisterSubCommand
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, TestRegisterSubCommand2, TestSize.Level1)
{
    SubcommandObj obj;
    auto func = [&obj]() -> SubCommand& {
        return obj;
    };
    SubCommand::ClearSubCommands();
    EXPECT_EQ(SubCommand::RegisterSubCommand("", func), false);
    EXPECT_EQ(SubCommand::RegisterSubCommand("-abc", func), false);
    EXPECT_EQ(SubCommand::RegisterSubCommand("null", func), true);
    EXPECT_EQ(SubCommand::RegisterSubCommand("null", func), false);
}

/**
 * @tc.name: RegisterCommandComponent
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, RegisterCommandComponent, TestSize.Level1)
{
    EXPECT_TRUE(RegisterCommandComponent());
}

class SubcommandParseFail : public SubCommand {
public:
    SubcommandParseFail() : SubCommand("parsefail", "test", "ut") {}
    bool ParseOption(std::vector<std::string> &args) override { return false; }
    HiperfError OnSubCommand(std::vector<std::string>& args) override { return HiperfError::NO_ERR; }
};

class SubcommandLeaveArgs : public SubCommand {
public:
    SubcommandLeaveArgs() : SubCommand("leaveargs", "test", "ut") {}
    bool ParseOption(std::vector<std::string> &args) override { return true; }
    HiperfError OnSubCommand(std::vector<std::string>& args) override { return HiperfError::NO_ERR; }
};

/**
 * @tc.name: CheckRestartOption_NoRestart
 * @tc.desc: Test CheckRestartOption returns true when restart is false
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, CheckRestartOption_NoRestart, TestSize.Level2)
{
    SubcommandObj subcomm;
    std::vector<pid_t> selectPids;
    EXPECT_TRUE(subcomm.CheckRestartOption("app", false, false, selectPids));
}

/**
 * @tc.name: CheckRestartOption_EmptyAppPackage
 * @tc.desc: Test CheckRestartOption returns false when restart true but appPackage empty
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, CheckRestartOption_EmptyAppPackage, TestSize.Level2)
{
    SubcommandObj subcomm;
    std::vector<pid_t> selectPids;
    EXPECT_FALSE(subcomm.CheckRestartOption("", false, true, selectPids));
}

/**
 * @tc.name: CheckRestartOption_ConflictSystemWide
 * @tc.desc: Test CheckRestartOption returns false when restart conflicts with system wide
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, CheckRestartOption_ConflictSystemWide, TestSize.Level2)
{
    SubcommandObj subcomm;
    std::vector<pid_t> selectPids;
    EXPECT_FALSE(subcomm.CheckRestartOption("app", true, true, selectPids));
}

/**
 * @tc.name: CheckRestartOption_ConflictSelectPids
 * @tc.desc: Test CheckRestartOption returns false when restart conflicts with select pids
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, CheckRestartOption_ConflictSelectPids, TestSize.Level2)
{
    SubcommandObj subcomm;
    std::vector<pid_t> selectPids = {1};
    EXPECT_FALSE(subcomm.CheckRestartOption("app", false, true, selectPids));
}

/**
 * @tc.name: HandleSubCommandExclude_BothNonEmpty_Conflict
 * @tc.desc: Test HandleSubCommandExclude returns false when both exclude options given
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, HandleSubCommandExclude_BothNonEmpty_Conflict, TestSize.Level2)
{
    SubcommandObj subcomm;
    std::vector<pid_t> excludeTids = {1};
    std::vector<std::string> excludeNames = {"thread"};
    std::vector<pid_t> selectTids = {1};
    EXPECT_FALSE(subcomm.HandleSubCommandExclude(excludeTids, excludeNames, selectTids));
}

/**
 * @tc.name: HandleSubCommandExclude_BothEmpty
 * @tc.desc: Test HandleSubCommandExclude returns true when no exclude options given
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, HandleSubCommandExclude_BothEmpty, TestSize.Level2)
{
    SubcommandObj subcomm;
    std::vector<pid_t> selectTids = {1};
    EXPECT_TRUE(subcomm.HandleSubCommandExclude({}, {}, selectTids));
}

/**
 * @tc.name: HandleSubCommandExclude_NoSelectTids
 * @tc.desc: Test HandleSubCommandExclude returns true when selectTids empty but excludes given
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, HandleSubCommandExclude_NoSelectTids, TestSize.Level2)
{
    SubcommandObj subcomm;
    std::vector<pid_t> excludeTids = {1};
    std::vector<pid_t> selectTids;
    EXPECT_TRUE(subcomm.HandleSubCommandExclude(excludeTids, {}, selectTids));
}

/**
 * @tc.name: HandleSubCommandExclude_ExcludeTids_RemovesMatch
 * @tc.desc: Test HandleSubCommandExclude removes matching tids from selectTids
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, HandleSubCommandExclude_ExcludeTids_RemovesMatch, TestSize.Level2)
{
    SubcommandObj subcomm;
    std::vector<pid_t> excludeTids = {2};
    std::vector<pid_t> selectTids = {1, 2, 3};
    EXPECT_TRUE(subcomm.HandleSubCommandExclude(excludeTids, {}, selectTids));
    EXPECT_EQ(selectTids.size(), 2u);
    EXPECT_EQ(std::find(selectTids.begin(), selectTids.end(), 2), selectTids.end());
}

/**
 * @tc.name: HandleSubCommandExclude_ExcludeTidNotFound
 * @tc.desc: Test HandleSubCommandExclude when excluded tid not in selectTids
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, HandleSubCommandExclude_ExcludeTidNotFound, TestSize.Level2)
{
    SubcommandObj subcomm;
    std::vector<pid_t> excludeTids = {99};
    std::vector<pid_t> selectTids = {1, 2};
    EXPECT_TRUE(subcomm.HandleSubCommandExclude(excludeTids, {}, selectTids));
    EXPECT_EQ(selectTids.size(), 2u);
}

/**
 * @tc.name: HandleSubCommandExclude_ExcludeThreadNames_NoMatch
 * @tc.desc: Test HandleSubCommandExclude with thread names that do not match
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, HandleSubCommandExclude_ExcludeThreadNames_NoMatch, TestSize.Level2)
{
    SubcommandObj subcomm;
    std::vector<std::string> excludeNames = {"nonexistent_thread_name_xyz"};
    std::vector<pid_t> selectTids = {getpid()};
    EXPECT_TRUE(subcomm.HandleSubCommandExclude({}, excludeNames, selectTids));
    EXPECT_EQ(selectTids.size(), 1u);
}

/**
 * @tc.name: OnSubCommandOptions_DumpOptionsEnabled
 * @tc.desc: Test OnSubCommandOptions with --dumpoptions triggers DumpOptions
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, OnSubCommandOptions_DumpOptionsEnabled, TestSize.Level2)
{
    SubcommandObj subcomm;
    std::vector<std::string> args = {"--dumpoptions"};
    EXPECT_TRUE(subcomm.OnSubCommandOptions(args));
}

/**
 * @tc.name: OnSubCommandOptions_ParseOptionFalse
 * @tc.desc: Test OnSubCommandOptions returns false when ParseOption fails
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, OnSubCommandOptions_ParseOptionFalse, TestSize.Level2)
{
    SubcommandParseFail subcomm;
    std::vector<std::string> args = {"test"};
    EXPECT_FALSE(subcomm.OnSubCommandOptions(args));
}

/**
 * @tc.name: OnSubCommandOptions_UnknownOptionAfterParse
 * @tc.desc: Test OnSubCommandOptions returns false when unknown args remain after parse
 * @tc.type: FUNC
 */
HWTEST_F(HiPerfSubcommandTest, OnSubCommandOptions_UnknownOptionAfterParse, TestSize.Level2)
{
    SubcommandLeaveArgs subcomm;
    std::vector<std::string> args = {"unknownopt"};
    EXPECT_FALSE(subcomm.OnSubCommandOptions(args));
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
