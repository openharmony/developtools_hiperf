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

#include "command_test.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
const std::string TEST_CMD_TRUE = "TEST_CMD_TRUE";
const std::string TEST_CMD_FALSE = "TEST_CMD_FALSE";
const std::string TEST_OPTION_TRUE = "-TEST_OPTION_TRUE";
const std::string TEST_OPTION_FALSE = "-TEST_OPTION_FALSE";

class CommandTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

private:
    std::unique_ptr<MockSubCommand> subCommandAlwaysTure =
        std::make_unique<MockSubCommand>(TEST_CMD_TRUE);
    std::unique_ptr<MockSubCommand> subCommandAlwaysFalse =
        std::make_unique<MockSubCommand>(TEST_CMD_FALSE);
};

void CommandTest::SetUpTestCase() {}

void CommandTest::TearDownTestCase() {}

void CommandTest::SetUp()
{
    ASSERT_EQ(Option::RegisterMainOption(TEST_OPTION_TRUE, TEST_OPTION_HELP, OptionAlwaysTrue),
              true);
    ASSERT_EQ(Option::RegisterMainOption(TEST_OPTION_FALSE, TEST_OPTION_HELP, OptionAlwaysFalse),
              true);

    EXPECT_CALL(*subCommandAlwaysTure, OnSubCommand(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*subCommandAlwaysFalse, OnSubCommand(_)).WillRepeatedly(Return(false));

    ASSERT_TRUE(SubCommand::RegisterSubCommand(subCommandAlwaysTure.get()->Name(),
                                               std::move(subCommandAlwaysTure)));
    ASSERT_TRUE(SubCommand::RegisterSubCommand(subCommandAlwaysFalse.get()->Name(),
                                               std::move(subCommandAlwaysFalse)));
}

void CommandTest::TearDown()
{
    SubCommand::ClearSubCommands();
    Option::ClearMainOptions();
}

/**
 * @tc.name: TestCommandDistribution
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CommandTest, TestCommandDistribution, TestSize.Level1)
{
    std::string args;

    args = TEST_OPTION_TRUE + " " + TEST_OPTION_TRUE + " " + TEST_OPTION_TRUE;
    EXPECT_EQ(Command::DispatchCommand(args), false);

    args = TEST_OPTION_TRUE + " " + TEST_OPTION_TRUE + " " + TEST_CMD_TRUE;
    EXPECT_EQ(Command::DispatchCommand(args), true);

    args = TEST_OPTION_TRUE + " " + TEST_CMD_TRUE + " " + TEST_OPTION_TRUE;
    EXPECT_EQ(Command::DispatchCommand(args), true);

    args = TEST_CMD_TRUE + " " + TEST_OPTION_TRUE + " " + TEST_OPTION_TRUE;
    EXPECT_EQ(Command::DispatchCommand(args), true);

    args = TEST_CMD_TRUE + " " + TEST_CMD_TRUE + " " + TEST_CMD_TRUE;
    EXPECT_EQ(Command::DispatchCommand(args), true);

    args = TEST_NOREG_CMD + " " + TEST_CMD_TRUE + " " + TEST_CMD_TRUE;
    EXPECT_EQ(Command::DispatchCommand(args), false);

    args = TEST_NO_OPTION_CMD + " " + TEST_CMD_TRUE + " " + TEST_CMD_TRUE;
    EXPECT_EQ(Command::DispatchCommand(args), false);

    args = TEST_CMD_TRUE + " " + TEST_NOREG_CMD + " " + TEST_CMD_TRUE;
    EXPECT_EQ(Command::DispatchCommand(args), true);

    args = TEST_OPTION_FALSE + " " + TEST_CMD_TRUE + " " + TEST_CMD_TRUE;
    EXPECT_EQ(Command::DispatchCommand(args), false);

    args = TEST_OPTION_TRUE + " " + TEST_CMD_FALSE + " " + TEST_CMD_TRUE;
    EXPECT_EQ(Command::DispatchCommand(args), false);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
