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

#include "subcommand_list_test.h"

#include "subcommand_list.h"
#include "subcommand.h"

using namespace testing::ext;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class SubCommandListTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    SubCommandList subCommandList;
};

void SubCommandListTest::SetUpTestCase() {}

void SubCommandListTest::TearDownTestCase() {}

void SubCommandListTest::SetUp() {}

void SubCommandListTest::TearDown() {}

/**
 * @tc.name: TestOnSubCommandHW
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandListTest, TestOnSubCommandHW, TestSize.Level0)
{
    std::vector<std::string> args;
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    args = {"hw"};
    EXPECT_EQ(subCommandList.OnSubCommand(args), HiperfError::NO_ERR);
    std::string stringOut = stdoutRecord.Stop();
}

/**
 * @tc.name: TestOnSubCommandSW
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandListTest, TestOnSubCommandSW, TestSize.Level1)
{
    std::vector<std::string> args;
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    args = {"sw"};
    EXPECT_EQ(subCommandList.OnSubCommand(args), HiperfError::NO_ERR);
    std::string stringOut = stdoutRecord.Stop();
}

/**
 * @tc.name: TestOnSubCommandTP
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandListTest, TestOnSubCommandTP, TestSize.Level2)
{
    std::vector<std::string> args;
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    args = {"tp"};
    EXPECT_EQ(subCommandList.OnSubCommand(args), HiperfError::NO_ERR); // still not support
    std::string stringOut = stdoutRecord.Stop();
}

/**
 * @tc.name: TestOnSubCommandCACHE
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandListTest, TestOnSubCommandCACHE, TestSize.Level1)
{
    std::vector<std::string> args;
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    args = {"cache"};
    EXPECT_EQ(subCommandList.OnSubCommand(args), HiperfError::NO_ERR);
    std::string stringOut = stdoutRecord.Stop();
}

/**
 * @tc.name: TestOnSubCommandRAW
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandListTest, TestOnSubCommandRAW, TestSize.Level1)
{
    std::vector<std::string> args;
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    args = {"raw"};
    EXPECT_EQ(subCommandList.OnSubCommand(args), HiperfError::NO_ERR);
    std::string stringOut = stdoutRecord.Stop();
}

/**
 * @tc.name: TestOnSubCommandERROR
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandListTest, TestOnSubCommandERROR, TestSize.Level3)
{
    std::vector<std::string> args;
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    args = {"error"};
    EXPECT_EQ(subCommandList.OnSubCommand(args), HiperfError::OPTION_NOT_SUPPORT);
    std::string stringOut = stdoutRecord.Stop();
}

/**
 * @tc.name: TestOnSubCommandEmpty
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandListTest, TestOnSubCommandEmpty, TestSize.Level2)
{
    std::vector<std::string> args;
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    args.clear();
    EXPECT_EQ(subCommandList.OnSubCommand(args), HiperfError::NO_ERR);
    std::string stringOut = stdoutRecord.Stop();
}

/**
 * @tc.name: TestRegisterSubCommandList
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandListTest, TestRegisterSubCommandList, TestSize.Level1)
{
    SubCommand::ClearSubCommands();
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
    subCommandList.RegisterSubCommandList();
    SubCommand::RegisterSubCommand("list", std::make_unique<SubCommandList>());
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 1u);
}

/**
 * @tc.name: GetInstance
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandListTest, GetInstance, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    EXPECT_EQ(SubCommandList::GetInstance().Name(), "list");
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
