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

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
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
HWTEST_F(SubCommandListTest, TestOnSubCommandHW, TestSize.Level1)
{
    std::vector<std::string> args;
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    args = {"hw"};
    EXPECT_EQ(subCommandList.OnSubCommand(args), true);
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
    EXPECT_EQ(subCommandList.OnSubCommand(args), true);
    std::string stringOut = stdoutRecord.Stop();
}

/**
 * @tc.name: TestOnSubCommandTP
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandListTest, TestOnSubCommandTP, TestSize.Level1)
{
    std::vector<std::string> args;
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    args = {"tp"};
    EXPECT_EQ(subCommandList.OnSubCommand(args), true); // still not support
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
    EXPECT_EQ(subCommandList.OnSubCommand(args), true);
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
    EXPECT_EQ(subCommandList.OnSubCommand(args), true);
    std::string stringOut = stdoutRecord.Stop();
}

/**
 * @tc.name: TestOnSubCommandERROR
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandListTest, TestOnSubCommandERROR, TestSize.Level1)
{
    std::vector<std::string> args;
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    args = {"error"};
    EXPECT_EQ(subCommandList.OnSubCommand(args), false);
    std::string stringOut = stdoutRecord.Stop();
}

/**
 * @tc.name: TestOnSubCommandEmpty
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandListTest, TestOnSubCommandEmpty, TestSize.Level1)
{
    std::vector<std::string> args;
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    args.clear();
    EXPECT_EQ(subCommandList.OnSubCommand(args), true);
    std::string stringOut = stdoutRecord.Stop();
}

/**
 * @tc.name: TestRegisterSubCommandList
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandListTest, TestRegisterSubCommandList, TestSize.Level1)
{
    subCommandList.RegisterSubCommandList();
    EXPECT_EQ(1, 1);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
