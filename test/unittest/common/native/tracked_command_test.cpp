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
#include <memory>
#include <string>
#include <vector>

#include "tracked_command.h"
#include "tracked_command_test.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class TrackedCommandTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    const vector<string> cmd_ {"ls"};
    const vector<string> cmdNotExist_ {"not_a_command"};
};

void TrackedCommandTest::SetUpTestCase() {}

void TrackedCommandTest::TearDownTestCase() {}

void TrackedCommandTest::SetUp() {}

void TrackedCommandTest::TearDown() {}

HWTEST_F(TrackedCommandTest, CommandExisted, TestSize.Level1)
{
    unique_ptr<TrackedCommand> trackedCMD = TrackedCommand::CreateInstance(cmd_);
    ASSERT_NE(trackedCMD, nullptr);
    auto cmdName = trackedCMD->GetCommandName();
    EXPECT_EQ(cmdName, cmd_[0]);
    auto state = trackedCMD->GetState();
    EXPECT_EQ(state, TrackedCommand::State::COMMAND_WAITING);
    auto pid = trackedCMD->GetChildPid();
    EXPECT_NE(pid, -1);
    bool res = trackedCMD->StartCommand();
    EXPECT_TRUE(res);
    state = trackedCMD->GetState();
    EXPECT_EQ(state, TrackedCommand::State::COMMAND_STARTED);
    int wstatus {0};
    res = trackedCMD->WaitCommand(wstatus);
    state = trackedCMD->GetState();
    if (res) {
        EXPECT_EQ(state, TrackedCommand::State::COMMAND_STOPPED);
    } else {
        EXPECT_NE(state, TrackedCommand::State::COMMAND_STOPPED);
    }
}

HWTEST_F(TrackedCommandTest, CommandNotExisted, TestSize.Level1)
{
    unique_ptr<TrackedCommand> trackedCMD = TrackedCommand::CreateInstance(cmdNotExist_);
    ASSERT_NE(trackedCMD, nullptr);
    auto cmdName = trackedCMD->GetCommandName();
    EXPECT_EQ(cmdName, cmdNotExist_[0]);
    auto state = trackedCMD->GetState();
    EXPECT_EQ(state, TrackedCommand::State::COMMAND_WAITING);
    auto pid = trackedCMD->GetChildPid();
    EXPECT_NE(pid, -1);
    bool res = trackedCMD->StartCommand();
    EXPECT_FALSE(res);
    state = trackedCMD->GetState();
    EXPECT_EQ(state, TrackedCommand::State::COMMAND_FAILURE);
    int wstatus {0};
    res = trackedCMD->WaitCommand(wstatus);
    state = trackedCMD->GetState();
    if (res) {
        EXPECT_EQ(state, TrackedCommand::State::COMMAND_STOPPED);
    } else {
        EXPECT_NE(state, TrackedCommand::State::COMMAND_STOPPED);
    }
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
