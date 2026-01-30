/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "hiperf_client.h"
#include "subcommand_record_test.h"
#include "perf_pipe_test.h"

#include <gtest/gtest.h>
#include <hilog/log.h>

using namespace testing::ext;
using namespace std::chrono;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
const std::chrono::milliseconds CONTROL_WAITREPY_TIMEOUT = 2000ms;
class PerfPipeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PerfPipeTest::SetUpTestCase() {}

void PerfPipeTest::TearDownTestCase() {}

void PerfPipeTest::SetUp() {}

void PerfPipeTest::TearDown() {}

/**
 * @tc.name: CreateFifoFile
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(PerfPipeTest, CreateRecordFifoFile, TestSize.Level0)
{
    PerfPipe perfPipe;
    std::string controlCmd = "prepare";
    std::string fifoFileC2S;
    std::string fifoFileS2C;
    perfPipe.SetFifoFileName(CommandType::RECORD, controlCmd, fifoFileC2S, fifoFileS2C);
    EXPECT_EQ(perfPipe.CreateFifoFile(), true);
    EXPECT_EQ(perfPipe.CreateFifoFile(), false);
    EXPECT_EQ(remove(fifoFileC2S.c_str()), 0);
    EXPECT_EQ(remove(fifoFileS2C.c_str()), 0);
}

/**
 * @tc.name: SendFifoAndWaitReply
 * @tc.desc: Test send Fifo and wait reply
 * @tc.type: FUNC
 */
HWTEST_F(PerfPipeTest, SendFifoAndWaitReply, TestSize.Level1)
{
    PerfPipe perfPipe;
    std::string controlCmd = "prepare";
    std::string fifoFileC2S;
    std::string fifoFileS2C;
    perfPipe.SetFifoFileName(CommandType::RECORD, controlCmd, fifoFileC2S, fifoFileS2C);
    EXPECT_EQ(perfPipe.SendFifoAndWaitReply(HiperfClient::REPLY_START, CONTROL_WAITREPY_TIMEOUT), false);
}

/**
 * @tc.name: ProcessControlCmd
 * @tc.desc: Test send Fifo and wait reply
 * @tc.type: FUNC
 */
HWTEST_F(PerfPipeTest, ProcessControlCmd, TestSize.Level1)
{
    PerfPipe perfPipe;
    std::string controlCmd = "prepare";
    std::string fifoFileC2S;
    std::string fifoFileS2C;
    perfPipe.SetFifoFileName(CommandType::RECORD, controlCmd, fifoFileC2S, fifoFileS2C);
    EXPECT_EQ(perfPipe.ProcessControlCmd(), false);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
