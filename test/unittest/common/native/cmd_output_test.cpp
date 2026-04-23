
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "cmd_output_test.h"
#include <gtest/gtest.h>
#include <hilog/log.h>
#include "test_utilities.h"
 	 
using namespace testing::ext;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class CmdOutputTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
};

void CmdOutputTest::SetUpTestCase()
{
    if (chmod("/data/test/hiperf_test_demo", 0755) == -1) { // 0755 : -rwxr-xr-x
        GTEST_LOG_(ERROR) << "hiperf_test_demo chmod failed.";
    }
    (void)system("/data/test/hiperf_test_demo &");
}

void CmdOutputTest::TearDownTestCase()
{
    DebugLogger::GetInstance()->Reset();
    if (system("kill -9 `pidof hiperf_test_demo`") != 0) {
        GTEST_LOG_(ERROR) << "kill hiperf_test_demo failed.";
    }
}

void CmdOutputTest::SetUp()
{
    ASSERT_TRUE(RunCmd("hiperf record --control stop"));
}

/**
 * @tc.name: RecordCommand_ControlStartStop_FailureCase
 * @tc.desc: start, stop
 * @tc.type: FUNC
 */
HWTEST_F(CmdOutputTest, RecordCommand_ControlStartStop_FailureCase, TestSize.Level1)
{
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control start", {"start sampling failed"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling failed"}));
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlAllActions_SuccessCase, TestSize.Level0)
{
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control prepare -a",
               {"create control hiperf sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control start", {"start sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control pause", {"pause sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control resume", {"resume sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}));
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepare_DuplicateRun_ConflictCase, TestSize.Level1)
{
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control prepare -a",
               {"create control hiperf sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control prepare -a",
               {"another sampling service is running"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}));
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepareStart_DuplicateStart_SuccessCase, TestSize.Level1)
{
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control prepare -a",
               {"create control hiperf sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control start", {"start sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control start", {"start sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}));
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepare_PauseResumeWithoutStart_FailureCase, TestSize.Level1)
{
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control prepare -a",
               {"create control hiperf sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control pause", {"pause sampling failed"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control resume", {"resume sampling failed"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}));
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepareStart_DuplicateResumePause_SuccessCase, TestSize.Level1)
{
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control prepare -a",
               {"create control hiperf sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control start", {"start sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control resume", {"resume sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control resume", {"resume sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control pause", {"pause sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control pause", {"pause sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}));
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepareStartStop_DuplicateStop_FailureCase, TestSize.Level1)
{
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control prepare -a",
               {"create control hiperf sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control start", {"start sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling failed"}));
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepareWithBacktrack_StartDuplicateOutput_SuccessCase, TestSize.Level0)
{
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control prepare -a --backtrack",
 	                                 {"create control hiperf sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control start", {"start sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control output", {"output sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control output", {"output sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}));
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepareWithApp_Stop_SuccessCase, TestSize.Level0)
{
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control prepare --app hiperf_test_demo",
 	                                 {"create control hiperf sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}));
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepareWithPid_HuksService_SuccessCase, TestSize.Level1)
{
    std::vector<std::string> appPids;
    GetAppPids(std::string("hiperf_test_demo"), appPids);
    EXPECT_FALSE(appPids.empty());
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control prepare -p " + appPids[0],
 	                                 {"create control hiperf sampling success"}));
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}));
}

HWTEST_F(CmdOutputTest, RecordCommand_RecordWithDurationPid_HuksService_OutputCorrectDurationPrompt_SuccessCase,
 	     TestSize.Level1)
{
    std::vector<std::string> appPids;
    GetAppPids(std::string("hiperf_test_demo"), appPids);
    EXPECT_FALSE(appPids.empty());
    EXPECT_TRUE(CheckTraceCommandOutput("hiperf record -d 3 -p " + appPids[0],
		       {"Profiling duration is 3.000 seconds"}));
    RunCmd("hiperf record --control stop");
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS