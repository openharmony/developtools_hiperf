
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
    void TearDown();
};

void CmdOutputTest::SetUpTestCase()
{
    if (chmod("/data/test/hiperf_test_demo", 0755) == -1) { // 0755 : -rwxr-xr-x
        GTEST_LOG_(ERROR) << "hiperf_test_demo chmod failed.";
    }
    system("/data/test/hiperf_test_demo &");
}

void CmdOutputTest::TearDownTestCase()
{
    DebugLogger::GetInstance()->Reset();
    if (system("kill -9 `pidof hiperf_test_demo`") != 0) {
        GTEST_LOG_(ERROR) << "kill hiperf_test_demo failed.";
    }
}

void CmdOutputTest::SetUp() {
}

void CmdOutputTest::TearDown() {
}

/**
 * @tc.name: RecordCommand_ControlStartStop_FailureCase
 * @tc.desc: start, stop
 * @tc.type: FUNC
 */
HWTEST_F(CmdOutputTest, RecordCommand_ControlStartStop_FailureCase, TestSize.Level1)
{
    ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control start", {"start sampling failed"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling failed"}),
 	          true);
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlAllActions_SuccessCase, TestSize.Level0)
{
    ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control prepare -a", {"create control hiperf sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control start", {"start sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control pause", {"pause sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control resume", {"resume sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}),
 	          true);
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepare_DuplicateRun_ConflictCase, TestSize.Level1)
{
    ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control prepare -a", {"create control hiperf sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control prepare -a", {"another sampling service is running"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}),
 	          true);
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepareStart_DuplicateStart_SuccessCase, TestSize.Level1)
{
    ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control prepare -a", {"create control hiperf sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control start", {"start sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control start", {"start sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}),
 	          true);
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepare_PauseResumeWithoutStart_FailureCase, TestSize.Level1)
{
    ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control prepare -a", {"create control hiperf sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control pause", {"pause sampling failed"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control resume", {"resume sampling failed"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}),
 	          true);
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepareStart_DuplicateResumePause_SuccessCase, TestSize.Level1)
{
 	ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control prepare -a", {"create control hiperf sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control start", {"start sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control resume", {"resume sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control resume", {"resume sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control pause", {"pause sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control pause", {"pause sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}),
 	          true);
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepareStartStop_DuplicateStop_FailureCase, TestSize.Level1)
{
 	ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control prepare -a", {"create control hiperf sampling success"}),
 	          true);
 	EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control start", {"start sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling failed"}),
 	          true);
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepareWithBacktrack_StartDuplicateOutput_SuccessCase, TestSize.Level0)
{
 	ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control prepare -a --backtrack",
 	                                 {"create control hiperf sampling success"}),
 	          true);
 	EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control start", {"start sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control output", {"output sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control output", {"output sampling success"}),
 	          true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}),
 	          true);
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepareWithApp_Stop_SuccessCase, TestSize.Level0)
{
 	ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control prepare --app hiperf_test_demo",
 	                                 {"create control hiperf sampling success"}), true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}), true);
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepareWithApp_AppNotRunning_FailureCase, TestSize.Level1)
{
    ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    RunCmd("am force-stop com.example.insight_test_stage");
    std::vector<std::string> get_app_pids;
    GetAppPids("pidof com.example.insight_test_stage", get_app_pids);
    ASSERT_TRUE(get_app_pids.empty());
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control prepare --app com.example.insight_test_stage",
 	                                 {"app com.example.insight_test_stage not running"}), true);
    RunCmd("hiperf record --control stop");
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepareWithPid_HuksService_SuccessCase, TestSize.Level1)
{
    std::vector<std::string> get_app_pids;
    ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    GetAppPids("pidof hiperf_test_demo", get_app_pids);
    ASSERT_FALSE(get_app_pids.empty()) << "hiperf_test_demo process not found, test aborted";
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control prepare -p " + get_app_pids[0],
 	                                 {"create control hiperf sampling success"}), true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}),
 	          true);
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepareWithPidRestart_MissingAppOption_FailureCase, TestSize.Level1)
{
    std::vector<std::string> get_app_pids;
 	ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    GetAppPids("pidof hiperf_test_demo", get_app_pids);
    ASSERT_FALSE(get_app_pids.empty()) << "hiperf_test_demo process not found, test aborted";
    std::string pid = get_app_pids[0];
    ASSERT_FALSE(pid.empty()) << "The obtained PID is an empty string, test aborted";
    if (!pid.empty() && pid.back() == '\n') {
        pid.pop_back();
    }
    std::string cmd_str = "hiperf record --control prepare -p " + pid + " --restart";
    EXPECT_EQ(CheckTraceCommandOutput(cmd_str, {"to detect the performance of application startup,"
 	                                            " --app option must be given"}), true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}),
 	          true);
}

HWTEST_F(CmdOutputTest, RecordCommand_RecordWithDurationApp_SuccessCase, TestSize.Level0)
{
	ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record -d 3 --app hiperf_test_demo",
                                     {"Profiling duration is 3.000 seconds"}), true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}),
 	          true);
}

HWTEST_F(CmdOutputTest, RecordCommand_RecordWithDurationApp_AppNotRunning_FailureCase, TestSize.Level0)
{
	ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    std::vector<std::string> get_app_pids;
    GetAppPids("pidof hiperf_test_demo", get_app_pids);
    if (!get_app_pids.empty()) {
        for (const auto& pid : get_app_pids) {
            int kill_ret = RunCmd("kill -9 " + pid);
            ASSERT_EQ(kill_ret, 0);
            GTEST_LOG_(INFO) << "kill hiperf_test_demo failed." << "PID:" << pid << "）";
        }
    }
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record -d 3 --app hiperf_test_demo",
                                     {"app hiperf_test_demo not running"}), true);
    RunCmd("hiperf record --control stop");
}

HWTEST_F(CmdOutputTest, RecordCommand_RecordWithDurationPid_HuksService_OutputCorrectDurationPrompt_SuccessCase,
 	     TestSize.Level1)
{
	ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    std::vector<std::string> get_app_pids;
    GetAppPids("pidof hiperf_test_demo", get_app_pids);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record -d 3 -p " + get_app_pids[0],
		     {"Profiling duration is 3.000 seconds"}), true);
    RunCmd("hiperf record --control stop");
}

HWTEST_F(CmdOutputTest, RecordCommand_RecordWithDurationPidRestart_HuksService_MissingAppOption_FailureCase,
 	     TestSize.Level1)
{
	ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    std::vector<std::string> get_app_pids;
    GetAppPids("pidof hiperf_test_demo", get_app_pids);
    ASSERT_FALSE(get_app_pids.empty()) << "hiperf_test_demo process not found, test aborted";
    std::string pid = get_app_pids[0];
    ASSERT_FALSE(pid.empty()) << "The obtained PID is an empty string, test aborted";
    if (!pid.empty() && pid.back() == '\n') {
 	    pid.pop_back();
    }
    std::string cmd_str = "hiperf record -d 3 -p " + pid + " --restart";
    EXPECT_EQ(CheckTraceCommandOutput(cmd_str, {"to detect the performance of application startup,"
 	                                             " --app option must be given"}), true);
    RunCmd("hiperf record --control stop");
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepareWithApp_BooksApp_AppNotRunning_FailureCase, TestSize.Level1)
{
    ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    RunCmd("am force-stop example.app.books");
    std::vector<std::string> get_app_pids;
    GetAppPids("pidof example.app.books", get_app_pids);
    ASSERT_TRUE(get_app_pids.empty());
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control prepare --app example.app.books",
                                     {"app example.app.books not running"}), true);
    RunCmd("hiperf record --control stop");
}

HWTEST_F(CmdOutputTest, RecordCommand_RecordWithDurationAppOutput_InsightTestApp_AppNotRunning_FailureCase,
 	     TestSize.Level1)
{
    ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record -d 3 --app hiperf_test_demo -o /data123/perf.data",
                                     {"app hiperf_test_demo not running"}), true);
    RunCmd("hiperf record --control stop");
}

HWTEST_F(CmdOutputTest, RecordCommand_ControlPrepareWithAppOutput_InsightTestApp_AppNotRunning_FailureCase,
 	     TestSize.Level1)
{
	ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    EXPECT_EQ(CheckTraceCommandOutput(
 	          "hiperf record --control prepare --app hiperf_test_demo -o /data123/perf.data",
              {"app hiperf_test_demo not running"}), true);
	RunCmd("hiperf record --control stop");
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS