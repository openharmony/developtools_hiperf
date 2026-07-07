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

#include "hiperf_client_test.h"

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <csignal>
#include <thread>

#include "test_utilities.h"
#include "utilities.h"

using namespace testing::ext;
using namespace std;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
const int DEFAULT_DURATION_TIME = 10;
class HiperfClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static void TestCaseOption(const HiperfClient::RecordOption &opt);
};

void HiperfClientTest::SetUpTestCase()
{
    if (chmod("/data/test/hiperf_test_demo", 0755) == -1) { // 0755 : -rwxr-xr-x
        GTEST_LOG_(ERROR) << "hiperf_test_demo chmod failed.";
    }
    if (system("/data/test/hiperf_test_demo &") != 0) {
        GTEST_LOG_(ERROR) << "start hiperf_test_demo failed.";
    } else {
        GTEST_LOG_(INFO) << "start hiperf_test_demo success.";
    }
}

void HiperfClientTest::TearDownTestCase()
{
    DebugLogger::GetInstance()->Reset();
    if (system("kill -9 `pidof hiperf_test_demo`") != 0) {
        GTEST_LOG_(ERROR) << "kill hiperf_test_demo failed.";
    } else {
        GTEST_LOG_(INFO) << "kill hiperf_test_demo success.";
    }
}

void HiperfClientTest::SetUp() {}

void HiperfClientTest::TearDown() {}

/**
 * @tc.name:
 * @tc.desc: record
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, NoPara, TestSize.Level0)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    HiperfClient::Client myHiperf;
    myHiperf.SetDebugMode();
    ASSERT_TRUE(myHiperf.Start());

    ASSERT_TRUE(myHiperf.Pause());
    std::this_thread::sleep_for(100ms);

    ASSERT_TRUE(myHiperf.Resume());
    std::this_thread::sleep_for(100ms);

    ASSERT_TRUE(myHiperf.Stop());

    stdoutRecord.Stop();
}

HWTEST_F(HiperfClientTest, OutDir, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    HiperfClient::Client myHiperf("/data/local/tmp/");
    ASSERT_EQ(myHiperf.GetOutputDir(), "/data/local/tmp/");
    myHiperf.SetDebugMode();
    ASSERT_TRUE(myHiperf.Start());

    ASSERT_TRUE(myHiperf.Pause());
    std::this_thread::sleep_for(100ms);

    ASSERT_TRUE(myHiperf.Resume());
    std::this_thread::sleep_for(100ms);

    ASSERT_TRUE(myHiperf.Stop());

    stdoutRecord.Stop();
}

HWTEST_F(HiperfClientTest, DebugMuchMode, TestSize.Level0)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    HiperfClient::Client myHiperf;
    myHiperf.SetDebugMuchMode();
    ASSERT_TRUE(myHiperf.Start());

    ASSERT_TRUE(myHiperf.Pause());
    std::this_thread::sleep_for(100ms);

    ASSERT_TRUE(myHiperf.Resume());
    std::this_thread::sleep_for(100ms);

    ASSERT_TRUE(myHiperf.Stop());

    stdoutRecord.Stop();
}

HWTEST_F(HiperfClientTest, EnableHilog, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    HiperfClient::Client myHiperf;
    myHiperf.SetDebugMode();
    myHiperf.EnableHilog();
    ASSERT_TRUE(myHiperf.Start());

    ASSERT_TRUE(myHiperf.Pause());
    std::this_thread::sleep_for(100ms);

    ASSERT_TRUE(myHiperf.Resume());
    std::this_thread::sleep_for(100ms);

    ASSERT_TRUE(myHiperf.Stop());

    stdoutRecord.Stop();
}

HWTEST_F(HiperfClientTest, Prepare, TestSize.Level0)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    HiperfClient::RecordOption opt;
    opt.SetTargetSystemWide(true);

    HiperfClient::Client myHiperf("/data/local/tmp/");
    ASSERT_TRUE(myHiperf.PrePare(opt));
    std::this_thread::sleep_for(100ms);

    ASSERT_TRUE(myHiperf.StartRun());
    std::this_thread::sleep_for(100ms);

    ASSERT_TRUE(myHiperf.Stop());

    stdoutRecord.Stop();
}

HWTEST_F(HiperfClientTest, GetCommandPath, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    HiperfClient::Client myHiperf("/data/local/tmp/");
    ASSERT_EQ(myHiperf.GetCommandPath().empty(), false);

    stdoutRecord.Stop();
}

void HiperfClientTest::TestCaseOption(const HiperfClient::RecordOption &opt)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    HiperfClient::Client myHiperf;
    myHiperf.SetDebugMode();

    ASSERT_TRUE(myHiperf.IsReady());
    ASSERT_TRUE(myHiperf.Start(opt));

    bool retPause = true;
    bool retResume = true;
    bool retStop = true;
    if (!myHiperf.Pause()) {
        retPause = false;
    }
    std::this_thread::sleep_for(100ms);

    if (!myHiperf.Resume()) {
        retResume = false;
    }
    std::this_thread::sleep_for(100ms);

    if (!myHiperf.Stop()) {
        retStop = false;
    }

    ASSERT_TRUE(retPause);
    ASSERT_TRUE(retResume);
    ASSERT_TRUE(retStop);

    stdoutRecord.Stop();
}

HWTEST_F(HiperfClientTest, SetTargetSystemWide, TestSize.Level0)
{
    HiperfClient::RecordOption opt;
    opt.SetTargetSystemWide(true);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetCompressData, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetCompressData(true);
    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetSelectCpus, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    std::vector<int> cpus = {0, 1};
    opt.SetSelectCpus(cpus);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetTimeStopSec, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetTimeStopSec(2);

    HiperfClient::Client myHiperf;
    ASSERT_TRUE(myHiperf.IsReady());
    ASSERT_TRUE(myHiperf.Start(opt));
}

HWTEST_F(HiperfClientTest, SetFrequency, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetFrequency(500);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetPeriod, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetPeriod(3);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetSelectEvents, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    std::vector<std::string> selectEvents = {"hw-cpu-cycles:k"};
    opt.SetSelectEvents(selectEvents);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetSelectGroups, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    std::vector<std::string> selectEvents = {"hw-cpu-cycles:u"};
    opt.SetSelectGroups(selectEvents);
    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetNoInherit, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetNoInherit(true);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetSelectPids, TestSize.Level0)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetCallStackSamplingConfigs, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetCallStackSamplingConfigs(1);

    HiperfClient::Client myHiperf;
    ASSERT_TRUE(myHiperf.IsReady());
    ASSERT_TRUE(myHiperf.Start(opt));
}

HWTEST_F(HiperfClientTest, SetSelectTids, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectTids = {gettid()};
    opt.SetSelectTids(selectTids);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetExcludePerf, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    opt.SetTargetSystemWide(true);
    opt.SetExcludePerf(true);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetCpuPercent, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetCpuPercent(50);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetOffCPU, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetOffCPU(true);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetCallStack, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetCallGraph("fp");

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetDelayUnwind, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetDelayUnwind(true);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetDisableUnwind, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetDisableUnwind(true);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetDisableCallstackMerge, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetDisableCallstackMerge(true);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetOutputFilename, TestSize.Level0)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetOutputFilename("perf.data.ut");

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetSymbolDir, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetSymbolDir("/data/local/tmp/");

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetDataLimit, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetDataLimit("100M");

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetAppPackage, TestSize.Level0)
{
    HiperfClient::RecordOption opt;
    opt.SetAppPackage("hiperf_test_demo");

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetClockId, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetClockId("monotonic");

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetMmapPages, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetMmapPages(64);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetReport, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetReport(true);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetVecBranchSampleTypes, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetCallStackSamplingConfigs(1);
    std::vector<std::string> branchSampleTypes = {"any"};
    opt.SetVecBranchSampleTypes(branchSampleTypes);
    HiperfClient::Client myHiperf;
    ASSERT_TRUE(myHiperf.IsReady());
}

HWTEST_F(HiperfClientTest, Output, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    std::vector<std::string> process = {"hilogd"};
    opt.SetTargetSystemWide(true);
    opt.SetBackTrack(true);
    opt.SetBackTrackSec(10); // 10 : 10s
    opt.SetExcludeProcess(process);

    HiperfClient::Client myHiperf("/data/local/tmp/");
    EXPECT_TRUE(myHiperf.PrePare(opt));
    std::this_thread::sleep_for(100ms);
    EXPECT_FALSE(myHiperf.Output());
    std::this_thread::sleep_for(100ms);
    EXPECT_TRUE(myHiperf.Stop());
}

/**
 * @tc.desc: SetCallStackSamplingConfigs(int duration)
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, SetCallStackSamplingConfigsWithZeroDuration, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetCallStackSamplingConfigs(0);

    bool hasTimeStopSec = false;
    int actualDuration = 0;
    for (size_t i = 0; i < opt.GetOptionVecString().size(); i++) {
        if (opt.GetOptionVecString()[i] == "-d") {
            hasTimeStopSec = true;
            actualDuration = std::stoi(opt.GetOptionVecString()[i + 1]);
            break;
        }
    }
    ASSERT_TRUE(hasTimeStopSec);
    ASSERT_EQ(actualDuration, DEFAULT_DURATION_TIME);
}

/**
 * @tc.desc: SetOption(const std::string &name, bool enable)
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, SetOptionRemoveExistingArgument, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    const std::string targetArg = "-a";

    opt.SetOption(targetArg, true);
    auto args = opt.GetOptionVecString();
    ASSERT_TRUE(std::find(args.begin(), args.end(), targetArg) != args.end());

    opt.SetOption(targetArg, false);
    args = opt.GetOptionVecString();

    auto it = std::find(args.begin(), args.end(), targetArg);
    ASSERT_TRUE(it == args.end());
}

/**
 * @tc.desc: SetOption(const std::string &name, const std::vector<int> &vInt)
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, RemoveExistingOptionWithEmptyVectorOfInt, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    opt.SetOption("-c", std::vector<int>{1, 2, 3});

    auto args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 2);
    ASSERT_EQ(args[0], "-c");
    ASSERT_EQ(args[1], "1,2,3");

    opt.SetOption("-c", std::vector<int>{});

    args = opt.GetOptionVecString();
    auto it = std::find(args.begin(), args.end(), "-c");
    ASSERT_EQ(it, args.end());
}

/**
 * @tc.desc: SetOption(const std::string &name, const std::vector<int> &vInt)
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, UpdateExistingOption, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    opt.SetOption("-c", std::vector<int>{1, 2});

    auto args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 2);
    ASSERT_EQ(args[0], "-c");
    ASSERT_EQ(args[1], "1,2");

    opt.SetOption("-c", std::vector<int>{3, 4, 5});

    args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 2);
    ASSERT_EQ(args[0], "-c");
    ASSERT_EQ(args[1], "3,4,5");
}

/**
 * @tc.desc: SetOption(const std::string &name, const std::string &str)
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, RemoveExistingOptionWithEmptyString, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    opt.SetOption("-o", std::string("perf.data"));

    auto args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 2);
    ASSERT_EQ(args[0], "-o");
    ASSERT_EQ(args[1], "perf.data");

    opt.SetOption("-o", std::string(""));

    args = opt.GetOptionVecString();
    auto it = std::find(args.begin(), args.end(), "-o");
    ASSERT_EQ(it, args.end());
}

/**
 * @tc.desc: SetOption(const std::string &name, const std::vector<std::string> &vStr)
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, RemoveExistingOptionWithEmptyVectorOfString, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    opt.SetOption("-e", std::vector<std::string>{"hw-cpu-cycles", "hw-instructions"});

    auto args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 2);
    ASSERT_EQ(args[0], "-e");
    ASSERT_EQ(args[1], "hw-cpu-cycles,hw-instructions");

    opt.SetOption("-e", std::vector<std::string>{});

    args = opt.GetOptionVecString();
    auto it = std::find(args.begin(), args.end(), "-e");
    ASSERT_EQ(it, args.end());
}

/**
 * @tc.desc: SetOption(const std::string &name, const std::vector<std::string> &vStr)
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, UpdateExistingOptionWithVector, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    opt.SetOption("-e", std::vector<std::string>{"hw-cpu-cycles", "hw-instructions"});

    auto args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 2);
    ASSERT_EQ(args[0], "-e");
    ASSERT_EQ(args[1], "hw-cpu-cycles,hw-instructions");

    opt.SetOption("-e", std::vector<std::string>{"hw-cache-references", "hw-cache-misses"});

    args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 2);
    ASSERT_EQ(args[0], "-e");
    ASSERT_EQ(args[1], "hw-cache-references,hw-cache-misses");
}

/**
 * @tc.desc: SetOption(int) - key is last element without value (heap overflow fix)
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, SetOptionIntKeyIsLastElementNoValue, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    opt.SetOption("-a", true);

    auto args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 1);
    ASSERT_EQ(args[0], "-a");

    opt.SetOption("-a", 100);

    args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 1);
    ASSERT_EQ(args[0], "-a");
}

/**
 * @tc.desc: SetOption(vector<int>) - key is last element without value (heap overflow fix)
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, SetOptionVectorIntKeyIsLastElementNoValue, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    opt.SetOption("-a", true);

    auto args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 1);
    ASSERT_EQ(args[0], "-a");

    opt.SetOption("-a", std::vector<int>{1, 2});

    args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 1);
    ASSERT_EQ(args[0], "-a");
}

/**
 * @tc.desc: SetOption(string) - key is last element without value (heap overflow fix)
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, SetOptionStringKeyIsLastElementNoValue, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    opt.SetOption("-a", true);

    auto args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 1);
    ASSERT_EQ(args[0], "-a");

    opt.SetOption("-a", std::string("perf.data"));

    args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 1);
    ASSERT_EQ(args[0], "-a");
}

/**
 * @tc.desc: SetOption(vector<string>) - key is last element without value (heap overflow fix)
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, SetOptionVectorStringKeyIsLastElementNoValue, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    opt.SetOption("-a", true);

    auto args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 1);
    ASSERT_EQ(args[0], "-a");

    opt.SetOption("-a", std::vector<std::string>{"hw-cpu-cycles"});

    args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 1);
    ASSERT_EQ(args[0], "-a");
}

/**
 * @tc.desc: SetOption(string) - empty string, key is last element without value (erase fix)
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, SetOptionStringEmptyKeyLastNoValue, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    opt.SetOption("-a", true);

    auto args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 1);
    ASSERT_EQ(args[0], "-a");

    opt.SetOption("-a", std::string(""));

    args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 0);
}

/**
 * @tc.desc: SetOption(vector<string>) - empty vector, key is last element without value (erase fix)
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, SetOptionVectorStringEmptyKeyLastNoValue, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    opt.SetOption("-a", true);

    auto args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 1);
    ASSERT_EQ(args[0], "-a");

    opt.SetOption("-a", std::vector<std::string>{});

    args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 0);
}

/**
 * @tc.name: SetSyncCmdStoppable_DefaultFalse
 * @tc.desc: Test IsSyncCmdStoppable returns false by default
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, SetSyncCmdStoppable_DefaultFalse, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    EXPECT_FALSE(opt.IsSyncCmdStoppable());
}

/**
 * @tc.name: SetSyncCmdStoppable_Enable
 * @tc.desc: Test SetSyncCmdStoppable enables stoppable sync cmd mode
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, SetSyncCmdStoppable_Enable, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    opt.SetSyncCmdStoppable(true);
    EXPECT_TRUE(opt.IsSyncCmdStoppable());
}

/**
 * @tc.name: SetSyncCmdStoppable_Disable
 * @tc.desc: Test SetSyncCmdStoppable can be disabled after enabled
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, SetSyncCmdStoppable_Disable, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    opt.SetSyncCmdStoppable(true);
    EXPECT_TRUE(opt.IsSyncCmdStoppable());
    opt.SetSyncCmdStoppable(false);
    EXPECT_FALSE(opt.IsSyncCmdStoppable());
}

/**
 * @tc.name: StopHiperfCmdSync_NotRunning
 * @tc.desc: Test StopHiperfCmdSync returns KILL_NO_PROCESS when no recording is running
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, StopHiperfCmdSync_NotRunning, TestSize.Level1)
{
    HiperfClient::Client client;
    EXPECT_TRUE(client.Setup("/data/test/"));
    HiperfClient::KillResult result = client.StopHiperfCmdSync();
    EXPECT_EQ(result, HiperfClient::KillResult::KILL_NO_PROCESS);
}

/**
 * @tc.name: RunCmdSyncStoppable_NotReady
 * @tc.desc: Test RunCmdSyncStoppable returns false when client is not ready
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, RunCmdSyncStoppable_NotReady, TestSize.Level1)
{
    HiperfClient::Client client;
    client.ready_ = false;
    HiperfClient::RecordOption opt;
    opt.SetTimeStopSec(1);
    opt.SetSyncCmdStoppable(true);
    EXPECT_FALSE(client.RunCmdSyncStoppable(opt));
}

/**
 * @tc.name: SetOptionBool_EnableAlreadyExists
 * @tc.desc: Test SetOption(bool) when enable=true and arg already exists (no-op)
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, SetOptionBool_EnableAlreadyExists, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    opt.SetOption("-a", true);
    opt.SetOption("-a", true);
    auto args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 1u);
    EXPECT_EQ(args[0], "-a");
}

/**
 * @tc.name: SetOptionBool_DisableWhenNotExists
 * @tc.desc: Test SetOption(bool) when enable=false and arg not present (no-op)
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, SetOptionBool_DisableWhenNotExists, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    opt.SetOption("-a", false);
    auto args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 0u);
}

/**
 * @tc.name: SetOptionInt_UpdateExistingValue
 * @tc.desc: Test SetOption(int) updates value when key and value both exist
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, SetOptionInt_UpdateExistingValue, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    opt.SetOption("-f", 100);
    opt.SetOption("-f", 500);
    auto args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 2u);
    EXPECT_EQ(args[0], "-f");
    EXPECT_EQ(args[1], "500");
}

/**
 * @tc.name: SetOptionString_UpdateExistingValue
 * @tc.desc: Test SetOption(string) updates value when key and value both exist
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, SetOptionString_UpdateExistingValue, TestSize.Level2)
{
    HiperfClient::RecordOption opt;
    opt.SetOption("--clockid", std::string("monotonic"));
    opt.SetOption("--clockid", std::string("realtime"));
    auto args = opt.GetOptionVecString();
    ASSERT_EQ(args.size(), 2u);
    EXPECT_EQ(args[0], "--clockid");
    EXPECT_EQ(args[1], "realtime");
}

/**
 * @tc.name: Setup_AppendsTrailingSlash
 * @tc.desc: Test Setup appends '/' when outputDir lacks trailing slash
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, Setup_AppendsTrailingSlash, TestSize.Level2)
{
    HiperfClient::Client client;
    EXPECT_TRUE(client.Setup("/data/local/tmp"));
    EXPECT_EQ(client.GetOutputDir(), "/data/local/tmp/");
}

/**
 * @tc.name: Setup_EmptyOutputDirFallsBack
 * @tc.desc: Test Setup with empty outputDir falls back to current path
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, Setup_EmptyOutputDirFallsBack, TestSize.Level2)
{
    HiperfClient::Client client;
    EXPECT_TRUE(client.Setup(""));
    EXPECT_EQ(client.GetOutputDir(), "./");
}

/**
 * @tc.name: Setup_NonWritableDirFallsBack
 * @tc.desc: Test Setup falls back to current path when outputDir is not writable
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, Setup_NonWritableDirFallsBack, TestSize.Level2)
{
    HiperfClient::Client client;
    EXPECT_TRUE(client.Setup("/nonexistent_dir/"));
    EXPECT_EQ(client.GetOutputDir(), "./");
}

/**
 * @tc.name: PrepareExecCmd_NoDebug
 * @tc.desc: Test PrepareExecCmd without debug or debugMuch mode
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, PrepareExecCmd_NoDebug, TestSize.Level2)
{
    HiperfClient::Client client;
    std::vector<std::string> cmd;
    client.PrepareExecCmd(cmd);
    EXPECT_EQ(std::find(cmd.begin(), cmd.end(), "--verbose"), cmd.end());
    EXPECT_EQ(std::find(cmd.begin(), cmd.end(), "--much"), cmd.end());
}

/**
 * @tc.name: PrepareExecCmd_DebugMuchOnly
 * @tc.desc: Test PrepareExecCmd with debugMuch mode only
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, PrepareExecCmd_DebugMuchOnly, TestSize.Level2)
{
    HiperfClient::Client client;
    client.SetDebugMuchMode();
    std::vector<std::string> cmd;
    client.PrepareExecCmd(cmd);
    EXPECT_NE(std::find(cmd.begin(), cmd.end(), "--much"), cmd.end());
    EXPECT_EQ(std::find(cmd.begin(), cmd.end(), "--verbose"), cmd.end());
}

/**
 * @tc.name: PrepareExecCmd_DebugPrioritizedOverMuch
 * @tc.desc: Test PrepareExecCmd prioritizes debug over debugMuch
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, PrepareExecCmd_DebugPrioritizedOverMuch, TestSize.Level2)
{
    HiperfClient::Client client;
    client.SetDebugMode();
    client.SetDebugMuchMode();
    std::vector<std::string> cmd;
    client.PrepareExecCmd(cmd);
    EXPECT_NE(std::find(cmd.begin(), cmd.end(), "--verbose"), cmd.end());
    EXPECT_EQ(std::find(cmd.begin(), cmd.end(), "--much"), cmd.end());
}

/**
 * @tc.name: GetExecCmd_WithPipe
 * @tc.desc: Test GetExecCmd with pipe fds adds pipe arguments
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, GetExecCmd_WithPipe, TestSize.Level2)
{
    HiperfClient::Client client;
    std::vector<std::string> cmd;
    std::vector<std::string> args = {"-a"};
    client.GetExecCmd(cmd, 3, 4, args);
    EXPECT_NE(std::find(cmd.begin(), cmd.end(), "--pipe_input"), cmd.end());
    EXPECT_NE(std::find(cmd.begin(), cmd.end(), "--pipe_output"), cmd.end());
}

/**
 * @tc.name: GetExecCmd_WithoutPipe
 * @tc.desc: Test GetExecCmd without pipe fds has no pipe arguments
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, GetExecCmd_WithoutPipe, TestSize.Level2)
{
    HiperfClient::Client client;
    std::vector<std::string> cmd;
    std::vector<std::string> args = {"-a"};
    client.GetExecCmd(cmd, args);
    EXPECT_EQ(std::find(cmd.begin(), cmd.end(), "--pipe_input"), cmd.end());
    EXPECT_EQ(std::find(cmd.begin(), cmd.end(), "--pipe_output"), cmd.end());
}

/**
 * @tc.name: Start_WithArgs_NotReady
 * @tc.desc: Test Start(args) returns false when client not ready
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, Start_WithArgs_NotReady, TestSize.Level2)
{
    HiperfClient::Client client;
    client.ready_ = false;
    std::vector<std::string> args = {"-a"};
    EXPECT_FALSE(client.Start(args, false));
}

/**
 * @tc.name: StartRun_NotReady
 * @tc.desc: Test StartRun returns false when client not ready
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, StartRun_NotReady, TestSize.Level2)
{
    HiperfClient::Client client;
    client.ready_ = false;
    EXPECT_FALSE(client.StartRun());
}

/**
 * @tc.name: Pause_NotReady
 * @tc.desc: Test Pause returns false when client not ready
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, Pause_NotReady, TestSize.Level2)
{
    HiperfClient::Client client;
    client.ready_ = false;
    EXPECT_FALSE(client.Pause());
}

/**
 * @tc.name: Resume_NotReady
 * @tc.desc: Test Resume returns false when client not ready
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, Resume_NotReady, TestSize.Level2)
{
    HiperfClient::Client client;
    client.ready_ = false;
    EXPECT_FALSE(client.Resume());
}

/**
 * @tc.name: Output_NotReady
 * @tc.desc: Test Output returns false when client not ready
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, Output_NotReady, TestSize.Level2)
{
    HiperfClient::Client client;
    client.ready_ = false;
    EXPECT_FALSE(client.Output());
}

/**
 * @tc.name: Stop_NotReady
 * @tc.desc: Test Stop returns false when client not ready
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, Stop_NotReady, TestSize.Level2)
{
    HiperfClient::Client client;
    client.ready_ = false;
    EXPECT_FALSE(client.Stop());
}

/**
 * @tc.name: RunHiperfCmdSync_NotReady
 * @tc.desc: Test RunHiperfCmdSync returns false when client not ready
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, RunHiperfCmdSync_NotReady, TestSize.Level2)
{
    HiperfClient::Client client;
    client.ready_ = false;
    HiperfClient::RecordOption opt;
    opt.SetTimeStopSec(1);
    EXPECT_FALSE(client.RunHiperfCmdSync(opt));
}

/**
 * @tc.name: SendCommandAndWait_FdNotReady
 * @tc.desc: Test SendCommandAndWait returns false when fd not ready
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, SendCommandAndWait_FdNotReady, TestSize.Level2)
{
    HiperfClient::Client client;
    client.clientToServerFd_ = -1;
    EXPECT_FALSE(client.SendCommandAndWait("PAUSE\n"));
}

/**
 * @tc.name: KillChild_NoChildren
 * @tc.desc: Test KillChild is no-op when no children running
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, KillChild_NoChildren, TestSize.Level2)
{
    HiperfClient::Client client;
    client.clientToServerFd_ = -1;
    client.serverToClientFd_ = -1;
    client.hiperfPid_ = -1;
    client.hperfPrePid_ = -1;
    client.KillChild();
    EXPECT_EQ(client.clientToServerFd_, -1);
    EXPECT_EQ(client.hiperfPid_.load(), -1);
}

/**
 * @tc.name: ParentWait_ChildExitsZero
 * @tc.desc: Test ParentWait returns true when child exits with zero
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, ParentWait_ChildExitsZero, TestSize.Level2)
{
    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        _exit(0);
    }
    pid_t wpid = 0;
    int childStatus = 0;
    HiperfClient::Client client;
    EXPECT_TRUE(client.ParentWait(wpid, pid, childStatus));
}

/**
 * @tc.name: ParentWait_ChildExitsNonZero
 * @tc.desc: Test ParentWait returns false when child exits with non-zero
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, ParentWait_ChildExitsNonZero, TestSize.Level2)
{
    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        _exit(1);
    }
    pid_t wpid = 0;
    int childStatus = 0;
    HiperfClient::Client client;
    EXPECT_FALSE(client.ParentWait(wpid, pid, childStatus));
}

/**
 * @tc.name: ParentWait_ChildKilledBySignal
 * @tc.desc: Test ParentWait returns false when child killed by signal
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, ParentWait_ChildKilledBySignal, TestSize.Level2)
{
    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        raise(SIGTERM);
        _exit(1);
    }
    pid_t wpid = 0;
    int childStatus = 0;
    HiperfClient::Client client;
    EXPECT_FALSE(client.ParentWait(wpid, pid, childStatus));
}

/**
 * @tc.name: WaitCommandReply_TimeoutReturnsFalse
 * @tc.desc: Test WaitCommandReply returns false on timeout with no data
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, WaitCommandReply_TimeoutReturnsFalse, TestSize.Level2)
{
    int pipefd[2];
    ASSERT_EQ(pipe(pipefd), 0);
    HiperfClient::Client client;
    client.serverToClientFd_ = pipefd[0];
    EXPECT_FALSE(client.WaitCommandReply(std::chrono::milliseconds(100)));
    client.serverToClientFd_ = -1;
    close(pipefd[0]);
    close(pipefd[1]);
}

/**
 * @tc.name: Start_RecordOption_WithSyncStoppable
 * @tc.desc: Test Start(RecordOption) with SyncCmdStoppable exercises RunCmdSyncStoppable
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, Start_RecordOption_WithSyncStoppable, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    std::vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetTimeStopSec(1);
    opt.SetSyncCmdStoppable(true);
    HiperfClient::Client myHiperf;
    ASSERT_TRUE(myHiperf.IsReady());
    EXPECT_TRUE(myHiperf.Start(opt));
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
