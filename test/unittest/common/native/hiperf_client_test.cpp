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

void HiperfClientTest::SetUpTestCase() {}

void HiperfClientTest::TearDownTestCase()
{
    DebugLogger::GetInstance()->Reset();
}

void HiperfClientTest::SetUp() {}

void HiperfClientTest::TearDown()
{
}

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
    std::this_thread::sleep_for(1s);

    ASSERT_TRUE(myHiperf.Resume());
    std::this_thread::sleep_for(1s);

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
    std::this_thread::sleep_for(1s);

    ASSERT_TRUE(myHiperf.Resume());
    std::this_thread::sleep_for(1s);

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
    std::this_thread::sleep_for(1s);

    ASSERT_TRUE(myHiperf.Resume());
    std::this_thread::sleep_for(1s);

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
    std::this_thread::sleep_for(1s);

    ASSERT_TRUE(myHiperf.Resume());
    std::this_thread::sleep_for(1s);

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
    std::this_thread::sleep_for(1s);

    ASSERT_TRUE(myHiperf.StartRun());
    std::this_thread::sleep_for(1s);

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
    std::this_thread::sleep_for(1s);

    if (!myHiperf.Resume()) {
        retResume = false;
    }
    std::this_thread::sleep_for(1s);

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
    opt.SetTimeStopSec(40);

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
    std::string testProcesses = "com.ohos.sceneboard";
    if (!CheckTestApp(testProcesses)) {
        testProcesses = "com.ohos.launcher";
    }
    opt.SetAppPackage(testProcesses);

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
    std::this_thread::sleep_for(1s);
    EXPECT_FALSE(myHiperf.Output());
    std::this_thread::sleep_for(1s);
    EXPECT_TRUE(myHiperf.Stop());
}

/**
 * @tc.desc: SetCallStackSamplingConfigs(int duration)
 * @tc.type: FUNC
 */
HWTEST_F(HiperfClientTest, SetCallStackSamplingConfigs_WithZeroDuration, TestSize.Level2)
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
HWTEST_F(HiperfClientTest, SetOption_RemoveExistingArgument, TestSize.Level2)
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
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
