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

#include "utilities.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
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
HWTEST_F(HiperfClientTest, NoPara, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    HiperfClient::Client myHiperf;
    myHiperf.SetDebugMode();
    ASSERT_TRUE(myHiperf.Start());

    ASSERT_TRUE(myHiperf.Pause());
    this_thread::sleep_for(1s);

    ASSERT_TRUE(myHiperf.Resume());
    this_thread::sleep_for(1s);

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
    this_thread::sleep_for(1s);

    ASSERT_TRUE(myHiperf.Resume());
    this_thread::sleep_for(1s);

    ASSERT_TRUE(myHiperf.Stop());

    stdoutRecord.Stop();
}

HWTEST_F(HiperfClientTest, DebugMuchMode, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    HiperfClient::Client myHiperf;
    myHiperf.SetDebugMuchMode();
    ASSERT_TRUE(myHiperf.Start());

    ASSERT_TRUE(myHiperf.Pause());
    this_thread::sleep_for(1s);

    ASSERT_TRUE(myHiperf.Resume());
    this_thread::sleep_for(1s);

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
    this_thread::sleep_for(1s);

    ASSERT_TRUE(myHiperf.Resume());
    this_thread::sleep_for(1s);

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
    this_thread::sleep_for(1s);

    if (!myHiperf.Resume()) {
        retResume = false;
    }
    this_thread::sleep_for(1s);

    if (!myHiperf.Stop()) {
        retStop = false;
    }

    ASSERT_TRUE(retPause);
    ASSERT_TRUE(retResume);
    ASSERT_TRUE(retStop);

    stdoutRecord.Stop();
}

HWTEST_F(HiperfClientTest, SetTargetSystemWide, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    opt.SetTargetSystemWide(true);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetCompressData, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetCompressData(true);
    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetSelectCpus, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    vector<int> cpus = {0, 1};
    opt.SetSelectCpus(cpus);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetTimeStopSec, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetTimeStopSec(40);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetFrequency, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetFrequency(500);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetPeriod, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetPeriod(3);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetSelectEvents, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    vector<string> selectEvents = {"sw-cpu-clock:k"};
    opt.SetSelectEvents(selectEvents);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetSelectGroups, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    vector<string> selectEvents = {"hw-cpu-cycles:u"};
    opt.SetSelectGroups(selectEvents);
    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetNoInherit, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetNoInherit(true);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetSelectPids, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetSelectTids, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectTids = {gettid()};
    opt.SetSelectTids(selectTids);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetExcludePerf, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    opt.SetTargetSystemWide(true);
    opt.SetExcludePerf(true);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetCpuPercent, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetCpuPercent(50);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetOffCPU, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetOffCPU(true);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetCallStack, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetCallGraph("fp");

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetDelayUnwind, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetDelayUnwind(true);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetDisableUnwind, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetDisableUnwind(true);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetDisableCallstackMerge, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetDisableCallstackMerge(true);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetOutputFilename, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetOutputFilename("perf.data.ut");

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetSymbolDir, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetSymbolDir("/data/local/tmp/");

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetDataLimit, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetDataLimit("100M");

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetAppPackage, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    opt.SetAppPackage("com.ohos.launcher");

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetClockId, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetClockId("monotonic");

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetMmapPages, TestSize.Level1)
{
    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    opt.SetMmapPages(64);

    TestCaseOption(opt);
}

HWTEST_F(HiperfClientTest, SetVecBranchSampleTypes, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    HiperfClient::RecordOption opt;
    vector<pid_t> selectPids = {getpid()};
    opt.SetSelectPids(selectPids);
    std::vector<std::string> vecBranchSampleTypes = {"any", "any_call", "any_ret", "ind_call", "u", "k"};
    opt.SetVecBranchSampleTypes(vecBranchSampleTypes);
    HiperfClient::Client myHiperf;
    myHiperf.SetDebugMode();

    ASSERT_TRUE(myHiperf.IsReady());
#ifdef is_ohos
    ASSERT_EQ(myHiperf.Start(opt), false);
#else
    ASSERT_TRUE(myHiperf.Start(opt));
    ASSERT_TRUE(myHiperf.Pause());
    this_thread::sleep_for(1s);

    ASSERT_TRUE(myHiperf.Resume());
    this_thread::sleep_for(1s);

    ASSERT_TRUE(myHiperf.Stop());
#endif
    stdoutRecord.Stop();
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
