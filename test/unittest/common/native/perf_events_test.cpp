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

#include "perf_events_test.h"

#include <chrono>
#include <cinttypes>
#include <cstdlib>
#include <thread>
#include <unistd.h>

#include "debug_logger.h"
#include "utilities.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;

namespace OHOS {
namespace Developtools {
namespace HiPerf {
class PerfEventsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static void TestCodeThread(void);
    static void RunTestThreads(std::vector<std::thread> &threads);
    static void SetAllConfig(PerfEvents &event);
    static bool RecordCount(std::unique_ptr<PerfEventRecord> record);
    static void StatCount(
        const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &countEvents);

    static constexpr int TEST_CODE_MEM_FILE_SIZE = 1024;
    static constexpr auto TEST_CODE_SLEEP_BEFORE_RUN = 500ms;
    static constexpr auto TEST_CODE_SLEEP_AFTER_RUN = 1000ms;
    static constexpr int TEST_CODE_RUN_TIME = 10240;
    static constexpr int DOUBLE = 2;
    static constexpr int TRIPLE = 3;
    static constexpr auto TEST_TIME = 3s;
    static constexpr auto DEFAULT_TRACKING_TIME = 1000;
    static constexpr auto DEFAULT_STAT_REPORT_TIME = 500;
    static constexpr auto DEFAULT_SAMPLE_MMAPAGE = 256;

    static uint64_t g_recordCount;
    static uint64_t g_statCount;
};

void PerfEventsTest::SetUpTestCase() {}

void PerfEventsTest::TearDownTestCase() {}

void PerfEventsTest::SetUp() {}

void PerfEventsTest::TearDown() {}

uint64_t PerfEventsTest::g_recordCount = 0;
uint64_t PerfEventsTest::g_statCount = 0;

bool PerfEventsTest::RecordCount(std::unique_ptr<PerfEventRecord> record)
{
    g_recordCount++;
    return true;
}

void PerfEventsTest::StatCount(
    const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &countEvents)
{
    g_statCount++;
}

void PerfEventsTest::TestCodeThread()
{
    std::vector<std::unique_ptr<char[]>> mems;
    int tid = gettid();
    printf("%s:%d ++\n", __FUNCTION__, tid);
    for (int n = 0; n < TRIPLE; n++) {
        std::this_thread::sleep_for(TEST_CODE_SLEEP_BEFORE_RUN);
        constexpr size_t memSize {TEST_CODE_MEM_FILE_SIZE};
        for (int i = 0; i < TEST_CODE_RUN_TIME; i++) {
            if (i % DOUBLE == 0) {
                mems.push_back(std::make_unique<char[]>(memSize));
            } else {
                mems.push_back(std::make_unique<char[]>(memSize * DOUBLE));
            }
        }

        for (int i = 0; i < TEST_CODE_RUN_TIME; i++) {
            mems.pop_back();
        }

        std::this_thread::sleep_for(TEST_CODE_SLEEP_AFTER_RUN);
    }
    printf("%s:%d --\n", __FUNCTION__, tid);
}

void PerfEventsTest::RunTestThreads(std::vector<std::thread> &threads)
{
    long processorNum = GetProcessorNum();
    for (long i = 0; i < processorNum; i++) {
        threads.emplace_back(std::thread(&TestCodeThread));
    }
}

// it isn't include sample and stat
void PerfEventsTest::SetAllConfig(PerfEvents &event)
{
    std::vector<pid_t> selectCpus_;
    event.SetCpu(selectCpus_);
    std::vector<pid_t> pids;
    event.SetPid(pids);
    event.SetSystemTarget(true);
    event.SetTimeOut(DEFAULT_TRACKING_TIME);
    event.SetInherit(false);
    std::vector<std::string> trackedCommand_ {};
    event.SetTrackedCommand(trackedCommand_);
    const unsigned int frequency = 4000;
    event.SetSampleFrequency(frequency);
    const uint32_t dwarfSampleStackSize = 64;
    event.SetDwarfSampleStackSize(dwarfSampleStackSize);
    const int clockId = 1;
    event.SetClockId(clockId);

    // addevent must be tail
    event.AddDefaultEvent(PERF_TYPE_HARDWARE);
    event.AddDefaultEvent(PERF_TYPE_SOFTWARE);
}

static void RunTrack(PerfEvents &event)
{
    ASSERT_EQ(event.StartTracking(), true);
}

/**
 * @tc.name: Test
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(PerfEventsTest, GetSupportEvents, TestSize.Level1)
{
    ScopeDebugLevel tempLogLevel(LEVEL_DEBUG);
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    PerfEvents event;
    perf_type_id id = PERF_TYPE_HARDWARE;
    while (id < PERF_TYPE_MAX) {
        std::map<__u64, std::string> supportEvent = event.GetSupportEvents(id);
        for (auto it = supportEvent.begin(); it != supportEvent.end(); ++it) {
            printf("[%lld]\t%s\n", it->first, it->second.c_str());
        }
        id = perf_type_id(id + 1);
    }

    std::string stringOut = stdoutRecord.Stop();
}

HWTEST_F(PerfEventsTest, GetTypeName, TestSize.Level1)
{
    ScopeDebugLevel tempLogLevel(LEVEL_DEBUG);
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    PerfEvents event;
    perf_type_id id = PERF_TYPE_HARDWARE;
    while (id < PERF_TYPE_MAX) {
        std::string typeName = event.GetTypeName(id);
        EXPECT_GT(typeName.size(), 0u) << "the type should have name";
        printf("type[%d]\tname : %s\n", id, typeName.c_str());
        id = perf_type_id(id + 1);
    }

    std::string stringOut = stdoutRecord.Stop();
}

HWTEST_F(PerfEventsTest, RecordNormal, TestSize.Level1)
{
    ScopeDebugLevel tempLogLevel(LEVEL_DEBUG);
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    PerfEvents event;
    // prepare
    g_recordCount = 0;
    event.SetMmapPages(DEFAULT_SAMPLE_MMAPAGE);
    event.SetRecordCallBack(RecordCount);

    std::vector<pid_t> selectCpus_;
    event.SetCpu(selectCpus_);
    std::vector<pid_t> pids;
    event.SetPid(pids);
    event.SetSystemTarget(true);
    event.SetTimeOut(DEFAULT_TRACKING_TIME);
    event.SetInherit(false);
    std::vector<std::string> trackedCommand_ {};
    event.SetTrackedCommand(trackedCommand_);
    event.AddDefaultEvent(PERF_TYPE_SOFTWARE);
    event.AddDefaultEvent(PERF_TYPE_HARDWARE);

    ASSERT_EQ(event.PrepareTracking(), true);
    std::thread runThread(RunTrack, std::ref(event));
    std::vector<std::thread> testThreads;
    RunTestThreads(testThreads);

    std::this_thread::sleep_for(TEST_TIME);
    EXPECT_EQ(event.PauseTracking(), true);
    std::this_thread::sleep_for(TEST_TIME); // wait for clearing mmap buffer
    uint64_t recordCount = g_recordCount;
    std::this_thread::sleep_for(TEST_TIME);
    EXPECT_EQ(recordCount, g_recordCount) << "now should have no record";
    EXPECT_EQ(event.ResumeTracking(), true);
    TestCodeThread();
    std::this_thread::sleep_for(TEST_TIME);
    EXPECT_EQ(event.StopTracking(), true);
    runThread.join();
    for (std::thread &t : testThreads) {
        t.join();
    }
    ASSERT_GT(g_recordCount, recordCount) << "should have more records";

    size_t lostSamples = 0;
    size_t lostNonSamples = 0;
    event.GetLostSamples(lostSamples, lostNonSamples);

    std::string stringOut = stdoutRecord.Stop();
}

HWTEST_F(PerfEventsTest, RecordSetAll, TestSize.Level1)
{
    ScopeDebugLevel tempLogLevel(LEVEL_DEBUG);
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    PerfEvents event;
    // prepare
    g_recordCount = 0;
    event.SetMmapPages(DEFAULT_SAMPLE_MMAPAGE);
    event.SetRecordCallBack(RecordCount);
    SetAllConfig(event);
    ASSERT_EQ(event.PrepareTracking(), true);
    std::thread runThread(RunTrack, std::ref(event));
    std::vector<std::thread> testThreads;
    RunTestThreads(testThreads);

    std::this_thread::sleep_for(TEST_TIME);
    EXPECT_EQ(event.PauseTracking(), true);
    std::this_thread::sleep_for(TEST_TIME); // wait for clearing mmap buffer
    uint64_t recordCount = g_recordCount;
    std::this_thread::sleep_for(TEST_TIME);
    EXPECT_EQ(recordCount, g_recordCount) << "now should have no record";
    EXPECT_EQ(event.ResumeTracking(), true);
    TestCodeThread();
    std::this_thread::sleep_for(TEST_TIME);
    EXPECT_EQ(event.StopTracking(), true);
    runThread.join();
    for (std::thread &t : testThreads) {
        t.join();
    }
    ASSERT_GT(g_recordCount, recordCount) << "should have more records";

    std::string stringOut = stdoutRecord.Stop();
}

HWTEST_F(PerfEventsTest, StatNormal, TestSize.Level1)
{
    ScopeDebugLevel tempLogLevel(LEVEL_DEBUG);
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    PerfEvents event;
    // prepare
    g_statCount = 0;
    std::vector<pid_t> selectCpus_;
    event.SetCpu(selectCpus_);
    std::vector<pid_t> pids;
    event.SetPid(pids);
    event.SetSystemTarget(true);
    event.SetTimeOut(DEFAULT_TRACKING_TIME);
    event.SetTimeReport(DEFAULT_STAT_REPORT_TIME);
    event.SetVerboseReport(false);
    event.SetInherit(false);
    std::vector<std::string> trackedCommand_;
    event.SetTrackedCommand(trackedCommand_);
    event.AddDefaultEvent(PERF_TYPE_SOFTWARE);
    event.AddDefaultEvent(PERF_TYPE_TRACEPOINT);
    event.SetStatCallBack(StatCount);
    ASSERT_EQ(event.PrepareTracking(), true);
    std::thread runThread(RunTrack, std::ref(event));
    std::vector<std::thread> testThreads;
    RunTestThreads(testThreads);

    std::this_thread::sleep_for(TEST_TIME);
    EXPECT_EQ(event.PauseTracking(), true);
    EXPECT_GT(g_statCount, 0u) << "should have stats";
    uint64_t statCount = g_statCount;
    std::this_thread::sleep_for(TEST_TIME);
    EXPECT_EQ(event.ResumeTracking(), true);
    std::this_thread::sleep_for(TEST_TIME);
    EXPECT_EQ(event.StopTracking(), true);
    runThread.join();
    for (std::thread &t : testThreads) {
        t.join();
    }
    EXPECT_GT(g_statCount, statCount) << "should have more stats";

    std::string stringOut = stdoutRecord.Stop();
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
