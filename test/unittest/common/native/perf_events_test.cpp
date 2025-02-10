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

namespace OHOS {
namespace Developtools {
namespace HiPerf {
static constexpr uint64_t NANO_SECONDS_PER_SECOND = 1000000000;
static constexpr uint64_t TEN_THOUSAND = 10000u;
static constexpr uint64_t PAGE_SIZE = 1024u;
static constexpr uint64_t SEVENTEEN = 17u;

class PerfEventsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static void TestCodeThread(void);
    static void RunTestThreads(std::vector<std::thread> &threads);
    static void SetAllConfig(PerfEvents &event);
    static bool RecordCount(PerfEventRecord& record);
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

    static uint64_t gRecordCount;
    static uint64_t gStatCount;
};

void PerfEventsTest::SetUpTestCase() {}

void PerfEventsTest::TearDownTestCase() {}

void PerfEventsTest::SetUp() {}

void PerfEventsTest::TearDown() {}

uint64_t PerfEventsTest::gRecordCount = 0;
uint64_t PerfEventsTest::gStatCount = 0;

bool PerfEventsTest::RecordCount(PerfEventRecord& record)
{
    gRecordCount++;
    return true;
}

void PerfEventsTest::StatCount(
    const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &countEvents)
{
    gStatCount++;
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
    for (long i = 0; i < sysconf(_SC_NPROCESSORS_CONF); i++) {
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
    std::vector<std::string> trackedCommand_ {"ls"};
    event.SetTrackedCommand(trackedCommand_);
    const unsigned int frequency = 1000;
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
    int index = 0;
    bool value[] = {false, false, false, false, false, true};
    while (id < PERF_TYPE_MAX) {
        std::map<__u64, std::string> supportEvent = event.GetSupportEvents(id);
        ASSERT_EQ(supportEvent.empty(), value[index++]);
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
    gRecordCount = 0;
    event.SetMmapPages(DEFAULT_SAMPLE_MMAPAGE);
    event.SetRecordCallBack(RecordCount);

    std::vector<pid_t> selectCpus_;
    event.SetCpu(selectCpus_);
    std::vector<pid_t> pids;
    event.SetPid(pids);
    const unsigned int frequency = 1000;
    event.SetSampleFrequency(frequency);
    event.SetSystemTarget(true);
    event.SetTimeOut(DEFAULT_TRACKING_TIME);
    event.SetInherit(false);
    std::vector<std::string> trackedCommand_ {"ls"};
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
    uint64_t recordCount = gRecordCount;
    std::this_thread::sleep_for(TEST_TIME);
    EXPECT_EQ(recordCount, gRecordCount) << "now should have no record";
    EXPECT_EQ(event.ResumeTracking(), true);
    TestCodeThread();
    std::this_thread::sleep_for(TEST_TIME);
    EXPECT_EQ(event.StopTracking(), true);
    runThread.join();
    for (std::thread &t : testThreads) {
        t.join();
    }
    ASSERT_GT(gRecordCount, recordCount) << "should have more records";

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
    gRecordCount = 0;
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
    uint64_t recordCount = gRecordCount;
    std::this_thread::sleep_for(TEST_TIME);
    EXPECT_EQ(recordCount, gRecordCount) << "now should have no record";
    EXPECT_EQ(event.ResumeTracking(), true);
    TestCodeThread();
    std::this_thread::sleep_for(TEST_TIME);
    EXPECT_EQ(event.StopTracking(), true);
    runThread.join();
    for (std::thread &t : testThreads) {
        t.join();
    }
    ASSERT_GT(gRecordCount, recordCount) << "should have more records";

    std::string stringOut = stdoutRecord.Stop();
}

HWTEST_F(PerfEventsTest, StatNormal, TestSize.Level1)
{
    ScopeDebugLevel tempLogLevel(LEVEL_DEBUG);
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    PerfEvents event;
    // prepare
    gStatCount = 0;
    std::vector<pid_t> selectCpus_;
    event.SetCpu(selectCpus_);
    std::vector<pid_t> pids;
    event.SetPid(pids);
    event.SetSystemTarget(true);
    event.SetTimeOut(DEFAULT_TRACKING_TIME);
    event.SetTimeReport(DEFAULT_STAT_REPORT_TIME);
    event.SetVerboseReport(false);
    event.SetInherit(false);
    std::vector<std::string> trackedCommand_ {"ls"};
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
    EXPECT_GT(gStatCount, 0u) << "should have stats";
    uint64_t statCount = gStatCount;
    std::this_thread::sleep_for(TEST_TIME);
    EXPECT_EQ(event.ResumeTracking(), true);
    std::this_thread::sleep_for(TEST_TIME);
    EXPECT_EQ(event.StopTracking(), true);
    runThread.join();
    for (std::thread &t : testThreads) {
        t.join();
    }
    EXPECT_GT(gStatCount, statCount) << "should have more stats";

    std::string stringOut = stdoutRecord.Stop();
}

HWTEST_F(PerfEventsTest, CreateUpdateTimeThread2, TestSize.Level1)
{
    ScopeDebugLevel tempLogLevel(LEVEL_DEBUG);
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    PerfEvents event;
    event.backtrack_ = true;
    event.eventGroupItem_.emplace_back();
    event.eventGroupItem_[0].eventItems.emplace_back();
    event.readRecordThreadRunning_ = true;
    EXPECT_EQ(event.PrepareRecordThread(), true);
    this_thread::sleep_for(1s);
    std::vector<pid_t> tids = GetSubthreadIDs(getpid());
    EXPECT_FALSE(tids.empty());
    bool get = 0;
    for (const pid_t tid : tids) {
        std::string threadName = ReadFileToString(StringPrintf("/proc/%d/comm", tid));
        while (threadName.back() == '\0' || threadName.back() == '\n') {
            threadName.pop_back();
        }
        if (threadName == "timer_thread") {
            get = true;
            break;
        }
    }
    EXPECT_EQ(get, true);
    PerfEvents::updateTimeThreadRunning_ = false;
    this_thread::sleep_for(1s);
}

HWTEST_F(PerfEventsTest, IsOutputTracking, TestSize.Level1)
{
    ScopeDebugLevel tempLogLevel(LEVEL_DEBUG);
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    PerfEvents event;
    EXPECT_EQ(event.IsOutputTracking(), false);
    event.outputTracking_ = true;
    EXPECT_EQ(event.IsOutputTracking(), true);
}

HWTEST_F(PerfEventsTest, SetBackTrack, TestSize.Level1)
{
    ScopeDebugLevel tempLogLevel(LEVEL_DEBUG);
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    PerfEvents event;
    event.SetBackTrack(true);
    EXPECT_EQ(event.backtrack_, true);
}

HWTEST_F(PerfEventsTest, CalcBufferSizeLittleMemory, TestSize.Level1)
{
    ScopeDebugLevel tempLogLevel(LEVEL_DEBUG);
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    if (!LittleMemory()) {
        return;
    }

    PerfEvents event;
    event.backtrack_ = false;
    event.systemTarget_ = true;
    EXPECT_EQ(event.CalcBufferSize(), PerfEvents::MAX_BUFFER_SIZE_LITTLE);

    event.backtrack_ = true;
    event.cpuMmap_.clear();
    EXPECT_EQ(event.CalcBufferSize(), PerfEvents::MIN_BUFFER_SIZE);

    event.cpuMmap_[0] = {};
    event.mmapPages_ = TEN_THOUSAND;
    event.pageSize_ = TEN_THOUSAND;
    EXPECT_EQ(event.CalcBufferSize(), PerfEvents::MAX_BUFFER_SIZE_LITTLE);

    while (event.cpuMmap_.size() < SEVENTEEN) {
        event.cpuMmap_[event.cpuMmap_.size()] = {};
    }
    event.mmapPages_ = PAGE_SIZE;
    event.pageSize_ = PAGE_SIZE;
    static constexpr size_t EXPECT_SIZE = SEVENTEEN * PAGE_SIZE * PAGE_SIZE * 4;
    EXPECT_EQ(event.CalcBufferSize(), EXPECT_SIZE);
}

HWTEST_F(PerfEventsTest, CalcBufferSizeLargeMemory, TestSize.Level1)
{
    ScopeDebugLevel tempLogLevel(LEVEL_DEBUG);
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    if (LittleMemory()) {
        return;
    }

    PerfEvents event;
    event.backtrack_ = false;
    event.systemTarget_ = true;
    EXPECT_EQ(event.CalcBufferSize(), PerfEvents::MAX_BUFFER_SIZE_LARGE);

    event.backtrack_ = true;
    event.cpuMmap_.clear();
    EXPECT_EQ(event.CalcBufferSize(), PerfEvents::MIN_BUFFER_SIZE);

    event.cpuMmap_[0] = {};
    event.mmapPages_ = TEN_THOUSAND;
    event.pageSize_ = TEN_THOUSAND;
    EXPECT_EQ(event.CalcBufferSize(), PerfEvents::MAX_BUFFER_SIZE_LARGE);

    while (event.cpuMmap_.size() < SEVENTEEN) {
        event.cpuMmap_[event.cpuMmap_.size()] = {};
    }
    event.mmapPages_ = PAGE_SIZE;
    event.pageSize_ = PAGE_SIZE;
    static constexpr size_t EXPECT_SIZE = SEVENTEEN * PAGE_SIZE * PAGE_SIZE * 4;
    EXPECT_EQ(event.CalcBufferSize(), EXPECT_SIZE);
}

HWTEST_F(PerfEventsTest, IsSkipRecordForBacktrack1, TestSize.Level1)
{
    static constexpr size_t BACKTRACK_TIME = 2000u;
    static constexpr size_t SAMPLE_TIME = 1234u;
    ScopeDebugLevel tempLogLevel(LEVEL_DEBUG);
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    PerfEvents event;
    event.outputTracking_ = false;
    event.backtrackTime_ = BACKTRACK_TIME * NANO_SECONDS_PER_SECOND;
    event.currentTimeSecond_.store(event.backtrackTime_);

    PerfRecordSample sample;
    sample.data_.time = SAMPLE_TIME * NANO_SECONDS_PER_SECOND;

    EXPECT_EQ(event.IsSkipRecordForBacktrack(sample), true);
}

HWTEST_F(PerfEventsTest, IsSkipRecordForBacktrack2, TestSize.Level1)
{
    static constexpr size_t END_TIME = 2000u;
    static constexpr size_t SAMPLE_TIME = 1234u;
    ScopeDebugLevel tempLogLevel(LEVEL_DEBUG);
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    PerfEvents event;
    event.outputTracking_ = true;
    event.outputEndTime_ = END_TIME * NANO_SECONDS_PER_SECOND;

    PerfRecordSample sample;
    sample.data_.time = SAMPLE_TIME * NANO_SECONDS_PER_SECOND;

    EXPECT_EQ(event.IsSkipRecordForBacktrack(sample), false);
}

HWTEST_F(PerfEventsTest, IsSkipRecordForBacktrack3, TestSize.Level1)
{
    static constexpr size_t END_TIME = 1000u;
    static constexpr size_t SAMPLE_TIME = 1234u;
    ScopeDebugLevel tempLogLevel(LEVEL_DEBUG);
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    PerfEvents event;
    event.outputTracking_ = true;
    event.outputEndTime_ = END_TIME;

    PerfRecordSample sample;
    sample.data_.time = SAMPLE_TIME * NANO_SECONDS_PER_SECOND;

    EXPECT_EQ(event.IsSkipRecordForBacktrack(sample), true);
    EXPECT_EQ(event.outputTracking_, false);
    EXPECT_EQ(event.outputEndTime_, 0);
}

HWTEST_F(PerfEventsTest, OutputTracking, TestSize.Level1)
{
    static constexpr size_t TIME = 1234u;
    ScopeDebugLevel tempLogLevel(LEVEL_DEBUG);
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    PerfEvents event;
    event.startedTracking_ = false;
    EXPECT_EQ(event.OutputTracking(), false);

    event.startedTracking_ = true;
    event.outputTracking_ = true;
    EXPECT_EQ(event.OutputTracking(), true);

    event.outputTracking_ = false;
    PerfEvents::currentTimeSecond_.store(TIME);
    EXPECT_EQ(event.OutputTracking(), true);
    EXPECT_EQ(event.outputEndTime_, TIME);
    EXPECT_EQ(event.outputTracking_, true);
}

HWTEST_F(PerfEventsTest, SetConfig, TestSize.Level1)
{
    constexpr uint64_t config = 0x700010007;
    constexpr uint64_t config1 = 8;
    constexpr uint64_t config2 = 10;
    PerfEvents event;
    std::map<const std::string, uint64_t> speOptMap = {
        {"branch_filter", 1},   {"load_filter", 1},
        {"store_filter", 1},    {"ts_enable", 1},
        {"pa_enable", 1},       {"jitter", 1},
        {"min_latency", config2},      {"event_filter", config1},
        {"pct_enable", 1},
    };
    event.SetConfig(speOptMap);
    EXPECT_EQ(event.config_, config);
    EXPECT_EQ(event.config1_, config1);
    EXPECT_EQ(event.config2_, config2);
}

HWTEST_F(PerfEventsTest, SetConfig1, TestSize.Level1)
{
    constexpr uint64_t config = 0x700010003;
    PerfEvents event;
    std::map<const std::string, uint64_t> speOptMap = {
        {"branch_filter", 1},   {"load_filter", 1},
        {"store_filter", 1},    {"ts_enable", 1},
        {"pa_enable", 1},       {"jitter", 1},
        {"min_latency", 0},      {"event_filter", 0},
        {"pct_enable", 0},
    };
    event.SetConfig(speOptMap);
    EXPECT_EQ(event.config_, config);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
