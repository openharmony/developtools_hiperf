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
#include "subcommand_stat_test.h"

#include <algorithm>
#include <cinttypes>
#include <condition_variable>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <regex>
#include <sstream>
#include <thread>
#include <string>
#include <unistd.h>
#include <vector>

#include <gtest/gtest.h>
#include <hilog/log.h>
#include <sched.h>

#include "perf_events.h"
#include "test_utilities.h"
#include "tracked_command.h"

using namespace testing::ext;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
static std::atomic<bool> g_wait = false;
class SubCommandStatTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static void TestCodeThread(int &tid);
    bool FindExpectStr(const std::string &stringOut, const std::string &counterNames) const;
    uint EffectiveCounter(const std::string &stringOut,
                          const std::vector<std::string> &counterNames,
                          uint &effectiveHeadCounter) const;
    uint EffectiveCounter(const std::string &stringOut, const std::string &counterNames,
                          uint &effectiveHeadCounter) const;
    int CounterValue(const std::string &stringOut, const std::string &configName) const;
    void CheckGroupCoverage(const std::string &stringOut,
                            const std::string &groupCounterName) const;

    const std::vector<std::string> defaultConfigNames_ = {
        "hw-branch-misses",
        "hw-cpu-cycles",
        "hw-instructions",
#if defined(__aarch64__)
        "hw-stalled-cycles-backend",
        "hw-stalled-cycles-frontend",
#endif
        "sw-context-switches",
        "sw-page-faults",
        "sw-task-clock",
    };

    const int defaultRunTimeoutMs = 4100;
    const std::string timeReportStr = "Report at ";
    static std::mutex mtx;
    static std::condition_variable cv;
};

std::mutex SubCommandStatTest::mtx;
std::condition_variable SubCommandStatTest::cv;

void SubCommandStatTest::SetUpTestCase() {}

void SubCommandStatTest::TearDownTestCase() {}

void SubCommandStatTest::SetUp()
{
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
    ASSERT_EQ(SubCommand::RegisterSubCommand("stat", std::make_unique<SubCommandStat>()), true);
}

void SubCommandStatTest::TearDown()
{
    SubCommand::ClearSubCommands();
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
}

void SubCommandStatTest::TestCodeThread(int &tid)
{
    std::vector<std::unique_ptr<char[]>> mems;
    tid = gettid();
    printf("TestCodeThread:%d ++\n", tid);

    const int sum = 10;
    const int num = 2;

    constexpr size_t memSize {1024};
    for (uint i = 0; i < sum * memSize; i++) {
        if (i % num == 0) {
            mems.push_back(std::make_unique<char[]>(memSize));
        } else {
            mems.push_back(std::make_unique<char[]>(memSize * num));
        }
    }

    for (uint i = 0; i < sum * memSize; i++) {
        mems.pop_back();
    }
    if (g_wait) {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock);
    }
    printf("TestCodeThread:%d --\n", tid);
}

uint SubCommandStatTest::EffectiveCounter(const std::string &stringOut,
                                          const std::string &counterNames,
                                          uint &effectiveHeadCounter) const
{
    std::string filterCounterNames {};
    filterCounterNames = StringReplace(counterNames, ":u", "");
    filterCounterNames = StringReplace(filterCounterNames, ":k", "");
    return EffectiveCounter(stringOut, StringSplit(filterCounterNames, ","), effectiveHeadCounter);
}

bool SubCommandStatTest::FindExpectStr(const std::string &stringOut,
                                       const std::string &counterNames) const
{
    auto lines = StringSplit(stringOut, "\n");
    for (auto line : lines) {
        if (line.find(counterNames.c_str()) != std::string::npos) {
            return true;
        }
    }

    return false;
}

uint SubCommandStatTest::EffectiveCounter(const std::string &stringOut,
                                          const std::vector<std::string> &counterNames,
                                          uint &effectiveHeadCounter) const
{
    uint effectiveCounter = 0;
    for (auto name : counterNames) {
        EXPECT_NE(stringOut.find(name), std::string::npos);
    }
    auto lines = StringSplit(stringOut, "\n");
    for (auto line : lines) {
        if (line.find(timeReportStr.c_str()) != std::string::npos) {
            printf("reset the count because found: '%s'\n", timeReportStr.c_str());
            // reset the count
            effectiveCounter = 0;
            effectiveHeadCounter++;
            continue;
        }
        auto tokens = StringSplit(line.c_str(), " ");
        constexpr size_t sizeLimit {2};
        std::regex pattern("^\\d+[,\\d{3}]*");
        if (tokens.size() > sizeLimit &&
            (IsDigits(tokens[0]) || std::regex_match(tokens[0], pattern))) {
            if (find(counterNames.begin(), counterNames.end(), tokens[1]) != counterNames.end()) {
                uint64_t count = std::stoull(tokens[0]);
                effectiveCounter++;
                printf("[%u] found %s:%s count %" PRIu64 "\n", effectiveCounter, tokens[1].c_str(),
                       tokens[0].c_str(), count);
            }
        }
    }

    // no more count than max
    printf("effectiveCounter %u \n", effectiveCounter);
    printf("effectiveHeadCounter %u \n", effectiveHeadCounter);

    return effectiveCounter;
}

int SubCommandStatTest::CounterValue(const std::string &stringOut,
                                     const std::string &configName) const
{
    int res {-1};
    auto lines = StringSplit(stringOut, "\n");
    for (auto line : lines) {
        auto tokens = StringSplit(line.c_str(), " ");
        constexpr size_t sizeLimit {2};
        if (tokens.size() > sizeLimit and IsDigits(tokens[0])) {
            if (tokens[1] == configName) {
                uint64_t count = std::stoull(tokens[0]);
                res += count;
            }
        }
    }
    if (res != -1) {
        ++res;
    }
    return res;
}

void SubCommandStatTest::CheckGroupCoverage(const std::string &stringOut,
                                            const std::string &groupCounterName) const
{
    std::string filterGroupCounterName = StringReplace(groupCounterName, ":u", "");
    filterGroupCounterName = StringReplace(filterGroupCounterName, ":k", "");
    auto groupCounterNames = StringSplit(filterGroupCounterName, ",");

    for (auto name : groupCounterNames) {
        EXPECT_NE(stringOut.find(name), std::string::npos);
    }
    std::string groupCoverage;
    auto lines = StringSplit(stringOut, "\n");
    for (auto line : lines) {
        auto tokens = StringSplit(line.c_str(), " ");
        if (tokens.size() > 1 &&
            find(groupCounterNames.begin(), groupCounterNames.end(), tokens[1]) != groupCounterNames.end()) {
            if (groupCoverage.empty()) {
                groupCoverage = tokens.back();
            } else {
                EXPECT_EQ(groupCoverage, tokens.back());
            }
        }
    }
}

/**
 * @tc.name: TestOnSubCommand_a
 * @tc.desc: -a
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_a, TestSize.Level0)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("stat -a -c 0 -d 3 --dumpoptions"), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));
}

/**
 * @tc.name: TestOnSubCommand_a1
 * @tc.desc: -a
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_a1, TestSize.Level2)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("stat -a -d 3 --dumpoptions"), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    printf("output:\n%s", stringOut.c_str());
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));
}

/**
 * @tc.name: TestOnSubCommand_a2
 * @tc.desc: -a
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_a2, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("stat -a -d 3"), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));
}

/**
 * @tc.name: TestOnSubCommand_a3
 * @tc.desc: -a
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_a3, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("stat -a -c 0 -d 3"), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));
}

/**
 * @tc.name: TestOnSubCommand_a4
 * @tc.desc: -a
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_a4, TestSize.Level3)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("stat -a test"), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    // some times 'sw-page-faults' is 0
    std::string expectStr = "failed";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestOnSubCommand_c
 * @tc.desc: -c
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_c, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));

    printf("wait child thread run.\n");
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    // we need bound us to cpu which we selelct
    cpu_set_t mask, oldMask;
    CPU_ZERO(&mask);
    CPU_SET(1, &mask);

    sched_getaffinity(0, sizeof(cpu_set_t), &oldMask);
    sched_setaffinity(0, sizeof(cpu_set_t), &mask);
    EXPECT_LE(CPU_COUNT(&mask), CPU_COUNT(&oldMask));

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -c 0 -d 3 --dumpoptions";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));

    if (stringOut.find("event not support") == std::string::npos) {
        EXPECT_NE(stringOut.find("Timeout exit"), std::string::npos);
    }

    sched_setaffinity(0, sizeof(cpu_set_t), &oldMask);
    sched_getaffinity(0, sizeof(cpu_set_t), &mask);
    EXPECT_EQ(CPU_COUNT(&mask), CPU_COUNT(&oldMask));
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_c1
 * @tc.desc: -c
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_c1, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -c 1 -d 3";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_c2
 * @tc.desc: -c
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_c2, TestSize.Level1)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -c 0,1 -d 3";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_c3
 * @tc.desc: -c
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_c3, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("stat -a -c 0,1 -d 3"), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));
}

/**
 * @tc.name: TestOnSubCommand_c4
 * @tc.desc: -c
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_c4, TestSize.Level3)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -c test -d 3";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    // some times 'sw-page-faults' is 0
    std::string expectStr = "incorrect option";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_c5
 * @tc.desc: -c
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_c5, TestSize.Level3)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -c -2 -d 3";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    // some times 'sw-page-faults' is 0
    std::string expectStr = "Invalid -c value";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_d
 * @tc.desc: -d
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_d, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -c 0 -d 3 --dumpoptions";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_p
 * @tc.desc: -p
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_p, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p -1 -d 3";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    // some times 'sw-page-faults' is 0
    std::string expectStr = "Invalid -p value";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_p
 * @tc.desc: -p
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_p1, TestSize.Level3)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -a --app test -d 3";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    // some times 'sw-page-faults' is 0
    std::string expectStr = "You cannot specify -a and --app at the same time";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_p2
 * @tc.desc: -p
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_p2, TestSize.Level3)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat --app test -p 1234 -d 3";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    // some times 'sw-page-faults' is 0
    std::string expectStr = "You cannot specify --app and -t/-p at the same time";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_chkms
 * @tc.desc: --chkms
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_ch, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -a -d 3 --chkms 201";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    // some times 'sw-page-faults' is 0
    std::string expectStr = "Invalid --chkms value '201'";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_aa
 * @tc.desc: aa
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_aa, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat aa --app 123 -d 3";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    // some times 'sw-page-faults' is 0
    std::string expectStr = "You cannot specify a cmd and --app at the same time";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_d1
 * @tc.desc: -d
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_d1, TestSize.Level0)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("stat -a -d 3 --dumpoptions"), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));
}

/**
 * @tc.name: TestOnSubCommand_d2
 * @tc.desc: -d
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_d2, TestSize.Level3)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -d -1";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    // some times 'sw-page-faults' is 0
    std::string expectStr = "failed";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_d3
 * @tc.desc: -d
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_d3, TestSize.Level3)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -d test";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    // some times 'sw-page-faults' is 0
    std::string expectStr = "incorrect option";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_d4
 * @tc.desc: -d
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_d4, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -c 0,1 -d 1";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));
    t1.join();
}


/**
 * @tc.name: TestOnSubCommand_d5
 * @tc.desc: -d
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_d5, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10)); // 10: sleep 10ms
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -c 0 -d 3 --dumpoptions --per-core";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_d6
 * @tc.desc: -d
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_d6, TestSize.Level3)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10)); // 10: sleep 10ms
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -c 0 -d 3 --dumpoptions --per-thread";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_i
 * @tc.desc: -i
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_i, TestSize.Level1)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -c 0 -d 3 -i 1000 --dumpoptions";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));

    if (stringOut.find("event not support") == std::string::npos) {
        EXPECT_GE(effectiveHeadCounter, 3u);
    }
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_i1
 * @tc.desc: -i
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_i1, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -c 0 -d 3 -i 500 --dumpoptions";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));

    EXPECT_GE(effectiveHeadCounter, 3u);
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_i2
 * @tc.desc: -i
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_i2, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -c 0 -d 3 -i -1 --dumpoptions";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    // some times 'sw-page-faults' is 0
    std::string expectStr = "failed";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_i2
 * @tc.desc: -i
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_i3, TestSize.Level3)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -c 0 -d 3 -i test --dumpoptions";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    // some times 'sw-page-faults' is 0
    std::string expectStr = "incorrect";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_i4
 * @tc.desc: -i
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_i4, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -c 0 -d 1 -i 100 --dumpoptions";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));

    EXPECT_GE(effectiveHeadCounter, 3u);
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_e
 * @tc.desc: -e261
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_e, TestSize.Level0)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -e hw-instructions -c 0 -d 3 --dumpoptions";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::vector<std::string> configNmaes = {"hw-instructions"};
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, configNmaes, effectiveHeadCounter), configNmaes.size());
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_e1
 * @tc.desc: -e261
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_e1, TestSize.Level1)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -e hw-branch-misses -c 0 -d 3 --dumpoptions";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::vector<std::string> configNmaes = {"hw-branch-misses"};
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, configNmaes, effectiveHeadCounter), configNmaes.size());
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_e2
 * @tc.desc: -e261
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_e2, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -e hw-cpu-cycles -c 0 -d 3 --dumpoptions";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::vector<std::string> configNmaes = {"hw-cpu-cycles"};
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, configNmaes, effectiveHeadCounter), configNmaes.size());
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_e3
 * @tc.desc: -e261
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_e3, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -e hw-instructions -c 0 -d 3 --dumpoptions";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::vector<std::string> configNmaes = {"hw-instructions"};
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, configNmaes, effectiveHeadCounter), configNmaes.size());
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_e4
 * @tc.desc: -e261
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_e4, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -e hw-branch-test -c 0 -d 3 --dumpoptions";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string expectStr = "event is not supported";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_g
 * @tc.desc: -g
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_g, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -g hw-branch-misses"
              " -g hw-cpu-cycles,hw-instructions"
              " -c 0 -d 3 --dumpoptions";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    const std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    const std::vector<std::string> configNmaes = {
        "hw-branch-misses",
        "hw-cpu-cycles",
        "hw-instructions",
    };
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, configNmaes, effectiveHeadCounter), configNmaes.size());
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_g1
 * @tc.desc: -g
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_g1, TestSize.Level1)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -g hw-instructions,hw-branch-misses"
              " -c 0 -d 3 --dumpoptions";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    const std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    const std::vector<std::string> configNmaes = {
        "hw-instructions",
        "hw-branch-misses",
    };
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, configNmaes, effectiveHeadCounter), configNmaes.size());
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_g2
 * @tc.desc: -g
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_g2, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -g hw-cpu-cycles,hw-instructions"
              " -c 0 -d 3 --dumpoptions";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    const std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    const std::vector<std::string> configNmaes = {
        "hw-cpu-cycles",
        "hw-instructions",
    };
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, configNmaes, effectiveHeadCounter), configNmaes.size());
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_g3
 * @tc.desc: -g
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_g3, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -g hw-cpu-test,hw-instructions"
              " -c 0 -d 3 --dumpoptions";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    const std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    std::string expectStr = "event is not supported";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_g_uk
 * @tc.desc: -g u:k
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_g_uk, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::string cmdstr = "stat -p ";
    cmdstr += std::to_string(tid1);
    cmdstr += " -g hw-branch-misses:k"
              " -g hw-cpu-cycles:k,hw-instructions:k"
              " -c 0 -d 3 --dumpoptions";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::vector<std::string> configNmaes = {
        "hw-branch-misses:k",
        "hw-cpu-cycles:k",
        "hw-instructions:k",
    };
    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, configNmaes, effectiveHeadCounter), configNmaes.size());
    CheckGroupCoverage(stringOut, "hw-branch-misses:k");
    CheckGroupCoverage(stringOut, "hw-cpu-cycles:k,hw-instructions:k");
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_p_t
 * @tc.desc: -p -t
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_p_t, TestSize.Level1)
{
    int tid1 = 0;
    int tid2 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    std::thread t2(SubCommandStatTest::TestCodeThread, std::ref(tid2));

    printf("wait child thread run.\n");
    while (tid1 * tid2 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();

    std::string tidString = " -t ";
    tidString += std::to_string(tid1) + ",";
    tidString += std::to_string(tid2);

    std::string cmdString = "stat";
    cmdString += tidString;
    cmdString += " -c 0 -d 3 --dumpoptions";
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));

    t1.join();
    t2.join();
}

/**
 * @tc.name: TestOnSubCommand_p_t1
 * @tc.desc: -p -t
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_p_t1, TestSize.Level1)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();

    std::string tidString = " -t ";
    tidString += std::to_string(tid1);

    std::string cmdString = "stat";
    cmdString += tidString;
    cmdString += " -c 0 -d 3 --dumpoptions";
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_p_t2
 * @tc.desc: -p -t
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_p_t2, TestSize.Level2)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();

    std::string tidString = " -t ";
    tidString += "-1";

    std::string cmdString = "stat";
    cmdString += tidString;
    cmdString += " -c 0 -d 3 --dumpoptions";

    EXPECT_EQ(Command::DispatchCommand(cmdString), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    std::string expectStr = "failed";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestOnSubCommand_p_t3
 * @tc.desc: -p -t
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_p_t3, TestSize.Level3)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();

    std::string tidString = " -t ";
    tidString += "test";

    std::string cmdString = "stat";
    cmdString += tidString;
    cmdString += " -c 0 -d 3 --dumpoptions";

    EXPECT_EQ(Command::DispatchCommand(cmdString), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    std::string expectStr = "incorrect";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestOnSubCommand_p_t4
 * @tc.desc: -p -t
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_p_t4, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));

    printf("wait child thread run.\n");
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();

    std::string tidString = " -t ";
    tidString += std::to_string(tid1);

    std::string cmdString = "stat";
    cmdString += tidString;
    cmdString += " -c 0 -d 3 --dumpoptions";
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_verbose
 * @tc.desc: -p -t
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_verbose, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));

    printf("wait child thread run.\n");
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();

    std::string tidString = " -t ";
    tidString += std::to_string(tid1);

    std::string cmdString = "stat";
    cmdString += tidString;
    cmdString += " -c 0 -d 3 --verbose";
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    std::string expectStr = "timeEnabled:";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_verbose1
 * @tc.desc: -p -t
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_verbose1, TestSize.Level2)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));

    printf("wait child thread run.\n");
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();

    std::string tidString = " -t ";
    tidString += std::to_string(tid1);

    std::string cmdString = "stat";
    cmdString += tidString;
    cmdString += " -c 0 -d 3";
    g_wait = true;
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    g_wait = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.notify_all();
    }
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    std::string expectStr = "timeEnabled:";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), false);
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_cmd
 * @tc.desc: hiperf stat <cmd>
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_cmd, TestSize.Level1)
{
    std::string cmdstr = "stat -c 0 -d 3 --dumpoptions ls -l";

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));
}

/**
 * @tc.name: TestOnSubCommand_ni
 * @tc.desc: --no-inherit
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_ni, TestSize.Level2)
{
    StdoutRecord stdoutRecord;
    const std::string configName {"hw-cpu-cycles"};

    stdoutRecord.Start();
    std::string testCMD = "stat --no-inherit -p 2 -c 0 -d 3 --dumpoptions -e ";
    testCMD += configName;
    const auto tick2 = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(testCMD), true);
    const auto tock2 = std::chrono::steady_clock::now();
    const auto costMs2 = std::chrono::duration_cast<std::chrono::milliseconds>(tock2 - tick2);
    EXPECT_LE(costMs2.count(), defaultRunTimeoutMs);
    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    int counterValueWithoutInherit = CounterValue(stringOut, configName);
    EXPECT_NE(counterValueWithoutInherit, 0);
    HLOGD("%s  %d", configName.c_str(), counterValueWithoutInherit);
}

// ParseOption DumpOptions PrintUsage
/**
 * @tc.name: TestParseOption_ni
 * @tc.desc: --no-inherit
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestParseOption, TestSize.Level1)
{
    SubCommandStat cmdStat;
    std::vector<std::string> args;
    args = {"-h"};
    EXPECT_EQ(cmdStat.ParseOption(args), true);
    args = {"-a"};
    EXPECT_EQ(cmdStat.ParseOption(args), true);
    args = {"-c"};
    EXPECT_EQ(cmdStat.ParseOption(args), false);
    args = {"-d"};
    EXPECT_EQ(cmdStat.ParseOption(args), false);
    args = {"-i"};
    EXPECT_EQ(cmdStat.ParseOption(args), false);
    args = {"-e"};
    EXPECT_EQ(cmdStat.ParseOption(args), false);
    args = {"-g"};
    EXPECT_EQ(cmdStat.ParseOption(args), false);
    args = {"--no-inherit"};
    EXPECT_EQ(cmdStat.ParseOption(args), true);
    args = {"-p"};
    EXPECT_EQ(cmdStat.ParseOption(args), false);
    args = {"-t"};
    EXPECT_EQ(cmdStat.ParseOption(args), false);
    args = {"--verbose"};
    EXPECT_EQ(cmdStat.ParseOption(args), true);
    args.clear();
    EXPECT_EQ(cmdStat.ParseOption(args), true);
}

/**
 * @tc.name: TestDumpOptions
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestDumpOptions, TestSize.Level2)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    SubCommandStat cmdStat;
    cmdStat.DumpOptions();
    std::string stringOut = stdoutRecord.Stop();
    EXPECT_TRUE(stringOut.find("10000.000000 sec") != std::string::npos);
}

/**
 * @tc.name: TestPrintUsage
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestPrintUsage, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    SubCommandStat cmdStat;
    cmdStat.PrintUsage();
    std::string stringOut = stdoutRecord.Stop();
    EXPECT_TRUE(stringOut.find("Usage: hiperf stat [options] [command [command-args]]") !=
                std::string::npos);
}

/**
 * @tc.name: TestCheckOptions
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestCheckOptions, TestSize.Level1)
{
    SubCommandStat cmdStat;
    std::vector<pid_t> pids;

    cmdStat.timeStopSec_ = -1;
    EXPECT_EQ(cmdStat.CheckOptions(pids), false);

    cmdStat.timeReportMs_ = -1;
    EXPECT_EQ(cmdStat.CheckOptions(pids), false);

    cmdStat.targetSystemWide_ = true;
    pids = {1112, 1113};
    EXPECT_EQ(cmdStat.CheckOptions(pids), false);

    cmdStat.trackedCommand_ = {"test"};
    EXPECT_EQ(cmdStat.CheckOptions(pids), false);

    cmdStat.targetSystemWide_ = false;
    EXPECT_EQ(cmdStat.CheckOptions(pids), false);
}

/**
 * @tc.name: TestReport
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestReport, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    SubCommandStat cmdStat;
    FILE* filePtr = nullptr;
    std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> countEvents;
    std::unique_ptr<PerfEvents::CountEvent> testEvent(std::make_unique<PerfEvents::CountEvent>());
    std::string test = "test";
    countEvents[test] = std::move(testEvent);
    cmdStat.Report(countEvents, filePtr);
    std::string stringOut = stdoutRecord.Stop();
    EXPECT_TRUE(stringOut.find("test") != std::string::npos);
    EXPECT_TRUE(stringOut.find("count  name") != std::string::npos);
}

/**
 * @tc.name: TestReport_Piling
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestReport_Piling, TestSize.Level2)
{
    SubCommandStat cmdStat;
    std::vector<std::string> eventNames = {
        "hw-branch-instructions", "hw-branch-misses", "hw-cpu-cycles", "hw-instructions",
        "sw-context-switches",    "sw-page-faults",   "sw-task-clock", "sw-cpu-migrations"};
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> countEvents;
    FILE* filePtr = nullptr;
    for (int i = 0; i < 8; i++) {
        auto countEvent = std::make_unique<PerfEvents::CountEvent>(PerfEvents::CountEvent {});
        std::string configName = eventNames[i];
        countEvents[configName] = std::move(countEvent);
        countEvents[configName]->userOnly = false;
        countEvents[configName]->kernelOnly = false;
        std::unique_ptr<PerfEvents::CountEvent> &countEventTmp = countEvents[configName];
        if (i == 0) {
            countEventTmp->eventCount = 20283000 * 10;
        } else if (i == 4) {
            countEventTmp->eventCount = 2028300;
        } else if (i == 5) {
            countEventTmp->eventCount = 2000;
        } else if (i == 7) {
            countEventTmp->eventCount = 20;
        } else {
            countEventTmp->eventCount = 20283000;
        }
        countEventTmp->timeEnabled = 2830280;
        countEventTmp->timeRunning = 2278140;
        countEventTmp->id = 0;
        countEventTmp->usedCpus = countEventTmp->eventCount / 1e9;
    }
    cmdStat.Report(countEvents, filePtr);
    std::string stringOut = stdoutRecord.Stop();
    printf("output: %s\n", stringOut.c_str());
    EXPECT_EQ(FindExpectStr(stringOut, "G/sec"), true);
    EXPECT_EQ(FindExpectStr(stringOut, "M/sec"), true);
    EXPECT_EQ(FindExpectStr(stringOut, "K/sec"), true);
    EXPECT_EQ(FindExpectStr(stringOut, "/sec"), true);
}

/**
 * @tc.name: HandleOtherConfig
 * @tc.desc: Test handle other config
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, HandleOtherConfig, TestSize.Level2)
{
    PerfEvents::Summary summary(1, 1, 1, 1, 1);
    double comment = 0;
    constexpr int testNum = 100;
    EXPECT_EQ(SubCommandStat::HandleOtherConfig(comment, summary, testNum, testNum, true), "");
}

/**
 * @tc.name: CheckOptionPidAndApp
 * @tc.desc: Test handle other config
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, CheckOptionPidAndApp, TestSize.Level1)
{
    SubCommandStat stat;
    std::vector<pid_t> pids;
    EXPECT_EQ(stat.CheckOptionPidAndApp(pids), true);
    pids.push_back(1);
    pids.push_back(2); // 2: pid
    EXPECT_EQ(stat.CheckOptionPidAndApp(pids), true);
    pids.push_back(700011); // 700011: invalid pid
    EXPECT_EQ(stat.CheckOptionPidAndApp(pids), false);
}

/**
 * @tc.name: TestOnSubCommand_restart_fail
 * @tc.desc: --restart
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_restart_fail, TestSize.Level2)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("stat --restart"), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
}

/**
 * @tc.name: TestOnSubCommand_app_running
 * @tc.desc: --app
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_app_running, TestSize.Level3)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    EXPECT_EQ(Command::DispatchCommand("stat --app com.app.notrunning -d 2"), false);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
}

/**
 * @tc.name: CheckPidAndApp
 * @tc.desc: -p
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, CheckPidAndApp, TestSize.Level1)
{
    std::string cmd = "stat -p " + std::to_string(INT_MAX) + " -d 2";
    EXPECT_EQ(Command::DispatchCommand(cmd), false);
    pid_t existPid = -1;
    const std::string basePath {"/proc/"};
    std::vector<std::string> subDirs = GetSubDirs(basePath);
    for (int i = subDirs.size() - 1; i >= 0; i--) {
        std::string subDir = subDirs[i];
        if (!IsDigits(subDir)) {
            continue;
        }
        existPid = std::stoll(subDir);
        break;
    }

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    std::string existCmd = "stat -p " + std::to_string(existPid) + " -d 2";
    EXPECT_EQ(Command::DispatchCommand(existCmd), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
}

/**
 * @tc.name: AddReportArgs
 * @tc.desc: Test AddReportArgs with -a
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, ReportSampleAll, TestSize.Level1)
{
    SubCommandStat command;
    command.targetSystemWide_ = true;

    CommandReporter reporter("stat");
    reporter.isReported_ = true;
    command.AddReportArgs(reporter);
    EXPECT_EQ(reporter.targetProcess_, "ALL");
}

/**
 * @tc.name: AddReportArgs
 * @tc.desc: Test AddReportArgs with -p
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, ReportSamplePid, TestSize.Level1)
{
    SubCommandStat command;
    command.selectPids_ = { getpid() };
    std::string name = GetProcessName(getpid());

    CommandReporter reporter("stat");
    reporter.isReported_ = true;
    command.AddReportArgs(reporter);
    EXPECT_EQ(reporter.targetProcess_, name);
}

/**
 * @tc.name: AddReportArgs
 * @tc.desc: Test AddReportArgs with --app
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, ReportSampleApp, TestSize.Level1)
{
    SubCommandStat command;
    command.appPackage_ = "com.test.app";

    CommandReporter reporter("stat");
    reporter.isReported_ = true;
    command.AddReportArgs(reporter);
    EXPECT_EQ(reporter.targetProcess_, "com.test.app");
}

/**
 * @tc.name: GetInstance
 * @tc.desc: Test GetInstance
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, GetInstance, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    EXPECT_EQ(SubCommandStat::GetInstance().Name(), "stat");
}

/**
 * @tc.name: TestOnSubCommand_control01
 * @tc.desc: prepare, start, stop
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_control01, TestSize.Level1)
{
    ASSERT_TRUE(RunCmd("hiperf stat --control stop"));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf stat --control prepare -a",
        {"create control hiperf counting success", "stat result will saved in /data/local/tmp/perf_stat.txt"}), true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf stat --control start",
        {"start counting success"}), true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf stat --control stop",
        {"stop counting success"}), true);
}

/**
 * @tc.name: TestOnSubCommand_control02
 * @tc.desc: prepare, prepare
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_control02, TestSize.Level1)
{
    ASSERT_TRUE(RunCmd("hiperf stat --control stop"));
    ASSERT_TRUE(RunCmd("hiperf stat --control prepare -a"));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf stat --control prepare -a",
        {"another counting service is running"}), true);
}

/**
 * @tc.name: TestOnSubCommand_control03
 * @tc.desc: start, stop
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_control03, TestSize.Level1)
{
    ASSERT_TRUE(RunCmd("hiperf stat --control stop"));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf stat --control start",
        {"start counting failed"}), true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf stat --control stop",
        {"stop counting failed"}), true);
}

/**
 * @tc.name: TestOnSubCommand_control04
 * @tc.desc: --control without prepare, start, stop
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_control04, TestSize.Level1)
{
    EXPECT_EQ(CheckTraceCommandOutput("hiperf stat --control pause",
        {"command should be: prepare, start, stop"}), true);
}

/**
 * @tc.name: Control_Stability
 * @tc.desc: Call the command 'control' multiple time
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, Control_Stability, TestSize.Level1)
{
    ASSERT_TRUE(RunCmd("hiperf stat --control stop"));
    for (int i = 0; i < 10; i++) {  // 10: Number of loop
        EXPECT_EQ(CheckTraceCommandOutput("hiperf stat --control prepare -a -e hw-cpu-cycles,hw-instructions",
            {"create control hiperf counting success", "stat result will saved in /data/local/tmp/perf_stat.txt"}),
            true);
        EXPECT_EQ(CheckTraceCommandOutput("hiperf stat --control start",
            {"start counting success"}), true);
        EXPECT_EQ(CheckTraceCommandOutput("hiperf stat --control stop",
            {"stop counting success"}), true);
    }
}

/**
 * @tc.name: TestOnSubCommand_OutPutFileName01
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, OutPutFileName01, TestSize.Level1)
{
    EXPECT_EQ(CheckTraceCommandOutput("hiperf stat -d 10 -a -o /data/local/tmp/stat.txt",
        {"-o option must use with --control prepare option"}), true);
}

/**
 * @tc.name: TestOnSubCommand_OutPutFileName02
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, OutPutFileName02, TestSize.Level1)
{
    EXPECT_EQ(CheckTraceCommandOutput("hiperf stat --control prepare -a -o /data/log/hiperflog/stat.txt",
        {"Invalid output file path, permission denied"}), true);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
