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
#include <regex>
#include <sstream>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <hilog/log.h>
#include <sched.h>

#include "perf_events.h"
#include "tracked_command.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
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
};

void SubCommandStatTest::SetUpTestCase() {}

void SubCommandStatTest::TearDownTestCase() {}

void SubCommandStatTest::SetUp()
{
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
    ASSERT_EQ(RegisterSubCommandStat(), true);
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
    constexpr int sleepTime {500};
    const int sum = 10;
    const int num = 2;
    std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));

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

    std::this_thread::sleep_for(std::chrono::milliseconds(num * sleepTime));
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
        if (find(groupCounterNames.begin(), groupCounterNames.end(), tokens[1]) !=
            groupCounterNames.end()) {
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_a, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("stat -a -c 0 -d 3 --dumpoptions"), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_a1, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("stat -a -d 3 --dumpoptions"), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("stat -a -d 3"), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("stat -a -c 0 -d 3"), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_a4, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("stat -a test"), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_c, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    // some times 'sw-page-faults' is 0
    uint effectiveHeadCounter = 0u;
    EXPECT_GE(EffectiveCounter(stringOut, defaultConfigNames_, effectiveHeadCounter),
              (defaultConfigNames_.size() - 1));

    EXPECT_NE(stringOut.find("Timeout exit"), std::string::npos);

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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_c1, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("stat -a -c 0,1 -d 3"), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_c4, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
 * @tc.name: TestOnSubCommand_d
 * @tc.desc: -d
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_d, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
 * @tc.name: TestOnSubCommand_d1
 * @tc.desc: -d
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_d1, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("stat -a -d 3 --dumpoptions"), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_d2, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_d3, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_d4, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
 * @tc.name: TestOnSubCommand_i1
 * @tc.desc: -i
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_i1, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_i2, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_i3, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_i4, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_e, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_e2, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_e3, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_e4, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_g, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_g2, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_g3, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_g_uk, TestSize.Level1)
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
    const auto startTime = chrono::steady_clock::now();

    std::string tidString = " -t ";
    tidString += std::to_string(tid1) + ",";
    tidString += std::to_string(tid2);

    std::string cmdString = "stat";
    cmdString += tidString;
    cmdString += " -c 0 -d 3 --dumpoptions";

    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
    const auto startTime = chrono::steady_clock::now();

    std::string tidString = " -t ";
    tidString += std::to_string(tid1);

    std::string cmdString = "stat";
    cmdString += tidString;
    cmdString += " -c 0 -d 3 --dumpoptions";

    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_p_t2, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();

    std::string tidString = " -t ";
    tidString += "-1";

    std::string cmdString = "stat";
    cmdString += tidString;
    cmdString += " -c 0 -d 3 --dumpoptions";

    EXPECT_EQ(Command::DispatchCommand(cmdString), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_p_t3, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();

    std::string tidString = " -t ";
    tidString += "test";

    std::string cmdString = "stat";
    cmdString += tidString;
    cmdString += " -c 0 -d 3 --dumpoptions";

    EXPECT_EQ(Command::DispatchCommand(cmdString), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_p_t4, TestSize.Level1)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));

    printf("wait child thread run.\n");
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();

    std::string tidString = " -t ";
    tidString += std::to_string(tid1);

    std::string cmdString = "stat";
    cmdString += tidString;
    cmdString += " -c 0 -d 3 --dumpoptions";

    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_verbose, TestSize.Level1)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));

    printf("wait child thread run.\n");
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();

    std::string tidString = " -t ";
    tidString += std::to_string(tid1);

    std::string cmdString = "stat";
    cmdString += tidString;
    cmdString += " -c 0 -d 3 --verbose";

    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    std::string expectStr = "time_enabled:";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
    t1.join();
}

/**
 * @tc.name: TestOnSubCommand_verbose1
 * @tc.desc: -p -t
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestOnSubCommand_verbose1, TestSize.Level1)
{
    int tid1 = 0;
    std::thread t1(SubCommandStatTest::TestCodeThread, std::ref(tid1));

    printf("wait child thread run.\n");
    while (tid1 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();

    std::string tidString = " -t ";
    tidString += std::to_string(tid1);

    std::string cmdString = "stat";
    cmdString += tidString;
    cmdString += " -c 0 -d 3";

    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), defaultRunTimeoutMs);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }

    std::string expectStr = "time_enabled:";
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
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand(cmdstr), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
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
HWTEST_F(SubCommandStatTest, TestOnSubCommand_ni, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    const std::string configName {"sw-cpu-clock"};
    const std::string cmdPath {" ls"};

    stdoutRecord.Start();
    std::string testCMD = "stat --no-inherit -c 0 -d 3 --dumpoptions -e ";
    testCMD += configName;
    testCMD += cmdPath;
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
HWTEST_F(SubCommandStatTest, TestDumpOptions, TestSize.Level1)
{
    SubCommandStat cmdStat;
    cmdStat.DumpOptions();
    EXPECT_EQ(1, 1);
}

/**
 * @tc.name: TestPrintUsage
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestPrintUsage, TestSize.Level1)
{
    SubCommandStat cmdStat;
    cmdStat.PrintUsage();
    EXPECT_EQ(1, 1);
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
    SubCommandStat cmdStat;
    std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> countEvents;
    std::unique_ptr<PerfEvents::CountEvent> testEvent(std::make_unique<PerfEvents::CountEvent>());
    std::string test = "test";
    countEvents[test] = std::move(testEvent);
    cmdStat.Report(countEvents);
    EXPECT_EQ(1, 1);
}

/**
 * @tc.name: TestReport_Piling
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandStatTest, TestReport_Piling, TestSize.Level1)
{
    SubCommandStat cmdStat;
    std::vector<std::string> eventNames = {
        "hw-branch-instructions", "hw-branch-misses", "hw-cpu-cycles", "hw-instructions",
        "sw-context-switches",    "sw-page-faults",   "sw-task-clock", "sw-cpu-migrations"};
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> countEvents;
    for (int i = 0; i < 8; i++) {
        auto countEvent = make_unique<PerfEvents::CountEvent>(PerfEvents::CountEvent {});
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
        countEventTmp->time_enabled = 2830280;
        countEventTmp->time_running = 2278140;
        countEventTmp->id = 0;
        countEventTmp->used_cpus = countEventTmp->eventCount / 1e9;
    }
    cmdStat.Report(countEvents);
    std::string stringOut = stdoutRecord.Stop();
    printf("output: %s\n", stringOut.c_str());
    EXPECT_EQ(FindExpectStr(stringOut, "G/sec"), true);
    EXPECT_EQ(FindExpectStr(stringOut, "M/sec"), true);
    EXPECT_EQ(FindExpectStr(stringOut, "K/sec"), true);
    EXPECT_EQ(FindExpectStr(stringOut, "/sec"), true);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
