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

#include "subcommand_record_test.h"

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <sched.h>
#include <sstream>
#include <thread>

#include <poll.h>
#include <unistd.h>

#include "command.h"
#include "debug_logger.h"
#include "utilities.h"

using namespace std::literals::chrono_literals;
using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class SubCommandRecordTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    void TestEvents(std::string &opt, std::string &uk);

    static void TestRecordCommand(const std::string &option, bool expect = true,
                                  bool fixPid = true);
};

void SubCommandRecordTest::SetUpTestCase() {}

void SubCommandRecordTest::TearDownTestCase() {}

void SubCommandRecordTest::SetUp()
{
    SubCommand::ClearSubCommands(); // clear the subCommands left from other UT
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
    SubCommandRecord::RegisterSubCommandRecord();
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 1u);
}

void SubCommandRecordTest::TearDown()
{
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 1u);
    SubCommand::ClearSubCommands();
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
    MemoryHold::Get().Clean();
}

void SubCommandRecordTest::TestRecordCommand(const std::string &option, bool expect, bool fixPid)
{
    StdoutRecord stdoutRecord;

    std::string cmdString = "record ";
    if (fixPid) {
        cmdString += "--app com.ohos.launcher ";
    }
    cmdString += " " + option;
    printf("command : %s\n", cmdString.c_str());

    // it need load some symbols and much more log
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    bool ret = Command::DispatchCommand(cmdString);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    std::string stringOut = stdoutRecord.Stop();

    printf("run %" PRId64 " ms return %s(expect %s)\n", (uint64_t)costMs.count(), ret ? "true" : "false",
           expect ? "true" : "false");
    EXPECT_EQ(expect, ret);
}

// app package name
HWTEST_F(SubCommandRecordTest, PackageName, TestSize.Level1)
{
    TestRecordCommand("-d 2  --app com.ohos.launcher ", true, false);
}

HWTEST_F(SubCommandRecordTest, PackageNameErr, TestSize.Level1)
{
    TestRecordCommand("-d 2  --app package_name ", false, false);
}

// check app milliseconds
/**
 * @tc.name: CheckAppMsMin
 * @tc.desc: Test chkms minimum value
 * @tc.type: FUNC
 * @tc.require: issueI5R305
 */
HWTEST_F(SubCommandRecordTest, CheckAppMsMin, TestSize.Level1)
{
    TestRecordCommand("-d 0.5 --chkms 1 ");
}

/**
 * @tc.name: CheckAppMsMinErr
 * @tc.desc: Test chkms less than minimum value
 * @tc.type: FUNC
 * @tc.require: issueI5R305
 */
HWTEST_F(SubCommandRecordTest, CheckAppMsMinErr, TestSize.Level1)
{
    TestRecordCommand("-d 0.5 --chkms 0 ", false);
}

/**
 * @tc.name: CheckAppMsMax
 * @tc.desc: Test chkms maximum value
 * @tc.type: FUNC
 * @tc.require: issueI5R305
 */
HWTEST_F(SubCommandRecordTest, CheckAppMsMax, TestSize.Level1)
{
    TestRecordCommand("-d 0.5 --chkms 200 ");
}

/**
 * @tc.name: CheckAppMsMaxErr
 * @tc.desc: Test chkms more than maximum value
 * @tc.type: FUNC
 * @tc.require: issueI5R305
 */
HWTEST_F(SubCommandRecordTest, CheckAppMsMaxErr, TestSize.Level1)
{
    TestRecordCommand("-d 0.5 --chkms 201 ", false);
}

/**
 * @tc.name: CheckAppMsInputErr
 * @tc.desc: Test erro type of chkms
 * @tc.type: FUNC
 * @tc.require: issueI5R305
 */
HWTEST_F(SubCommandRecordTest, CheckAppMsInputErr, TestSize.Level1)
{
    TestRecordCommand("-d 0.5 --chkms abc ", false);
}
// stop seconds
HWTEST_F(SubCommandRecordTest, StopSecondsMin, TestSize.Level1)
{
    TestRecordCommand("-d 0.1 ");
}

HWTEST_F(SubCommandRecordTest, StopSecondsMinErr, TestSize.Level1)
{
    TestRecordCommand("-d 0.099 ", false);
}

HWTEST_F(SubCommandRecordTest, StopSecondsMax, TestSize.Level1)
{
    std::string opt = "-d 10000.0 ";
    opt += " ls "; // because UT don't need wait so long
    TestRecordCommand(opt, true, false);
}

HWTEST_F(SubCommandRecordTest, StopSecondsMaxErr, TestSize.Level1)
{
    std::string opt = "-d 10000.1 ";
    opt += " ";
    TestRecordCommand(opt, false);
}

// system wide
HWTEST_F(SubCommandRecordTest, SystemWide, TestSize.Level1)
{
    TestRecordCommand("-d 2 -a ", true, false);
}

// exclude hiperf
HWTEST_F(SubCommandRecordTest, ExcludePerf, TestSize.Level1)
{
    TestRecordCommand("-d 2 -a --exclude-hiperf ", true, false);
}

// select cpu
HWTEST_F(SubCommandRecordTest, SelectCpu, TestSize.Level1)
{
    TestRecordCommand("-d 2 -c 0 ");
}

HWTEST_F(SubCommandRecordTest, SelectCpuMulti, TestSize.Level1)
{
    int maxCpuid = GetProcessorNum();
    std::string opt = "-d 2 -e sw-task-clock -c ";
    for (int i = 0; i < maxCpuid; i++) {
        opt += std::to_string(i);
        opt += ",";
    }
    opt.pop_back();
    opt += " ";
    TestRecordCommand(opt);
}

HWTEST_F(SubCommandRecordTest, SelectCpuMinErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -c -1 ", false);
}

HWTEST_F(SubCommandRecordTest, SelectCpuMaxErr, TestSize.Level1)
{
    int maxCpuid = GetProcessorNum();
    std::string opt = "-d 2 -c ";
    opt += std::to_string(maxCpuid);
    opt += " ";
    TestRecordCommand(opt, false);
}

HWTEST_F(SubCommandRecordTest, SelectCpuInputErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -c abc ", false);
}

// cpu percent
HWTEST_F(SubCommandRecordTest, CpuLimitMin, TestSize.Level1)
{
    TestRecordCommand("-d 2 --cpu-limit 1 ");
}

HWTEST_F(SubCommandRecordTest, CpuLimitErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 --cpu-limit 0 ", false);
}

HWTEST_F(SubCommandRecordTest, CpuLimitMax, TestSize.Level1)
{
    TestRecordCommand("-d 2 --cpu-limit 100 ");
}

HWTEST_F(SubCommandRecordTest, CpuLimitMaxErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 --cpu-limit 101 ", false);
}

HWTEST_F(SubCommandRecordTest, CpuLimitInputErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 --cpu-limit abc ", false);
}

// frequency
HWTEST_F(SubCommandRecordTest, FrequncyMin, TestSize.Level1)
{
    TestRecordCommand("-d 2 -f 1 ");
}

HWTEST_F(SubCommandRecordTest, FrequncyMinErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -f 0 ", false);
}

HWTEST_F(SubCommandRecordTest, FrequncyMax, TestSize.Level1)
{
    TestRecordCommand("-d 2 -f 100000 ");
}

HWTEST_F(SubCommandRecordTest, FrequncyMaxErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -f 100001 ", false);
}

HWTEST_F(SubCommandRecordTest, FrequncyInputErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -f abc ", false);
}

// period
HWTEST_F(SubCommandRecordTest, PeriodMin, TestSize.Level1)
{
    TestRecordCommand("-d 2 --period 1 ");
}

HWTEST_F(SubCommandRecordTest, PeriodMinErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 --period 0 ", false);
}

HWTEST_F(SubCommandRecordTest, PeriodMax, TestSize.Level1)
{
    std::string opt = "-d 2 --period ";
    opt += std::to_string(INT_MAX);
    opt += " ";
    TestRecordCommand(opt);
}

HWTEST_F(SubCommandRecordTest, PeriodMaxErr, TestSize.Level1)
{
    std::string opt = "-d 2 --period ";
    uint32_t value = static_cast<uint32_t>(INT_MAX) + 1;
    opt += std::to_string(value);
    opt += " ";
    TestRecordCommand(opt, false);
}

HWTEST_F(SubCommandRecordTest, PeriodInputErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 --period abc ", false);
}

HWTEST_F(SubCommandRecordTest, PeriodAndFrequncyConflict, TestSize.Level1)
{
    TestRecordCommand("-d 2 -f 2000 --period 10 ", false);
}

void SubCommandRecordTest::TestEvents(std::string &opt, std::string &uk)
{
    PerfEvents perfEvents;
    for (auto type : TYPE_CONFIGS) {
        auto configs = perfEvents.GetSupportEvents(type.first);
        if (configs.empty()) {
            continue;
        }

        const int MAX_TESTEVENT = 5;
        int testEventCount = MAX_TESTEVENT;
        std::string cmdline = opt;
        for (auto config : configs) {
            if (testEventCount <= 0) {
                break;
            }
            cmdline += config.second;
            cmdline += uk;
            cmdline += ",";
            testEventCount--;
        }
        cmdline.pop_back(); // remove the last ','
        TestRecordCommand(cmdline);
        TearDown();
        SetUp();
    }
}

// select events
HWTEST_F(SubCommandRecordTest, SelectEvents, TestSize.Level1)
{
    std::string opt = "-d 2 -c 0 -e ";
    std::string uk = "";
    TestEvents(opt, uk);
}

HWTEST_F(SubCommandRecordTest, SelectEventsUser, TestSize.Level1)
{
    std::string opt = "-d 2 -c 0 -e ";
    std::string uk = ":u";
    TestEvents(opt, uk);
}

HWTEST_F(SubCommandRecordTest, SelectEventsKernel, TestSize.Level1)
{
    std::string opt = "-d 2 -c 0 -e ";
    std::string uk = ":k";
    TestEvents(opt, uk);
}

HWTEST_F(SubCommandRecordTest, SelectEventsErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -c 0 -e what ", false);
}

// select group events
HWTEST_F(SubCommandRecordTest, GroupEvents, TestSize.Level1)
{
    std::string opt = "-d 2 -c 0 -g ";
    std::string uk = "";
    TestEvents(opt, uk);
}

HWTEST_F(SubCommandRecordTest, GroupEventsUser, TestSize.Level1)
{
    std::string opt = "-d 2 -c 0 -g ";
    std::string uk = ":u";
    TestEvents(opt, uk);
}

HWTEST_F(SubCommandRecordTest, GroupEventsKernal, TestSize.Level1)
{
    std::string opt = "-d 2 -c 0 -g ";
    std::string uk = ":k";
    TestEvents(opt, uk);
}

HWTEST_F(SubCommandRecordTest, GroupEventsErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -c 0 -g what ", false);
}

HWTEST_F(SubCommandRecordTest, NoInherit, TestSize.Level1)
{
    TestRecordCommand("-d 2 --no-inherit ");
}

// select pid
HWTEST_F(SubCommandRecordTest, SelectPid, TestSize.Level1)
{
    TestRecordCommand("-d 2 -p 1 ", true, false);
}

HWTEST_F(SubCommandRecordTest, SelectPidMulti, TestSize.Level1)
{
    TestRecordCommand("-d 2 -p 1,2,3 ", true, false);
}

HWTEST_F(SubCommandRecordTest, SelectPidMinErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -p 0 ", false, false);
}

HWTEST_F(SubCommandRecordTest, SelectPidErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -p 99999999 ", false, false);
}

HWTEST_F(SubCommandRecordTest, SelectPidInputErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -p abc ", false, false);
}

// select tid
HWTEST_F(SubCommandRecordTest, SelectTid, TestSize.Level1)
{
    TestRecordCommand("-d 2 -t 1 ", true, false);
}

HWTEST_F(SubCommandRecordTest, SelectTidMulti, TestSize.Level1)
{
    TestRecordCommand("-d 2 -t 1,2,3 ", true, false);
}

HWTEST_F(SubCommandRecordTest, SelectTidMinErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -t 0 ", false, false);
}

HWTEST_F(SubCommandRecordTest, SelectTidErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -t 99999999 ", false, false);
}

HWTEST_F(SubCommandRecordTest, SelectTidInputErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -t abc ", false, false);
}

// cpu off
HWTEST_F(SubCommandRecordTest, CpuOff, TestSize.Level1)
{
    TestRecordCommand("-d 2 --offcpu ");
}

HWTEST_F(SubCommandRecordTest, BranchFilterAny, TestSize.Level1)
{
#if is_ohos
    TestRecordCommand("-d 2 -j any ", false); // broad doesn't support
#else
    TestRecordCommand("-d 2 -j any ");
#endif
}

HWTEST_F(SubCommandRecordTest, BranchFilterAnyCall, TestSize.Level1)
{
#if is_ohos
    TestRecordCommand("-d 2 -j any_call ", false); // broad doesn't support
#else
    TestRecordCommand("-d 2 -j any_call ");
#endif
}

HWTEST_F(SubCommandRecordTest, BranchFilterIndCall, TestSize.Level1)
{
#if is_ohos
    TestRecordCommand("-d 2 -j ind_call ", false); // broad doesn't support
#else
    TestRecordCommand("-d 2 -j ind_call ");
#endif
}

HWTEST_F(SubCommandRecordTest, BranchFilterAnyRet, TestSize.Level1)
{
#if is_ohos
    TestRecordCommand("-d 2 -j any_ret ", false); // broad doesn't support
#else
    TestRecordCommand("-d 2 -j any_ret ");
#endif
}

HWTEST_F(SubCommandRecordTest, BranchFilterOnlyCall, TestSize.Level1)
{
    TestRecordCommand("-d 2 -j call ", false);
}

HWTEST_F(SubCommandRecordTest, BranchFilterAll, TestSize.Level1)
{
#if is_ohos
    TestRecordCommand("-d 2 -j any,any_call,any_ret,ind_call,u,k ", false); // broad doesn't support
#else
    TestRecordCommand("-d 2 -j any,any_call,any_ret,ind_call,u,k ");
#endif
}

HWTEST_F(SubCommandRecordTest, BranchFilterInputErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -j what ", false);
}

HWTEST_F(SubCommandRecordTest, BranchFilterInputMoreErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -j any,n ", false);
}

// call stack
HWTEST_F(SubCommandRecordTest, CallStackFp, TestSize.Level1)
{
    TestRecordCommand("-d 2 --call-stack fp ");
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 -s fp ");
}

HWTEST_F(SubCommandRecordTest, CallStackFpInputMoreErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 --call-stack fp,abc ", false);
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 -s fp,abc ", false);
}

HWTEST_F(SubCommandRecordTest, CallStackInputErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 --call-stack what ", false);
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 -s what ", false);
}

HWTEST_F(SubCommandRecordTest, CallStackDwarfSizeMin, TestSize.Level1)
{
    // it will cause some crash in -fprofile-arcs and -ftest-coverage
    // we will fix it latter
    TestRecordCommand("-d 2 --call-stack dwarf,8 ");
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 -s dwarf,8 ");
}

HWTEST_F(SubCommandRecordTest, CallStackDwarfSizeMinErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 --call-stack dwarf,7 ", false);
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 -s dwarf,7 ", false);
}

HWTEST_F(SubCommandRecordTest, CallStackDwarfSizeMax, TestSize.Level1)
{
    TestRecordCommand("-d 2 --call-stack dwarf,65528 ");
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 -s dwarf,65528 ");
}

HWTEST_F(SubCommandRecordTest, CallStackDwarfSizeMaxErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 --call-stack dwarf,65529 ", false);
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 -s dwarf,65529 ", false);
}

HWTEST_F(SubCommandRecordTest, CallStackDwarfSizeErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 --call-stack dwarf,15 ", false);
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 -s dwarf,15 ", false);
}

HWTEST_F(SubCommandRecordTest, CallStackDwarfSizeInputErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 --call-stack dwarf,abc ", false);
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 -s dwarf,abc ", false);
}

HWTEST_F(SubCommandRecordTest, CallStackDwarfSizeInputMoreErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 --call-stack dwarf,16,32 ", false);
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 -s dwarf,16,32 ", false);
}

// unwind
HWTEST_F(SubCommandRecordTest, DlayUnwind, TestSize.Level1)
{
    TestRecordCommand("-d 2 -s dwarf,16 --delay-unwind ");
}

HWTEST_F(SubCommandRecordTest, DisableUnwind, TestSize.Level1)
{
    TestRecordCommand("-d 2 -s dwarf,16 --disable-unwind ");
}

HWTEST_F(SubCommandRecordTest, DisableCallstackMerge, TestSize.Level1)
{
    TestRecordCommand("-d 2 -s dwarf,16 --disable-callstack-expand ");
}

// symbol dir
HWTEST_F(SubCommandRecordTest, SymbolDir, TestSize.Level1)
{
    TestRecordCommand("-d 2 --symbol-dir ./ ");
}

HWTEST_F(SubCommandRecordTest, SymbolDirErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 --symbol-dir where ", false);
}

// clock id
HWTEST_F(SubCommandRecordTest, ClockIdMonotonic, TestSize.Level1)
{
    TestRecordCommand("-d 2 --clockid monotonic ");
}

HWTEST_F(SubCommandRecordTest, ClockIdMonotonicRaw, TestSize.Level1)
{
    TestRecordCommand("-d 2 --clockid monotonic_raw ");
}

HWTEST_F(SubCommandRecordTest, ClockIdBoottime, TestSize.Level1)
{
    TestRecordCommand("-c 0 -d 2 -e sw-task-clock --clockid boottime ");
}

HWTEST_F(SubCommandRecordTest, ClockIdRealtime, TestSize.Level1)
{
    TestRecordCommand("-c 0 -d 2 -e sw-task-clock --clockid realtime ");
}

HWTEST_F(SubCommandRecordTest, ClockIdClockTai, TestSize.Level1)
{
    TestRecordCommand("-c 0 -d 2 -e sw-task-clock --clockid clock_tai ");
}

HWTEST_F(SubCommandRecordTest, ClockIdInputErr, TestSize.Level1)
{
    TestRecordCommand("-c 0 -d 2 --clockid what ", false);
}

// mmap pages
HWTEST_F(SubCommandRecordTest, MmapPagesPower2Err, TestSize.Level1)
{
    TestRecordCommand("-d 2 -m 101 ", false);
}

HWTEST_F(SubCommandRecordTest, MmapPagesMin, TestSize.Level1)
{
    TestRecordCommand("-d 2 -m 2 ");
}

HWTEST_F(SubCommandRecordTest, MmapPagesMinErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -m 1 ", false);
}

HWTEST_F(SubCommandRecordTest, MmapPagesMax, TestSize.Level1)
{
    TestRecordCommand("-d 2 -m 1024 ");
}

HWTEST_F(SubCommandRecordTest, MmapPagesMaxErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -m 1025 ", false);
}

HWTEST_F(SubCommandRecordTest, MmapPagesInputErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -m abc ", false);
}

// output file name
HWTEST_F(SubCommandRecordTest, OutputFileName, TestSize.Level1)
{
    TestRecordCommand("-d 2 -o /data/local/tmp/output.perf.data ");
}

HWTEST_F(SubCommandRecordTest, OutputFileNameErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 -o nopath/output.perf.data ", false);
}

// data size limit
HWTEST_F(SubCommandRecordTest, DataLimit, TestSize.Level1)
{
    TestRecordCommand("-d 2 --data-limit 1K ");
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 --data-limit 1M ");
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 --data-limit 1G ");
}

HWTEST_F(SubCommandRecordTest, DataLimitErr, TestSize.Level1)
{
    TestRecordCommand("-d 2 --data-limit 10A ", false);
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 --data-limit 0G ", false);
}

HWTEST_F(SubCommandRecordTest, RecordCompress, TestSize.Level1)
{
    TestRecordCommand("-d 2 -z ");
}

HWTEST_F(SubCommandRecordTest, Verbose, TestSize.Level1)
{
    TestRecordCommand("-d 2 --verbose ");
}

HWTEST_F(SubCommandRecordTest, DumpOptions, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    SubCommandRecord cmd;
    cmd.DumpOptions();
    stdoutRecord.Stop();
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
