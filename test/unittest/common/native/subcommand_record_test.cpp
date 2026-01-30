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
#include <sys/stat.h>
#include <sys/utsname.h>
#include <thread>
#include <poll.h>
#include <unistd.h>

#include "command.h"
#include "debug_logger.h"
#include "hisysevent_manager.h"
#include "perf_pipe.h"
#include "subcommand_dump.h"
#include "subcommand_report.h"
#include "subcommand_test.h"
#include "test_hiperf_event_listener.h"
#include "test_utilities.h"
#include "utilities.h"

using namespace std::literals::chrono_literals;
using namespace testing::ext;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
static const std::string TEST_FILE = "/data/local/tmp/perf.data";
const std::string PERF_CPU_TIME_MAX_PERCENT = "/proc/sys/kernel/perf_cpu_time_max_percent";
static const std::chrono::milliseconds CONTROL_WAITREPY_TOMEOUT = 2ms;

class SubCommandRecordTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    void TestEvents(std::string &opt, std::string &uk, bool isFork = true);

    static void ForkAndRunTest(const std::string& cmd, bool expect = true, bool fixPid = true,
                               SubCommandRecord::CheckRecordCallBack callback = nullptr);

    static void TestRecordCommand(const std::string &option, bool expect = true, bool fixPid = true,
                                  SubCommandRecord::CheckRecordCallBack callback = nullptr);

    static bool TestRecordCommandForFork(const std::string &option, bool expect = true, bool fixPid = true,
                                         SubCommandRecord::CheckRecordCallBack callback = nullptr);

    size_t GetFileSize(const char* fileName);

    static std::string testProcesses;
};

std::string SubCommandRecordTest::testProcesses = "hiperf_test_demo";

void SubCommandRecordTest::SetUpTestCase()
{
    if (chmod("/data/test/hiperf_test_demo", 0755) == -1) { // 0755 : -rwxr-xr-x
        GTEST_LOG_(ERROR) << "hiperf_test_demo chmod failed.";
    }
    system("/data/test/hiperf_test_demo &");
}

void SubCommandRecordTest::TearDownTestCase()
{
    if (system("kill -9 `pidof hiperf_test_demo`") != 0) {
        GTEST_LOG_(ERROR) << "kill hiperf_test_demo failed.";
    }
}

void SubCommandRecordTest::SetUp()
{
    SubCommand::ClearSubCommands(); // clear the subCommands left from other UT
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
    SubCommand::RegisterSubCommand("record", std::make_unique<SubCommandRecord>());
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 1u);
    SubCommand::RegisterSubCommand("dump", std::make_unique<SubCommandDump>());
    SubCommand::RegisterSubCommand("report", std::make_unique<SubCommandReport>());
    SubCommand::RegisterSubCommand("TEST_CMD_1", std::make_unique<SubCommandTest>("TEST_CMD_1"));
}

void SubCommandRecordTest::TearDown()
{
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 4u);
    SubCommand::ClearSubCommands();
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
    MemoryHold::Get().Clean();
}

bool SubCommandRecordTest::TestRecordCommandForFork(const std::string &option, bool expect, bool fixPid,
                                                    SubCommandRecord::CheckRecordCallBack callback)
{
    StdoutRecord stdoutRecord;
    std::string cmdString = "record ";
    if (fixPid) {
        cmdString += "--app ";
        cmdString += " " + testProcesses;
    }
    cmdString += " " + option;
    printf("command : %s\n", cmdString.c_str());

    if (callback != nullptr) {
        std::string subcommandName = "record";
        SubCommand* subcommand = SubCommand::FindSubCommand(subcommandName);
        if (subcommand == nullptr) {
            return false;
        }
        SubCommandRecord* subcommandRecord = static_cast<SubCommandRecord*>(subcommand);
        subcommandRecord->SetCheckRecordCallback(callback);
    }

    // it need load some symbols and much more log
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    bool ret = Command::DispatchCommand(cmdString);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::steady_clock::now() - startTime);
    std::string stringOut = stdoutRecord.Stop();
    if ((stringOut.find("Sample records:") != std::string::npos) != expect) {
        GTEST_LOG_(ERROR) << "stringOut:" << stringOut << ret;
        return false;
    }
    printf("run %" PRId64 " ms return %s(expect %s)\n", (uint64_t)costMs.count(), ret ? "true" : "false",
           expect ? "true" : "false");
    return true;
}

void SubCommandRecordTest::ForkAndRunTest(const std::string& cmd, bool expect, bool fixPid,
                                          SubCommandRecord::CheckRecordCallBack callback)
{
    pid_t pid = fork();
    if (pid < 0) {
        FAIL() << "Fork test process failed";
        return;
    }
    if (pid == 0) {
        bool result = TestRecordCommandForFork(cmd, expect, fixPid, callback);
        _exit(result ? 0 : 1);
    }
    int status;
    int ret = wait(&status);
    GTEST_LOG_(INFO) << "Status:" << status << " Result:" << ret;
    ASSERT_EQ(status, 0);
}

void SubCommandRecordTest::TestRecordCommand(const std::string &option, bool expect, bool fixPid,
                                             SubCommandRecord::CheckRecordCallBack callback)
{
    StdoutRecord stdoutRecord;

    std::string cmdString = "record ";
    if (fixPid) {
        cmdString += "--app ";
        cmdString += " " + testProcesses;
    }
    cmdString += " " + option;
    printf("command : %s\n", cmdString.c_str());

    if (callback != nullptr) {
        std::string subcommandName = "record";
        SubCommand* subcommand = SubCommand::FindSubCommand(subcommandName);
        ASSERT_NE(subcommand, nullptr);
        SubCommandRecord* subcommandRecord = static_cast<SubCommandRecord*>(subcommand);
        subcommandRecord->SetCheckRecordCallback(callback);
    }

    // it need load some symbols and much more log
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    bool ret = Command::DispatchCommand(cmdString);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    std::string stringOut = stdoutRecord.Stop();
    if (expect) {
        EXPECT_EQ(stringOut.find("Sample records:") != std::string::npos, true);
    }
    printf("run %" PRId64 " ms return %s(expect %s)\n", (uint64_t)costMs.count(), ret ? "true" : "false",
           expect ? "true" : "false");
    EXPECT_EQ(expect, ret);
}

size_t SubCommandRecordTest::GetFileSize(const char* fileName)
{
    if (fileName == nullptr) {
        return 0;
    }
    struct stat statbuf;
    if (stat(fileName, &statbuf) == -1) {
        return 0;
    }
    size_t fileSize = statbuf.st_size;
    return fileSize;
}

static bool CheckIntFromProcFile(const std::string& proc, int expect)
{
    int value = -1;
    if (!ReadIntFromProcFile(proc, value)) {
        return false;
    }

    return value == expect;
}

static int g_maxCallstack = 0;
void CheckLevel(cJSON* list, int level)
{
    if (list == nullptr) {
        return;
    }
    g_maxCallstack = std::max(level, g_maxCallstack);
    int size = cJSON_GetArraySize(list);
    for (int i = 0; i < size; i++) {
        auto item = cJSON_GetArrayItem(list, i);
        auto it = cJSON_GetObjectItem(item, "callStack");
        if (cJSON_GetArraySize(it) > 0) {
            CheckLevel(it, level + 1);
        }
    }
}

bool CheckSymbolMap(cJSON* root)
{
    auto list = cJSON_GetObjectItem(root, "SymbolMap");
    auto size = cJSON_GetArraySize(list);
    vector<std::string> symbols = {"usleep"};
    int symbolCounts = 0;
    for (int i = 0; i < size; i++) {
        auto item = cJSON_GetArrayItem(list, i);
        auto it = cJSON_GetObjectItem(item, "symbol");
        for (auto symbol: symbols) {
            if (std::string(it->valuestring).find(SubCommandRecordTest::testProcesses) != std::string::npos) {
                symbolCounts++;
            }
        }
    }
    if (symbolCounts < symbols.size()) {
        return false;
    }
    return true;
}

bool CheckSymbolsFileList(cJSON* root, const std::string& symbolsFile)
{
    auto list = cJSON_GetObjectItem(root, "symbolsFileList");
    auto size = cJSON_GetArraySize(list);
    bool find = false;
    if (!symbolsFile.empty()) {
        find = false;
        for (int i = 0; i < size; i++) {
            auto item = cJSON_GetArrayItem(list, i);
            if (symbolsFile == item->valuestring) {
                find = true;
                break;
            }
        }
        if (!find) {
            return false;
        }
    }
    return true;
}

std::string GetProcessId(cJSON* root)
{
    std::string processId;
    auto list = cJSON_GetObjectItem(root, "processNameMap");
    auto size = cJSON_GetArraySize(list);
    for (int i = 0; i < size; i++) {
        auto item = cJSON_GetArrayItem(list, i);
        if (std::string(item->valuestring) == "/data/test/hiperf_test_demo") {
            processId = std::string(item->string);
        }
    }
    return processId;
}

bool CheckJsonReport(const std::string& fileName, const std::string& symbolsFile)
{
    cJSON* root = ParseJson(fileName.c_str());
    if (root == nullptr) {
        return false;
    }
    std::string processId = GetProcessId(root);
    if (processId.empty()) {
        return false;
    }
    if (!CheckSymbolMap(root)) {
        return false;
    }
    if (!CheckSymbolsFileList(root, symbolsFile)) {
        return false;
    }
    auto listRecord = cJSON_GetObjectItem(root, "recordSampleInfo");
    if (cJSON_GetArraySize(listRecord) <= 0) {
        return false;
    }
    auto itemRecord = cJSON_GetArrayItem(listRecord, 0);
    auto listProcesses = cJSON_GetObjectItem(itemRecord, "processes");
    cJSON* listThreads = nullptr;
    for (int i = 0; i < cJSON_GetArraySize(listProcesses); i++) {
        auto item = cJSON_GetArrayItem(listProcesses, i);
        auto it = cJSON_GetObjectItem(item, "pid");
        if (std::to_string(it->valueint) == processId) {
            listThreads = cJSON_GetObjectItem(item, "threads");
            break;
        }
    }
    if (listThreads == nullptr || cJSON_GetArraySize(listThreads) <= 0) {
        return false;
    }
    auto itemThreads = cJSON_GetArrayItem(listThreads, 0);
    auto listLibs = cJSON_GetObjectItem(itemThreads, "libs");
    if (cJSON_GetArraySize(listLibs) <= 0) {
        return false;
    }
    auto itemCallOrder = cJSON_GetObjectItem(itemThreads, "CallOrder");
    auto itemCallStack = cJSON_GetObjectItem(itemCallOrder, "callStack");
    CheckLevel(itemCallStack, 0);
    if (g_maxCallstack < 1) {
        return false;
    }
    return true;
}

// app package name
HWTEST_F(SubCommandRecordTest, PackageName, TestSize.Level0)
{
    ForkAndRunTest("-d 2 ", true, true);
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
    ForkAndRunTest("-d 0.5 --chkms 1 ");
}

/**
 * @tc.name: CheckAppMsMinErr
 * @tc.desc: Test chkms less than minimum value
 * @tc.type: FUNC
 * @tc.require: issueI5R305
 */
HWTEST_F(SubCommandRecordTest, CheckAppMsMinErr, TestSize.Level3)
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
    ForkAndRunTest("-d 0.5 --chkms 200 ");
}

/**
 * @tc.name: CheckAppMsMaxErr
 * @tc.desc: Test chkms more than maximum value
 * @tc.type: FUNC
 * @tc.require: issueI5R305
 */
HWTEST_F(SubCommandRecordTest, CheckAppMsMaxErr, TestSize.Level3)
{
    TestRecordCommand("-d 0.5 --chkms 201 ", false);
}

/**
 * @tc.name: CheckAppMsInputErr
 * @tc.desc: Test erro type of chkms
 * @tc.type: FUNC
 * @tc.require: issueI5R305
 */
HWTEST_F(SubCommandRecordTest, CheckAppMsInputErr, TestSize.Level3)
{
    TestRecordCommand("-d 0.5 --chkms abc ", false);
}
// stop seconds
HWTEST_F(SubCommandRecordTest, StopSecondsMin, TestSize.Level1)
{
    ForkAndRunTest("-d 0.1 ");
}

HWTEST_F(SubCommandRecordTest, StopSecondsMinErr, TestSize.Level2)
{
    TestRecordCommand("-d 0.099 ", false);
}

HWTEST_F(SubCommandRecordTest, StopSecondsMax, TestSize.Level3)
{
    std::string opt = "-d 10000.0 ";
    opt += " ls "; // because UT don't need wait so long
    ForkAndRunTest(opt, true, false);
}

HWTEST_F(SubCommandRecordTest, StopSecondsMaxErr, TestSize.Level2)
{
    std::string opt = "-d 10000.1 ";
    opt += " ";
    TestRecordCommand(opt, false);
}

HWTEST_F(SubCommandRecordTest, ReportCommand, TestSize.Level1)
{
    std::shared_ptr<HiperfEventListener> eventListener = std::make_shared<HiperfEventListener>();
    std::vector<ListenerRule> sysRules;
    sysRules.emplace_back(OHOS::HiviewDFX::HiSysEvent::Domain::PROFILER, "HIPERF_USAGE", RuleType::WHOLE_WORD);
    bool CheckListener = HiSysEventManager::AddListener(eventListener, sysRules);
    if (CheckListener != 0) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    ForkAndRunTest("-d 2 -a ", true, false);

    int CheckCount = 0;
    std::shared_ptr<HiviewDFX::HiSysEventRecord> eventRecord = eventListener->GetLastEvent();
    while (eventRecord == nullptr) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        CheckCount++;
        if (CheckCount == 6) {
            eventRecord == nullptr;
        }
    }
    HiSysEventManager::RemoveListener(eventListener);
    ASSERT_NE(eventRecord, nullptr);

    std::string value = "";
    EXPECT_EQ(eventRecord->GetParamValue("MAIN_CMD", value), VALUE_PARSED_SUCCEED);
    EXPECT_EQ(value, "record");

    EXPECT_EQ(eventRecord->GetParamValue("SUB_CMD", value), VALUE_PARSED_SUCCEED);
    EXPECT_EQ(value, " record -d 2 -a");

    EXPECT_EQ(eventRecord->GetParamValue("CALLER", value), VALUE_PARSED_SUCCEED);
    EXPECT_EQ(value, "./hiperf_unittest");

    EXPECT_EQ(eventRecord->GetParamValue("TARGET_PROCESS", value), VALUE_PARSED_SUCCEED);
    EXPECT_EQ(value, "ALL");

    EXPECT_EQ(eventRecord->GetParamValue("ERROR_CODE", value), VALUE_PARSED_SUCCEED);
    EXPECT_EQ(value, "0");

    EXPECT_EQ(eventRecord->GetParamValue("ERROR_MESSAGE", value), VALUE_PARSED_SUCCEED);
    if (!value.empty()) {
        EXPECT_EQ(value, "NO_ERR");
    }
}

// system wide
HWTEST_F(SubCommandRecordTest, SystemWide, TestSize.Level1)
{
    ForkAndRunTest("-d 2 -a ", true, false);
}

// trackedCommand_
HWTEST_F(SubCommandRecordTest, TrackedCommandErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -a aa ", false, false);
}

// --app and -p
HWTEST_F(SubCommandRecordTest, HasTargetErr, TestSize.Level3)
{
    TestRecordCommand("--app test -p 123 -d 3 ", false, false);
}

HWTEST_F(SubCommandRecordTest, HasTargetErr1, TestSize.Level3)
{
    TestRecordCommand("-d 3 ", false, false);
}

// exclude hiperf
HWTEST_F(SubCommandRecordTest, ExcludePerf, TestSize.Level3)
{
    SubCommandRecord::CheckRecordCallBack callback = [](const PerfEventRecord& record) {
        if (record.GetType() == PERF_RECORD_SAMPLE) {
            const PerfRecordSample& recordSample = static_cast<const PerfRecordSample&>(record);
            if (recordSample.data_.pid == getpid()) {
                _exit(1);
            }
        }
    };
    ForkAndRunTest("-d 2 -a --exclude-hiperf ", true, false, callback);
}

HWTEST_F(SubCommandRecordTest, ExcludePerfErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 --exclude-hiperf ", false, true);
}

// select cpu
HWTEST_F(SubCommandRecordTest, SelectCpu, TestSize.Level1)
{
    SubCommandRecord::CheckRecordCallBack callback = [](const PerfEventRecord& record) {
        if (record.GetType() == PERF_RECORD_SAMPLE) {
            const PerfRecordSample& recordSample = static_cast<const PerfRecordSample&>(record);
            if (recordSample.data_.cpu != 0) {
                _exit(1);
            }
        }
    };
    ForkAndRunTest("-d 2 -c 0 ", true, true, callback);
}

HWTEST_F(SubCommandRecordTest, SelectCpuMulti, TestSize.Level0)
{
    int maxCpuid = sysconf(_SC_NPROCESSORS_CONF);
    std::string opt = "-d 2 -e sw-task-clock -c ";
    for (int i = 0; i < maxCpuid; i++) {
        opt += std::to_string(i);
        opt += ",";
    }
    opt.pop_back();
    opt += " ";

    SubCommandRecord::CheckRecordCallBack callback = [maxCpuid](const PerfEventRecord& record) {
        if (record.GetType() == PERF_RECORD_SAMPLE) {
            const PerfRecordSample& recordSample = static_cast<const PerfRecordSample&>(record);
            if (recordSample.data_.cpu >= maxCpuid) {
                _exit(1);
            }
        }
    };
    ForkAndRunTest(opt, true, true, callback);
}

HWTEST_F(SubCommandRecordTest, SelectCpuMinErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 -c -1 ", false);
}

HWTEST_F(SubCommandRecordTest, SelectCpuMaxErr, TestSize.Level2)
{
    int maxCpuid = sysconf(_SC_NPROCESSORS_CONF);
    std::string opt = "-d 2 -c ";
    opt += std::to_string(maxCpuid);
    opt += " ";
    TestRecordCommand(opt, false);
}

HWTEST_F(SubCommandRecordTest, SelectCpuInputErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -c abc ", false);
}

// --control
HWTEST_F(SubCommandRecordTest, CheckControlErr, TestSize.Level3)
{
    TestRecordCommand("-a --control st", false, false);
}

// cpu percent
HWTEST_F(SubCommandRecordTest, CpuLimitMin, TestSize.Level1)
{
    ForkAndRunTest("-d 2 --cpu-limit 1 ");
    EXPECT_EQ(CheckIntFromProcFile(PERF_CPU_TIME_MAX_PERCENT, 1), true);
}

HWTEST_F(SubCommandRecordTest, CpuLimitErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 --cpu-limit 0 ", false);
}

HWTEST_F(SubCommandRecordTest, CpuLimitMax, TestSize.Level1)
{
    ForkAndRunTest("-d 2 --cpu-limit 100 ");
    EXPECT_EQ(CheckIntFromProcFile(PERF_CPU_TIME_MAX_PERCENT, 100), true);
}

HWTEST_F(SubCommandRecordTest, CpuLimitMaxErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 --cpu-limit 101 ", false);
}

HWTEST_F(SubCommandRecordTest, CpuLimitInputErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 --cpu-limit abc ", false);
}

// frequency
HWTEST_F(SubCommandRecordTest, FrequncyMin, TestSize.Level1)
{
    ForkAndRunTest("-d 2 -f 1 ");
}

HWTEST_F(SubCommandRecordTest, FrequncyMinErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 -f 0 ", false);
}

HWTEST_F(SubCommandRecordTest, FrequncyMax, TestSize.Level3)
{
    ForkAndRunTest("-d 2 -f 100000 ");
}

HWTEST_F(SubCommandRecordTest, FrequncyMaxErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 -f 100001 ", false);
}

HWTEST_F(SubCommandRecordTest, FrequncyInputErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -f abc ", false);
}

// period
HWTEST_F(SubCommandRecordTest, PeriodMin, TestSize.Level1)
{
    ForkAndRunTest("-d 2 --period 1 ");
}

HWTEST_F(SubCommandRecordTest, PeriodMinErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 --period 0 ", false);
}

HWTEST_F(SubCommandRecordTest, PeriodMax, TestSize.Level1)
{
    std::string opt = "-d 2 --period ";
    opt += std::to_string(INT_MAX);
    opt += " ";
    ForkAndRunTest(opt);
}

HWTEST_F(SubCommandRecordTest, PeriodMaxErr, TestSize.Level2)
{
    std::string opt = "-d 2 --period ";
    uint32_t value = static_cast<uint32_t>(INT_MAX) + 1;
    opt += std::to_string(value);
    opt += " ";
    TestRecordCommand(opt, false);
}

HWTEST_F(SubCommandRecordTest, PeriodInputErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 --period abc ", false);
}

HWTEST_F(SubCommandRecordTest, PeriodAndFrequncyConflict, TestSize.Level2)
{
    TestRecordCommand("-d 2 -f 2000 --period 10 ", false);
}

void SubCommandRecordTest::TestEvents(std::string &opt, std::string &uk, bool isFork)
{
    PerfEvents perfEvents;
    perfEvents.SetHM(IsHM());
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
        if (isFork) {
            ForkAndRunTest(cmdline);
        } else {
            TestRecordCommand(cmdline);
        }
        TearDown();
        SetUp();
    }
}

// select events
HWTEST_F(SubCommandRecordTest, SelectEvents, TestSize.Level0)
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

HWTEST_F(SubCommandRecordTest, SelectEventsKernel_2, TestSize.Level1)
{
    std::string opt = "-d 2 -c 0 -e ";
    std::string uk = ":k";
    TestEvents(opt, uk, false);
}

HWTEST_F(SubCommandRecordTest, SelectEventsErr, TestSize.Level3)
{
    ForkAndRunTest("-d 2 -c 0 -e what ", false);
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

HWTEST_F(SubCommandRecordTest, GroupEventsErr, TestSize.Level2)
{
    ForkAndRunTest("-d 2 -c 0 -g what ", false);
}

HWTEST_F(SubCommandRecordTest, NoInherit, TestSize.Level1)
{
    ForkAndRunTest("-d 2 --no-inherit ");
}

// select pid
HWTEST_F(SubCommandRecordTest, SelectPid, TestSize.Level1)
{
    ForkAndRunTest("-d 2 -p 1 ", true, false);
}

HWTEST_F(SubCommandRecordTest, KernelSymbols, TestSize.Level1)
{
    TestRecordCommand("-d 2 -p 2 -s dwarf ", true, false);
}

HWTEST_F(SubCommandRecordTest, SelectPidMulti, TestSize.Level0)
{
    ForkAndRunTest("-d 2 -p 1,2 ", true, false);
}

HWTEST_F(SubCommandRecordTest, SelectPidMinErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 -p 0 ", false, false);
}

HWTEST_F(SubCommandRecordTest, SelectPidMinErr1, TestSize.Level3)
{
    TestRecordCommand("-d 2 -p -1 ", false, false);
}

HWTEST_F(SubCommandRecordTest, SelectPidErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 -p 99999999 ", false, false);
}

HWTEST_F(SubCommandRecordTest, SelectPidInputErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 -p abc ", false, false);
}

HWTEST_F(SubCommandRecordTest, SelectPidInputConflict, TestSize.Level3)
{
    ForkAndRunTest("-d 2 -a -p 1 ", false, false);
}

// select tid
HWTEST_F(SubCommandRecordTest, SelectTid, TestSize.Level1)
{
    ForkAndRunTest("-d 2 -t 1 ", true, false);
}

HWTEST_F(SubCommandRecordTest, SelectTidMulti, TestSize.Level0)
{
    ForkAndRunTest("-d 2 -t 1,2 ", true, false);
}

HWTEST_F(SubCommandRecordTest, SelectTidMinErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -t 0 ", false, false);
}

HWTEST_F(SubCommandRecordTest, SelectTidErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -t 99999999 ", false, false);
}

HWTEST_F(SubCommandRecordTest, SelectTidInputErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -t abc ", false, false);
}

// cpu off
HWTEST_F(SubCommandRecordTest, CpuOff, TestSize.Level1)
{
    ForkAndRunTest("-d 2 --offcpu -o /data/local/tmp/offcpu_perf.data");
}

HWTEST_F(SubCommandRecordTest, BranchFilterInputErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -j what ", false);
}

HWTEST_F(SubCommandRecordTest, BranchFilterInputMoreErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -j any,n ", false);
}

// call stack
HWTEST_F(SubCommandRecordTest, CallStackFp, TestSize.Level0)
{
    ForkAndRunTest("-d 2 --call-stack fp ");
    TearDown();
    SetUp();
    ForkAndRunTest("-d 2 -s fp ");
}

HWTEST_F(SubCommandRecordTest, CallStackFpInputMoreErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 --call-stack fp,abc ", false);
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 -s fp,abc ", false);
}

HWTEST_F(SubCommandRecordTest, CallStackInputErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 --call-stack what ", false);
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 -s what ", false);
}

HWTEST_F(SubCommandRecordTest, CallStackDwarfSizeMin, TestSize.Level2)
{
    // it will cause some crash in -fprofile-arcs and -ftest-coverage
    // we will fix it latter
    ForkAndRunTest("-d 2 --call-stack dwarf,8 ");
    TearDown();
    SetUp();
    ForkAndRunTest("-d 2 -s dwarf,8 ");
}

HWTEST_F(SubCommandRecordTest, CallStackDwarfSizeMinErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 --call-stack dwarf,7 ", false);
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 -s dwarf,7 ", false);
}

HWTEST_F(SubCommandRecordTest, CallStackDwarfSizeMax, TestSize.Level1)
{
    ForkAndRunTest("-d 2 --call-stack dwarf,65528 ");
    TearDown();
    SetUp();
    ForkAndRunTest("-d 2 -s dwarf,65528 ");
}

HWTEST_F(SubCommandRecordTest, CallStackDwarfSizeMaxErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 --call-stack dwarf,65529 ", false);
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 -s dwarf,65529 ", false);
}

HWTEST_F(SubCommandRecordTest, CallStackDwarfSizeErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 --call-stack dwarf,15 ", false);
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 -s dwarf,15 ", false);
}

HWTEST_F(SubCommandRecordTest, CallStackDwarfSizeInputErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 --call-stack dwarf,abc ", false);
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 -s dwarf,abc ", false);
}

HWTEST_F(SubCommandRecordTest, CallStackDwarfSizeInputMoreErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 --call-stack dwarf,16,32 ", false);
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 -s dwarf,16,32 ", false);
}

HWTEST_F(SubCommandRecordTest, CallStackUsageErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -s abc --call-stack bcd", false);
}

// unwind
HWTEST_F(SubCommandRecordTest, DlayUnwind, TestSize.Level1)
{
    ForkAndRunTest("-d 2 -s dwarf,16 --delay-unwind ");
}

HWTEST_F(SubCommandRecordTest, DisableUnwind, TestSize.Level1)
{
    ForkAndRunTest("-d 2 -s dwarf,16 --disable-unwind ");
}

HWTEST_F(SubCommandRecordTest, DisableCallstackMerge, TestSize.Level1)
{
    ForkAndRunTest("-d 2 -s dwarf,16 --disable-callstack-expand ");
}

// symbol dir
HWTEST_F(SubCommandRecordTest, SymbolDir, TestSize.Level1)
{
    ForkAndRunTest("-d 2 --symbol-dir ./ ");
}

HWTEST_F(SubCommandRecordTest, SymbolDirErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 --symbol-dir where ", false);
}

// clock id
HWTEST_F(SubCommandRecordTest, ClockIdMonotonic, TestSize.Level1)
{
    ForkAndRunTest("-d 2 --clockid monotonic ");
}

HWTEST_F(SubCommandRecordTest, ClockIdMonotonicRaw, TestSize.Level1)
{
    ForkAndRunTest("-d 2 --clockid monotonic_raw ");
}

HWTEST_F(SubCommandRecordTest, ClockIdBoottime, TestSize.Level1)
{
    ForkAndRunTest("-c 0 -d 2 -e sw-task-clock --clockid boottime ");
}

HWTEST_F(SubCommandRecordTest, ClockIdRealtime, TestSize.Level1)
{
    ForkAndRunTest("-c 0 -d 2 -e sw-task-clock --clockid realtime ");
}

HWTEST_F(SubCommandRecordTest, ClockIdClockTai, TestSize.Level1)
{
    ForkAndRunTest("-c 0 -d 2 -e sw-task-clock --clockid clock_tai ");
}

HWTEST_F(SubCommandRecordTest, ClockIdInputErr, TestSize.Level2)
{
    TestRecordCommand("-c 0 -d 2 --clockid what ", false);
}

// mmap pages
HWTEST_F(SubCommandRecordTest, MmapPagesPower2Err, TestSize.Level3)
{
    TestRecordCommand("-d 2 -m 101 ", false);
}

HWTEST_F(SubCommandRecordTest, MmapPagesMin, TestSize.Level2)
{
    ForkAndRunTest("-d 2 -m 2 ");
}

HWTEST_F(SubCommandRecordTest, MmapPagesMinErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 -m 1 ", false);
}

HWTEST_F(SubCommandRecordTest, MmapPagesMax, TestSize.Level1)
{
    ForkAndRunTest("-d 2 -m 1024 ");
}

HWTEST_F(SubCommandRecordTest, MmapPagesMaxErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 -m 1025 ", false);
}

HWTEST_F(SubCommandRecordTest, MmapPagesInputErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 -m abc ", false);
}

// output file name
HWTEST_F(SubCommandRecordTest, OutputFileName, TestSize.Level2)
{
    ForkAndRunTest("-d 2 -o /data/local/tmp/output.perf.data ");
}

HWTEST_F(SubCommandRecordTest, OutputFileNameErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 -o nopath/output.perf.data ", false);
}

// data size limit
HWTEST_F(SubCommandRecordTest, DataLimit, TestSize.Level2)
{
    ForkAndRunTest("-d 2 --data-limit 1K ");
    TearDown();
    SetUp();
    ForkAndRunTest("-d 2 --data-limit 1M ");
    TearDown();
    SetUp();
    ForkAndRunTest("-d 2 --data-limit 1G ");
}

HWTEST_F(SubCommandRecordTest, DataLimit1, TestSize.Level2)
{
    ForkAndRunTest("-a --data-limit 1K ", true, false);
}

HWTEST_F(SubCommandRecordTest, DataLimitErr, TestSize.Level2)
{
    TestRecordCommand("-d 2 --data-limit 10A ", false);
    TearDown();
    SetUp();
    TestRecordCommand("-d 2 --data-limit 0G ", false);
}

HWTEST_F(SubCommandRecordTest, RecordCompress, TestSize.Level1)
{
    ForkAndRunTest("-d 2 -z -o /data/local/tmp/perf.data.tar.gz");
}

HWTEST_F(SubCommandRecordTest, Verbose, TestSize.Level2)
{
    ForkAndRunTest("-d 2 --verbose ");
}

HWTEST_F(SubCommandRecordTest, DumpOptions, TestSize.Level2)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    SubCommandRecord cmd;
    cmd.DumpOptions();
    std::string stringOut = stdoutRecord.Stop();
    EXPECT_TRUE(stringOut.find("cpuPercent:	25") != std::string::npos);
    EXPECT_TRUE(stringOut.find("mmapPages_:	1024") != std::string::npos);
}

/**
 * @tc.name: FileSizeOnFrequency100_DWARF_SYSTEM
 * @tc.desc: Test size of file generated under system wide frequency 100 and dwarf unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency100_DWARF_SYSTEM, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -a -f 100 -s dwarf", true, false);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency500_DWARF_SYSTEM
 * @tc.desc: Test size of file generated under system wide frequency 500 and dwarf unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency500_DWARF_SYSTEM, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -a -f 500 -s dwarf", true, false);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency1000_DWARF_SYSTEM
 * @tc.desc: Test size of file generated under system wide frequency 1000 and dwarf unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency1000_DWARF_SYSTEM, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -a -f 1000 -s dwarf", true, false);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency2000_DWARF_SYSTEM
 * @tc.desc: Test size of file generated under system wide frequency 2000 and dwarf unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency2000_DWARF_SYSTEM, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -a -f 2000 -s dwarf", true, false);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency4000_DWARF_SYSTEM
 * @tc.desc: Test size of file generated under system wide frequency 4000 and dwarf unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency4000_DWARF_SYSTEM, TestSize.Level0)
{
    ForkAndRunTest("-d 10 -a -f 4000 -s dwarf", true, false);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency8000_DWARF_SYSTEM
 * @tc.desc: Test size of file generated under system wide frequency 8000 and dwarf unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency8000_DWARF_SYSTEM, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -a -f 8000 -s dwarf", true, false);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency100_FP_SYSTEM
 * @tc.desc: Test size of file generated under system wide frequency 100 and fp unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency100_FP_SYSTEM, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -a -f 100 -s fp", true, false);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency500_FP_SYSTEM
 * @tc.desc: Test size of file generated under system wide frequency 500 and fp unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency500_FP_SYSTEM, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -a -f 500 -s fp", true, false);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency1000_FP_SYSTEM
 * @tc.desc: Test size of file generated under system wide frequency 1000 and fp unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency1000_FP_SYSTEM, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -a -f 1000 -s fp", true, false);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency2000_FP_SYSTEM
 * @tc.desc: Test size of file generated under system wide frequency 2000 and fp unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency2000_FP_SYSTEM, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -a -f 2000 -s fp", true, false);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency4000_FP_SYSTEM
 * @tc.desc: Test size of file generated under system wide frequency 4000 and fp unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency4000_FP_SYSTEM, TestSize.Level0)
{
    ForkAndRunTest("-d 10 -a -f 4000 -s fp", true, false);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency8000_FP_SYSTEM
 * @tc.desc: Test size of file generated under system wide frequency 8000 and fp unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency8000_FP_SYSTEM, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -a -f 8000 -s fp", true, false);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency100_DWARF_PROCESS
 * @tc.desc: Test size of file generated under one process frequency 100 and dwarf unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency100_DWARF_PROCESS, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -f 100 -s dwarf", true, true);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency500_DWARF_PROCESS
 * @tc.desc: Test size of file generated under one process frequency 500 and dwarf unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency500_DWARF_PROCESS, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -f 500 -s dwarf", true, true);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency1000_DWARF_PROCESS
 * @tc.desc: Test size of file generated under one process frequency 1000 and dwarf unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency1000_DWARF_PROCESS, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -f 1000 -s dwarf", true, true);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency2000_DWARF_PROCESS
 * @tc.desc: Test size of file generated under one process frequency 2000 and dwarf unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency2000_DWARF_PROCESS, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -f 2000 -s dwarf", true, true);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency4000_DWARF_PROCESS
 * @tc.desc: Test size of file generated under one process frequency 4000 and dwarf unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency4000_DWARF_PROCESS, TestSize.Level0)
{
    ForkAndRunTest("-d 10 -f 4000 -s dwarf", true, true);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency8000_DWARF_PROCESS
 * @tc.desc: Test size of file generated under one process frequency 8000 and dwarf unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency8000_DWARF_PROCESS, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -f 8000 -s dwarf", true, true);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency100_FP_PROCESS
 * @tc.desc: Test size of file generated under one process frequency 100 and fp unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency100_FP_PROCESS, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -f 100 -s fp", true, true);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency500_FP_PROCESS
 * @tc.desc: Test size of file generated under one process frequency 500 and fp unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency500_FP_PROCESS, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -f 500 -s fp", true, true);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency1000_FP_PROCESS
 * @tc.desc: Test size of file generated under one process frequency 1000 and fp unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency1000_FP_PROCESS, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -f 1000 -s fp", true, true);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency2000_FP_PROCESS
 * @tc.desc: Test size of file generated under one process frequency 2000 and fp unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency2000_FP_PROCESS, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -f 2000 -s fp", true, true);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency4000_FP_PROCESS
 * @tc.desc: Test size of file generated under one process frequency 4000 and fp unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency4000_FP_PROCESS, TestSize.Level0)
{
    ForkAndRunTest("-d 10 -f 4000 -s fp", true, true);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: FileSizeOnFrequency8000_FP_PROCESS
 * @tc.desc: Test size of file generated under one process frequency 8000 and fp unwind
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, FileSizeOnFrequency8000_FP_PROCESS, TestSize.Level2)
{
    ForkAndRunTest("-d 10 -f 8000 -s fp", true, true);
    std::string fileName = TEST_FILE;
    size_t fileSize = GetFileSize(fileName.c_str());
    EXPECT_GT(fileSize, 0);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf dump -i /data/local/tmp/perf.data",
        {"magic:"}), true);
}

/**
 * @tc.name: ExcludeThreadName
 * @tc.desc: Test --exclude-thread option sucess
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, ExcludeThreadName, TestSize.Level1)
{
    SubCommandRecord::CheckRecordCallBack callback = [](const PerfEventRecord& record) {
        if (record.GetType() == PERF_RECORD_SAMPLE) {
            const PerfRecordSample& recordSample = static_cast<const PerfRecordSample&>(record);
            std::string threadName = ReadFileToString(StringPrintf("/proc/%d/comm", recordSample.data_.tid));
            if (threadName == "DfxWatchdog") {
                _exit(1);
            }
        }
    };
    ForkAndRunTest("-d 2 --exclude-thread DfxWatchdog ", true, true, callback);
}

/**
 * @tc.name: ExcludeThreadNames
 * @tc.desc: Test --exclude-thread option multi threads
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, ExcludeThreadNames, TestSize.Level1)
{
    SubCommandRecord::CheckRecordCallBack callback = [](const PerfEventRecord& record) {
        if (record.GetType() == PERF_RECORD_SAMPLE) {
            const PerfRecordSample& recordSample = static_cast<const PerfRecordSample&>(record);
            std::string threadName = ReadFileToString(StringPrintf("/proc/%d/comm", recordSample.data_.tid));
            if (threadName == "DfxWatchdog" || threadName == "GC_WorkerThread") {
                _exit(1);
            }
        }
    };
    ForkAndRunTest("-d 2 --exclude-thread DfxWatchdog,GC_WorkerThread ", true, true, callback);
}

/**
 * @tc.name: ExcludeErrorThreadName
 * @tc.desc: Test --exclude-thread option error thread name
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, ExcludeErrorThreadName, TestSize.Level1)
{
    SubCommandRecord::CheckRecordCallBack callback = [](const PerfEventRecord& record) {
        if (record.GetType() == PERF_RECORD_SAMPLE) {
            const PerfRecordSample& recordSample = static_cast<const PerfRecordSample&>(record);
            std::string threadName = ReadFileToString(StringPrintf("/proc/%d/comm", recordSample.data_.tid));
            if (threadName == "test") {
                _exit(1);
            }
        }
    };
    ForkAndRunTest("-d 2 --exclude-thread test ", true, true, callback);
}

/**
 * @tc.name: ExcludeErrorThreadNames
 * @tc.desc: Test --exclude-thread option multi error thread names
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, ExcludeErrorThreadNames, TestSize.Level1)
{
    SubCommandRecord::CheckRecordCallBack callback = [](const PerfEventRecord& record) {
        if (record.GetType() == PERF_RECORD_SAMPLE) {
            const PerfRecordSample& recordSample = static_cast<const PerfRecordSample&>(record);
            std::string threadName = ReadFileToString(StringPrintf("/proc/%d/comm", recordSample.data_.tid));
            if (threadName == "test1" || threadName == "test2") {
                _exit(1);
            }
        }
    };
    ForkAndRunTest("-d 2 --exclude-thread test1,test2 ", true, true, callback);
}

/**
 * @tc.name: ExcludeTids
 * @tc.desc: Test --exclude-tid
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, ExcludeTids, TestSize.Level1)
{
    SubCommandRecord::CheckRecordCallBack callback = [](const PerfEventRecord& record) {
        if (record.GetType() == PERF_RECORD_SAMPLE) {
            const PerfRecordSample& recordSample = static_cast<const PerfRecordSample&>(record);
            if (recordSample.data_.tid == 200) {
                _exit(1);
            }
        }
    };
    ForkAndRunTest("-d 2 -s dwarf -f 2000 --exclude-tid 200", true, true, callback);
}

/**
 * @tc.name: ExcludeThread
 * @tc.desc: Test --exclude-thread
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, ExcludeThread, TestSize.Level1)
{
    SubCommandRecord::CheckRecordCallBack callback = [](const PerfEventRecord& record) {
        if (record.GetType() == PERF_RECORD_SAMPLE) {
            const PerfRecordSample& recordSample = static_cast<const PerfRecordSample&>(record);
            std::string threadName = ReadFileToString(StringPrintf("/proc/%d/comm", recordSample.data_.tid));
            if (threadName == "com.app.test") {
                _exit(1);
            }
        }
    };
    ForkAndRunTest("-d 2 -s dwarf -f 2000 --exclude-thread com.app.test", true, true, callback);
}

/**
 * @tc.name: ExcludeMixedThreadName
 * @tc.desc: Test --exclude-thread option mixed correct name and error name
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, ExcludeMixedThreadName, TestSize.Level1)
{
    SubCommandRecord::CheckRecordCallBack callback = [](const PerfEventRecord& record) {
        if (record.GetType() == PERF_RECORD_SAMPLE) {
            const PerfRecordSample& recordSample = static_cast<const PerfRecordSample&>(record);
            std::string threadName = ReadFileToString(StringPrintf("/proc/%d/comm", recordSample.data_.tid));
            if (threadName == "DfxWatchdog" || threadName == "test") {
                _exit(1);
            }
        }
    };
    ForkAndRunTest("-d 2 --exclude-thread DfxWatchdog,test ", true, true, callback);
}

// --restart
HWTEST_F(SubCommandRecordTest, ReStartNotApp1, TestSize.Level3)
{
    TestRecordCommand("-p 5 --restart ", false, false);
}

HWTEST_F(SubCommandRecordTest, ReStartNotApp2, TestSize.Level3)
{
    TestRecordCommand("-a --restart ", false, false);
}

HWTEST_F(SubCommandRecordTest, ReStartNotApp3, TestSize.Level3)
{
    TestRecordCommand("-p 5 -a --restart ", false, false);
}

HWTEST_F(SubCommandRecordTest, ReStartConflict, TestSize.Level3)
{
    TestRecordCommand("--restart -a ", false, true);
}

HWTEST_F(SubCommandRecordTest, ReStart, TestSize.Level0)
{
    TestRecordCommand("--restart ", false, true);
}

/**
 * @tc.name: CmdLinesSizeSucess
 * @tc.desc: Test --cmdline-size option
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, CmdLinesSizeSucess, TestSize.Level1)
{
    ForkAndRunTest("-d 2 --cmdline-size 1024 ", true);
}

/**
 * @tc.name: CmdLinesSizeOutRange
 * @tc.desc: Test --cmdline-size option
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, CmdLinesSizeOutRange, TestSize.Level3)
{
    TestRecordCommand("-d 2 --cmdline-size 8192 ", false);
}

/**
 * @tc.name: CmdLinesSizeNotPowerOf2
 * @tc.desc: Test --cmdline-size option
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, CmdLinesSizeNotPowerOf2, TestSize.Level3)
{
    TestRecordCommand("-d 2 --cmdline-size 1000 ", false);
}

/**
 * @tc.name: EnableDebugInfoSymbolicFp
 * @tc.desc: Test --enable-debuginfo-symbolic option with -s fp
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, EnableDebugInfoSymbolicFp, TestSize.Level1)
{
    ForkAndRunTest("-d 2 -s fp --enable-debuginfo-symbolic ", true);
}

/**
 * @tc.name: EnableDebugInfoSymbolicDwarf
 * @tc.desc: Test --enable-debuginfo-symbolic option with -s dwarf
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, EnableDebugInfoSymbolicDwarf, TestSize.Level1)
{
    ForkAndRunTest("-d 2 -s dwarf --enable-debuginfo-symbolic ", true);
}

/**
 * @tc.name: CallChainUserOnlyFp
 * @tc.desc: Test --callchain-useronly option with fp
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, CallChainUserOnlyFp, TestSize.Level3)
{
    ForkAndRunTest("-d 2 -s fp --callchain-useronly", true, true);
}

/**
 * @tc.name: CallChainUserOnlyDwarf
 * @tc.desc: Test --callchain-useronly option with dwarf
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, CallChainUserOnlyDwarf, TestSize.Level1)
{
    ForkAndRunTest("-d 2 -s dwarf --callchain-useronly", true, true);
}

/**
 * @tc.name: CallChainUserOnlyError
 * @tc.desc: Test --callchain-useronly option without fp/dwarf
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, CallChainUserOnly, TestSize.Level3)
{
    ForkAndRunTest("-d 2 --callchain-useronly", true, true);
}

/**
 * @tc.name: DedupStack
 * @tc.desc: Test --dedup_stack option
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, DedupStack, TestSize.Level1)
{
    ForkAndRunTest("-d 2 -s dwarf --dedup_stack", true, true);
}

/**
 * @tc.name: DedupStackErr
 * @tc.desc: Test --dedup_stack option with -a
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, DedupStackErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -a -s dwarf --dedup_stack", false, false);
}

/**
 * @tc.name: TestNoFork
 * @tc.desc: Test no fork
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestNoFork, TestSize.Level1)
{
    TestRecordCommand("-d 2 -s dwarf --dedup_stack -f 2000 --cmdline-size 1024", true, true);
}

/**
 * @tc.name: TestAllNoFork
 * @tc.desc: Test no fork with -a
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestAllNoFork, TestSize.Level1)
{
    TestRecordCommand("-d 2 -a -s dwarf --clockid monotonic --exclude-hiperf", true, false);
}

/**
 * @tc.name: CreateFifoServer
 * @tc.desc: Test create Fipo server
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, CreateFifoServer, TestSize.Level1)
{
    SubCommandRecord cmd;
    EXPECT_EQ(cmd.CreateFifoServer(), false);
}

/**
 * @tc.name: SendFifoAndWaitReply
 * @tc.desc: Test send Fifo and wait reply
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, SendFifoAndWaitReply, TestSize.Level1)
{
    SubCommandRecord cmd;
    std::string test = "test";
    EXPECT_EQ(cmd.perfPipe_.SendFifoAndWaitReply(test, CONTROL_WAITREPY_TOMEOUT), false);
}

/**
 * @tc.name: ReportErr
 * @tc.desc: Test report option error
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, ReportErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -a --report ", false, false);
}

/**
 * @tc.name: TestHasReport
 * @tc.desc: Test --report option
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestHasReport, TestSize.Level1)
{
    TestRecordCommand("-d 2 -s dwarf --report", true, true);
}

/**
 * @tc.name: TraceCommand
 * @tc.desc: Test TraceCommand option
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TraceCommand, TestSize.Level1)
{
    TestRecordCommand("-d 2 -s dwarf ls", true, false);
}

/**
 * @tc.name: TraceCommandErr
 * @tc.desc: Test InvalidCommand option
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TraceCommandErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -s dwarf invalidcommand", false, false);
}

/**
 * @tc.name: TestInputErr
 * @tc.desc: Test input with -a
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestInputErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -a -s dwarf -f 2000 --pipe_input", false, false);
}

/**
 * @tc.name: TestOutputErr
 * @tc.desc: Test output with -a
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestOutputErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -a -s dwarf -f 2000 --pipe_output", false, false);
}

/**
 * @tc.name: TestBranchFilterErr
 * @tc.desc: Test branch filter with -a
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestBranchFilterErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -a -s dwarf -f 2000 -j", false, false);
}

/**
 * @tc.name: TestCallStackErr
 * @tc.desc: Test call stack with -a
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestCallStackErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -a -f 2000 --call-stack", false, false);
}

/**
 * @tc.name: TestEventGroupErr
 * @tc.desc: Test event group with -a
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestEventGroupErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -a -f 2000 -g", false, false);
}

/**
 * @tc.name: TestExcludeThreadErr
 * @tc.desc: Test exclude-thread with -a
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestExcludeThreadErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -a -f 2000 --exclude-thread", false, false);
}

/**
 * @tc.name: TestSymbolDirErr
 * @tc.desc: Test symbol-dir with -a
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestSymbolDirErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -a -f 2000 --symbol-dir", false, false);
}

/**
 * @tc.name: TestControlErr
 * @tc.desc: Test control with -a
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestControlErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -a -f 2000 --control", false, false);
}

/**
 * @tc.name: TestCmdlineSizeErr
 * @tc.desc: Test cmdline-size with -a
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestCmdlineSizeErr, TestSize.Level3)
{
    TestRecordCommand("-d 2 -a -f 2000 --cmdline-size", false, false);
}

/**
 * @tc.name: AddReportArgs
 * @tc.desc: Test AddReportArgs with -a
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, ReportSampleAll, TestSize.Level1)
{
    SubCommandRecord command;
    command.targetSystemWide_ = true;

    CommandReporter reporter("record");
    reporter.isReported_ = true;
    command.AddReportArgs(reporter);
    EXPECT_EQ(reporter.targetProcess_, "ALL");
}

/**
 * @tc.name: AddReportArgs
 * @tc.desc: Test AddReportArgs with -p
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, ReportSamplePid, TestSize.Level1)
{
    SubCommandRecord command;
    command.selectPids_ = { getpid() };
    std::string name = GetProcessName(getpid());

    CommandReporter reporter("record");
    reporter.isReported_ = true;
    command.AddReportArgs(reporter);
    EXPECT_EQ(reporter.targetProcess_, name);
}

/**
 * @tc.name: AddReportArgs
 * @tc.desc: Test AddReportArgs with --app
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, ReportSampleApp, TestSize.Level1)
{
    SubCommandRecord command;
    command.appPackage_ = "com.test.app";

    CommandReporter reporter("record");
    reporter.isReported_ = true;
    command.AddReportArgs(reporter);
    EXPECT_EQ(reporter.targetProcess_, "com.test.app");
}

/**
 * @tc.name: ChecKernel
 * @tc.desc: Test kernel version
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, ChecKernel, TestSize.Level1)
{
    utsname unameBuf;
    if ((uname(&unameBuf)) == 0) {
        std::string osrelease = unameBuf.release;
        std::string sysname = unameBuf.sysname;
        EXPECT_EQ(osrelease.find(HMKERNEL) != std::string::npos || sysname.find("Linux") != std::string::npos, true);
    }
}

/**
 * @tc.name: RecordAndReport
 * @tc.desc: Test record and report
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, RecordAndReport, TestSize.Level1)
{
    const std::string cmd = "hiperf record -d 1 -s dwarf -f 100 --app " +
                            SubCommandRecordTest::testProcesses +
                            " -o /data/local/tmp/perf.data";
    EXPECT_EQ(CheckTraceCommandOutput(cmd, {"Process and Saving data..."}), true);
    EXPECT_EQ(CheckTraceCommandOutput(
        "hiperf report --json -i /data/local/tmp/perf.data -o /data/local/tmp/perf.json",
        {"report done"}),
              true);
    EXPECT_TRUE(CheckJsonReport("/data/local/tmp/perf.json", ""));
}

/**
 * @tc.name: GetInstance
 * @tc.desc: Test GetInstance
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, GetInstance, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    EXPECT_EQ(SubCommandRecord::GetInstance().Name(), "record");
}

/**
 * @tc.name: CheckExcludeArgs
 * @tc.desc: Test CheckExcludeArgs
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, CheckExcludeArgs, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    SubCommandRecord record;
    record.targetSystemWide_ = true;
    record.excludeTidArgs_ = { 1, 2, 3 };
    EXPECT_EQ(record.CheckExcludeArgs(), false);

    record.excludeTidArgs_ = {};
    record.excludeThreadNameArgs_ = { "a" };
    EXPECT_EQ(record.CheckExcludeArgs(), false);

    record.targetSystemWide_ = false;
    record.excludeProcessNameArgs_ = { "a" };
    EXPECT_EQ(record.CheckExcludeArgs(), false);

    record.excludeProcessNameArgs_ = {};
    record.excludeHiperf_ = true;
    EXPECT_EQ(record.CheckExcludeArgs(), false);

    record.excludeHiperf_ = false;
    EXPECT_EQ(record.CheckExcludeArgs(), true);
}

/**
 * @tc.name: ParseControlCmd
 * @tc.desc: Test ParseControlCmd
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, ParseControlCmd, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    SubCommandRecord record;
    std::vector<std::string> strs {"prepare", "start", "pause", "resume", "output", "stop", ""};
    for (const auto& str : strs) {
        EXPECT_TRUE(record.ParseControlCmd(str));
    }

    EXPECT_FALSE(record.ParseControlCmd("ABC"));
}

/**
 * @tc.name: PostOutputRecordFile
 * @tc.desc: Test PostOutputRecordFile
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, PostOutputRecordFile, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    SubCommandRecord record;
    record.fileWriter_ = std::make_unique<PerfFileWriter>();
    record.outputEnd_ = false;
    EXPECT_EQ(record.PostOutputRecordFile(false), true);
    EXPECT_EQ(record.fileWriter_, nullptr);
    EXPECT_EQ(record.outputEnd_, true);
}

/**
 * @tc.name: InitControlCommandHandlerMap
 * @tc.desc: Test InitControlCommandHandlerMap
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, InitControlCommandHandlerMap, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    SubCommandRecord record;
    record.InitControlCommandHandlerMap();
    EXPECT_EQ(record.controlCommandHandlerMap_.size(), 7u);
}

/**
 * @tc.name: CollectExcludeThread
 * @tc.desc: Test CollectExcludeThread
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, CollectExcludeThread1, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    SubCommandRecord record;
    record.excludeHiperf_ = false;
    record.excludeTids_ = {};
    pid_t pid = getpid();
    std::string name = GetProcessName(pid);
    size_t pos = name.find_last_of("/");
    if (pos != std::string::npos) {
        name = name.substr(pos + 1);
    }
    record.excludeProcessNameArgs_ = { name };
    record.excludeTidArgs_ = {};
    record.CollectExcludeThread();

    ASSERT_GE(record.excludePids_.size(), 1u);
    EXPECT_EQ(record.excludeTids_.size(), 0u);
    bool get = false;
    for (pid_t id : record.excludePids_) {
        if (pid == id) {
            get = true;
            break;
        }
    }
    EXPECT_EQ(get, true);
}

/**
 * @tc.name: SetExcludeHiperf
 * @tc.desc: Test SetExcludeHiperf
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, SetExcludeHiperf, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    SubCommandRecord record;
    record.excludeHiperf_ = true;
    pid_t pid = getpid();
    record.SetExcludeHiperf();

    ASSERT_EQ(record.excludePids_.size(), 1u);
    EXPECT_EQ(*(record.excludePids_.begin()), pid);
}

/**
 * @tc.name: CollectExcludeThread
 * @tc.desc: Test CollectExcludeThread
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, CollectExcludeThread3, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    SubCommandRecord record;
    record.excludeHiperf_ = false;
    record.excludeTids_ = {};
    record.excludeProcessNameArgs_ = {};
    record.excludeTidArgs_ = {1, 2, 3};
    record.CollectExcludeThread();

    ASSERT_EQ(record.excludePids_.size(), 0u);
    ASSERT_EQ(record.excludeTids_.size(), 3u);

    for (const auto& tid : record.excludeTidArgs_) {
        EXPECT_TRUE(record.excludeTids_.find(tid) != record.excludeTids_.end());
    }
}

/**
 * @tc.name: IsThreadExcluded
 * @tc.desc: Test IsThreadExcluded
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, IsThreadExcluded, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    SubCommandRecord record;
    record.excludePids_ = { 1, 2 };
    record.excludeTids_ = { 1, 2, 3 };

    EXPECT_EQ(record.IsThreadExcluded(1, 1), true);
    EXPECT_EQ(record.IsThreadExcluded(1, 3), true);
    EXPECT_EQ(record.IsThreadExcluded(1, 4), true);
    EXPECT_EQ(record.IsThreadExcluded(3, 1), true);
    EXPECT_EQ(record.IsThreadExcluded(3, 5), false);
}

/**
 * @tc.name: CheckBacktrackOption
 * @tc.desc: Test CheckBacktrackOption
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, CheckBacktrackOption, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    SubCommandRecord record;
    record.backtrack_ = false;
    EXPECT_EQ(record.CheckBacktrackOption(), true);

    record.backtrack_ = true;
    record.controlCmd_ = {};
    record.clientPipeInput_ = -1;
    EXPECT_EQ(record.CheckBacktrackOption(), false);

    record.clientPipeInput_ = 0;
    record.clockId_ = "";
    EXPECT_EQ(record.CheckBacktrackOption(), true);

    record.clockId_ = "realtime";
    EXPECT_EQ(record.CheckBacktrackOption(), false);

    record.clockId_ = "boottime";
    EXPECT_EQ(record.CheckBacktrackOption(), true);
}

/**
 * @tc.name: GetSpeOptions
 * @tc.desc: Test GetSpeOptions
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, GetSpeOptions, TestSize.Level1)
{
    constexpr uint64_t disable     = 0;
    constexpr uint64_t enable      = 1;
    constexpr uint64_t minLatency  = 10;
    constexpr uint64_t eventFilter = 0x8;
    SubCommandRecord command;
    command.selectEvents_ = {"arm_spe_0/load_filter=1", "branch_filter=1", "pct_enable=1",
                             "store_filter=0", "ts_enable=1", "pa_enable=0", "jitter=1",
                             "min_latency=10", "event_filter=0x8/"};
    EXPECT_EQ(command.GetSpeOptions(), true);
    EXPECT_EQ(command.speOptMap_["ts_enable"], enable);
    EXPECT_EQ(command.speOptMap_["pa_enable"], disable);
    EXPECT_EQ(command.speOptMap_["pct_enable"], enable);
    EXPECT_EQ(command.speOptMap_["branch_filter"], enable);
    EXPECT_EQ(command.speOptMap_["load_filter"], enable);
    EXPECT_EQ(command.speOptMap_["store_filter"], disable);
    EXPECT_EQ(command.speOptMap_["jitter"], enable);
    EXPECT_EQ(command.speOptMap_["min_latency"], minLatency);
    EXPECT_EQ(command.speOptMap_["event_filter"], eventFilter);
}

/**
 * @tc.name: CheckSpeOption
 * @tc.desc: Test CheckSpeOption
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, CheckSpeOption, TestSize.Level1)
{
    constexpr uint64_t disable = 0;
    constexpr uint64_t enable  = 1;
    SubCommandRecord command;
    command.speOptMap_["ts_enable"] = enable; // 2 : invalid value
    command.speOptMap_["pa_enable"] = enable;
    command.speOptMap_["pct_enable"] = enable;
    command.speOptMap_["branch_filter"] = enable;
    command.speOptMap_["load_filter"] = disable;
    command.speOptMap_["store_filter"] = enable;
    command.speOptMap_["jitter"] = enable;
    EXPECT_EQ(command.CheckSpeOption(), true);
}

/**
 * @tc.name: CheckSpeOptionErr
 * @tc.desc: Test CheckSpeOption
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, CheckSpeOptionErr, TestSize.Level3)
{
    constexpr uint64_t disable = 0;
    constexpr uint64_t enable  = 1;
    constexpr uint64_t invalid = 20;
    SubCommandRecord command;
    command.speOptMap_["branch_filter"] = invalid;
    command.speOptMap_["load_filter"] = disable;
    command.speOptMap_["jitter"] = enable;
    EXPECT_EQ(command.CheckSpeOption(), false);
}

HWTEST_F(SubCommandRecordTest, CheckThreadName, TestSize.Level1)
{
    bool checkRet = false;
    SubCommandRecord cmd;
    PerfEvents event;
    pid_t timeTid = 0;
    event.backtrack_ = true;
    event.eventGroupItem_.emplace_back();
    event.eventGroupItem_[0].eventItems.emplace_back();
    event.readRecordThreadRunning_ = true;

    auto saveRecord = [](PerfEventRecord& record) -> bool {
        return true;
    };
    cmd.virtualRuntime_.SetRecordMode(saveRecord);
    EXPECT_EQ(event.PrepareRecordThread(), true);
    std::this_thread::sleep_for(1s);
    std::vector<pid_t> tids = GetSubthreadIDs(getpid());
    EXPECT_FALSE(tids.empty());
    bool get = false;
    for (const pid_t tid : tids) {
        std::string threadName = ReadFileToString(StringPrintf("/proc/%d/comm", tid));
        while (threadName.back() == '\0' || threadName.back() == '\n') {
            threadName.pop_back();
        }
        if (threadName == "timer_thread") {
            timeTid = tid;
            get = true;
            break;
        }
    }
    EXPECT_EQ(get, true);

    std::string recordCommand = "-t " + std::to_string(timeTid) + " -d 5 -s dwarf -o /data/local/tmp/tid_name.data";
    TestRecordCommand(recordCommand, true, false);
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    EXPECT_EQ(Command::DispatchCommand("report -i /data/local/tmp/tid_name.data -o /data/local/tmp/tid_name.report"),
              true);
    std::string stringOut = stdoutRecord.Stop();
    EXPECT_EQ(stringOut.find("report done") != std::string::npos, true);

    std::ifstream ifs("/data/local/tmp/tid_name.report", std::ifstream::in);
    EXPECT_EQ(ifs.is_open(), true);
    std::string line;
    while (getline(ifs, line)) {
        if (line.find("timer_thread") != std::string::npos) {
            checkRet = true;
            break;
        }
    }
    ifs.close();
    EXPECT_EQ(checkRet, true);
}

HWTEST_F(SubCommandRecordTest, CheckDevhostMapOffset, TestSize.Level1)
{
    if (IsHM()) {
        bool checkRet = false;
        SubCommandRecord cmd;
        cmd.SetHM();
        VirtualThread &kthread = cmd.virtualRuntime_.GetThread(cmd.virtualRuntime_.devhostPid_,
                                                            cmd.virtualRuntime_.devhostPid_);
        kthread.ParseDevhostMap(cmd.virtualRuntime_.devhostPid_);
        TestRecordCommand("-d 5 -s dwarf -o /data/local/tmp/test_maps.data", true, true);
        StdoutRecord stdoutRecord;
        stdoutRecord.Start();
        EXPECT_EQ(Command::DispatchCommand("dump -i /data/local/tmp/test_maps.data"), true);
        std::string stringOut = stdoutRecord.Stop();
        std::istringstream stream(stringOut);

        std::string line;
        bool isMmapRecord = false;
        bool isMmapFirstLine = false;
        uint64_t mapOffset = 0;
        while (getline(stream, line)) {
            if (strstr(line.c_str(), "record mmap:") != nullptr) {
                isMmapRecord = true;
                continue;
            }
            if (strstr(line.c_str(), "record sample:") != nullptr) {
                break;
            }
            if (isMmapFirstLine) {
                isMmapFirstLine = false;
                uint64_t pgoff = 0;
                int ret = sscanf_s(line.c_str(), "  %*s 0x%" PRIx64 ", %*s %*s", &pgoff);
                constexpr int numSlices {1};
                if (ret != numSlices) {
                    printf("unknown line %d: '%s' \n", ret, line.c_str());
                    continue;
                }
                EXPECT_EQ(mapOffset, pgoff);
                checkRet = true;
                continue;
            }

            if (isMmapRecord) {
                isMmapRecord = false;
                isMmapFirstLine = GetMemMapOffset(cmd.virtualRuntime_.devhostPid_, mapOffset, kthread.memMaps_, line);
            }
        }
        EXPECT_EQ(checkRet, true);
    }
}

HWTEST_F(SubCommandRecordTest, CheckGetCountFromFile, TestSize.Level1)
{
    SubCommandRecord cmd;
    uint32_t cpuPresent = cmd.GetCountFromFile("/sys/devices/system/cpu/present");
    ASSERT_GT(cpuPresent, 1);
    uint32_t cpuOnline = cmd.GetCountFromFile("/sys/devices/system/cpu/online");
    ASSERT_GT(cpuOnline, 1);
}

HWTEST_F(SubCommandRecordTest, CheckProductCfg, TestSize.Level1)
{
    SubCommandRecord cmd;
    cJSON* root = GetProductCfgRoot(cmd.PRODUCT_CONFIG_PATH);
    if (root) {
        size_t mmapPages = 0;
        EXPECT_EQ(GetCfgValue(cmd.PRODUCT_CONFIG_PATH, cmd.CFG_MAP_PAGES, mmapPages), true);
        cmd.GetMmapPagesCfg();
        cJSON_Delete(root);
    }
}

/**
 * @tc.name: TestOnSubCommand_control01
 * @tc.desc: prepare, start, stop
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestOnSubCommand_control01, TestSize.Level1)
{
    ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    EXPECT_EQ(CheckTraceCommandOutput(
        "hiperf record --control prepare -a --exclude-hiperf -o /data/local/tmp/perf_control01.data -s dwarf",
        {"create control hiperf sampling success"}),
              true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control start", {"start sampling success"}),
              true);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}),
              true);
    EXPECT_EQ(CheckTraceCommandOutput(
        "hiperf report --json -i /data/local/tmp/perf_control01.data -o /data/local/tmp/perf.json",
        {"report done"}),
              true);
}

/**
 * @tc.name: TestOnSubCommand_control_app
 * @tc.desc: prepare, start, stop with app
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestOnSubCommand_control_app, TestSize.Level1)
{
    ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    const std::string cmd = "hiperf record --control prepare --app " +
                            SubCommandRecordTest::testProcesses +
                            " -o /data/local/tmp/perf_control_app.data -s dwarf";
    EXPECT_EQ(CheckTraceCommandOutput(cmd, {"create control hiperf sampling success"}),
              true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control start", {"start sampling success"}),
              true);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}),
              true);
    EXPECT_EQ(CheckTraceCommandOutput(
        "hiperf report --json -i /data/local/tmp/perf_control_app.data -o /data/local/tmp/perf.json",
        {"report done"}),
              true);
    EXPECT_TRUE(CheckJsonReport("/data/local/tmp/perf.json", ""));
}

/**
 * @tc.name: TestOnSubCommand_control02
 * @tc.desc: prepare, prepare
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestOnSubCommand_control02, TestSize.Level1)
{
    ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    ASSERT_TRUE(RunCmd("hiperf record --control prepare -a"));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control prepare -a",
                                      {"another sampling service is running"}),
              true);
}

/**
 * @tc.name: TestOnSubCommand_control03
 * @tc.desc: start, stop
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestOnSubCommand_control03, TestSize.Level1)
{
    ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control start", {"start sampling failed"}),
              true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling failed"}),
              true);
}

/**
 * @tc.name: TestOnSubCommand_control04
 * @tc.desc: prepare, start, resume, pause, stop
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestOnSubCommand_control04, TestSize.Level1)
{
    ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control prepare -a",
                                      {"create control hiperf sampling success"}),
              true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control start", {"start sampling success"}),
              true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control resume", {"resume sampling success"}),
              true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control pause", {"pause sampling success"}),
              true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}),
              true);
}

/**
 * @tc.name: TestOnSubCommand_control05
 * @tc.desc: prepare, start, output, stop
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestOnSubCommand_control05, TestSize.Level1)
{
    ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control prepare -a --backtrack",
                                      {"create control hiperf sampling success"}),
              true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control start", {"start sampling success"}),
              true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control output", {"output sampling success"}),
              true);
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop", {"stop sampling success"}),
              true);
}

/**
 * @tc.name: Control_Stability
 * @tc.desc: --control prepare, start, stop
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, Control_Stability, TestSize.Level1)
{
    ASSERT_TRUE(RunCmd("hiperf record --control stop"));
    for (int i = 0; i < 10; i++) {  // 10: Number of loop
        EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control prepare -a -e hw-cpu-cycles,hw-instructions",
            {"create control hiperf sampling success"}), true);
        EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control start",
            {"start sampling success"}), true);
        EXPECT_EQ(CheckTraceCommandOutput("hiperf record --control stop",
            {"stop sampling success"}), true);
    }
}

/**
 * @tc.name: TestOnSubCommand_WrongStopSeconds
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, WrongStopSeconds, TestSize.Level2)
{
    std::string opt = "-d 123abc  ";
    TestRecordCommand(opt, false);
}

/**
 * @tc.name: TestOnSubCommand_OutPutFileName
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, OutPutFileName, TestSize.Level2)
{
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record -d 3 -a -o /data/log/hiperflog/perf.data",
        {"Invalid output file path, permission denied"}), true);
}

/**
 * @tc.name: TestOnSubCommand_OutPutFileName
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, GetOffsetNum, TestSize.Level1)
{
    SubCommandRecord cmd;
    uint32_t offset = cmd.GetOffsetNum();
    EXPECT_GT(offset, 0);
}

/**
 * @tc.name: TestOnSubCommand_OutPutFileName
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, UpdateDevHostMaps1, TestSize.Level1)
{
    constexpr uint32_t pid = 70;
    constexpr uint32_t tid = 70;
    constexpr uint32_t addr = 111;
    constexpr uint64_t len = 1000;
    constexpr uint64_t pgoff = 0;
    PerfRecordMmap recordIn {true, pid, tid, addr,
                             len, pgoff, "testdatammap"};
    SubCommandRecord cmd;
    cmd.rootPids_.insert(pid);
    cmd.offset_ = cmd.GetOffsetNum();
    cmd.UpdateDevHostMaps(recordIn);
    EXPECT_EQ(recordIn.data_.addr, cmd.offset_ + addr);
}

/**
 * @tc.name: TestOnSubCommand_OutPutFileName
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, UpdateDevHostMaps2, TestSize.Level1)
{
    constexpr uint32_t devhostPid = 71;
    constexpr uint32_t pid = 70;
    constexpr uint32_t tid = 70;
    constexpr uint32_t addr = 111;
    constexpr uint64_t len = 1000;
    constexpr uint64_t pgoff = 0;
    PerfRecordMmap recordIn {true, pid, tid, addr,
                             len, pgoff, "testdatammap"};
    SubCommandRecord cmd;
    cmd.rootPids_.insert(devhostPid);
    cmd.offset_ = cmd.GetOffsetNum();
    cmd.UpdateDevHostMaps(recordIn);
    EXPECT_EQ(recordIn.data_.addr, addr);
}

/**
 * @tc.name: TestOnSubCommand_OutPutFileName
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, UpdateDevHostMaps3, TestSize.Level1)
{
    constexpr uint32_t pid = 70;
    constexpr uint32_t tid = 70;
    constexpr uint32_t addr = 111;
    constexpr uint64_t len = 1000;
    constexpr uint64_t pgoff = 0;
    constexpr uint64_t testNum = 1;
    PerfRecordMmap2 recordIn {true, pid, tid, addr, len, pgoff,
                              testNum, testNum, testNum, testNum, testNum, "testdatammap2"};
    SubCommandRecord cmd;
    cmd.rootPids_.insert(pid);
    cmd.offset_ = cmd.GetOffsetNum();
    cmd.UpdateDevHostMaps(recordIn);
    EXPECT_EQ(recordIn.data_.addr, cmd.offset_ + addr);
}

/**
 * @tc.name: TestOnSubCommand_OutPutFileName
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, UpdateDevHostMaps4, TestSize.Level1)
{
    constexpr uint32_t devhostPid = 71;
    constexpr uint32_t pid = 70;
    constexpr uint32_t tid = 70;
    constexpr uint32_t addr = 111;
    constexpr uint64_t len = 1000;
    constexpr uint64_t pgoff = 0;
    constexpr uint64_t testNum = 1;
    PerfRecordMmap2 recordIn {true, pid, tid, addr, len, pgoff,
                              testNum, testNum, testNum, testNum, testNum, "testdatammap2"};
    SubCommandRecord cmd;
    cmd.rootPids_.insert(devhostPid);
    cmd.offset_ = cmd.GetOffsetNum();
    cmd.UpdateDevHostMaps(recordIn);
    EXPECT_EQ(recordIn.data_.addr, addr);
}

HWTEST_F(SubCommandRecordTest, CheckRecordDefaultPath, TestSize.Level1)
{
    SubCommandRecord cmd;
    string defaultName = "/data/local/tmp/perf.data";
    EXPECT_EQ(cmd.outputFilename_, defaultName);
}

/**
 * @tc.name: HandleReply_Success_OK
 */
HWTEST_F(SubCommandRecordTest, HandleReply_Success_OK, TestSize.Level1)
{
    SubCommandRecord cmd;
    cmd.restart_ = false;

    bool recvSuccess = true;
    std::string reply = "OK";
    bool isSuccess = false;
    bool shouldPrintReply = false;

    bool result = cmd.HandleReply(recvSuccess, reply, isSuccess, shouldPrintReply);

    EXPECT_TRUE(result);
    EXPECT_TRUE(isSuccess);
    EXPECT_FALSE(shouldPrintReply);
}

/**
 * @tc.name: HandleReply_Success_NotRunning
 */
HWTEST_F(SubCommandRecordTest, HandleReply_Success_NotRunning, TestSize.Level1)
{
    SubCommandRecord cmd;

    bool recvSuccess = true;
    std::string reply = "app not running";
    bool isSuccess = false;
    bool shouldPrintReply = true;

    bool result = cmd.HandleReply(recvSuccess, reply, isSuccess, shouldPrintReply);

    EXPECT_FALSE(result);
    EXPECT_FALSE(isSuccess);
    EXPECT_FALSE(shouldPrintReply);
}

/**
 * @tc.name: HandleReply_Success_CallStop
 */
HWTEST_F(SubCommandRecordTest, HandleReply_Success_CallStop, TestSize.Level1)
{
    SubCommandRecord cmd;

    bool recvSuccess = true;
    std::string reply = "called stop\n";
    bool isSuccess = false;
    bool shouldPrintReply = true;

    bool result = cmd.HandleReply(recvSuccess, reply, isSuccess, shouldPrintReply);

    EXPECT_FALSE(result);
    EXPECT_FALSE(isSuccess);
    EXPECT_FALSE(shouldPrintReply);
}

/**
 * @tc.name: HandleReply_Fail_WithFAIL
 */
HWTEST_F(SubCommandRecordTest, HandleReply_Fail_WithFAIL, TestSize.Level1)
{
    SubCommandRecord cmd;

    bool recvSuccess = true;
    std::string reply = "Operation FAIL";
    bool isSuccess = false;
    bool shouldPrintReply = false;

    bool result = cmd.HandleReply(recvSuccess, reply, isSuccess, shouldPrintReply);

    EXPECT_TRUE(result);
    EXPECT_FALSE(isSuccess);
    EXPECT_FALSE(shouldPrintReply);
}

/**
 * @tc.name: HandleFinalResult_Success_Case
 */
HWTEST_F(SubCommandRecordTest, HandleFinalResult_Success_Case, TestSize.Level1)
{
    SubCommandRecord cmd;
    pid_t testPid = getpid();
    bool isSuccess = true;
    bool shouldPrintReply = false;
    bool result = cmd.HandleFinalResult(isSuccess, testPid, shouldPrintReply);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: HandleArmSpeEvent
 * @tc.desc: Test HandleArmSpeEvent
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, HandleArmSpeEvent, TestSize.Level2)
{
    SubCommandRecord command;
    command.selectEvents_ = {};
    EXPECT_EQ(command.HandleArmSpeEvent(), true);
    command.selectEvents_ = {"arm_spe_1"};
    EXPECT_EQ(command.HandleArmSpeEvent(), true);
    command.selectEvents_ = {"arm_spe_0"};
    EXPECT_EQ(command.HandleArmSpeEvent(), true);
}

/**
 * @tc.name: AddEventsAndHandleOffCpu
 * @tc.desc: Test AddEventsAndHandleOffCpu
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, TestAddEventsAndHandleOffCpuSuccess, TestSize.Level2)
{
    SubCommandRecord recordCmd;
    recordCmd.selectEvents_ = {"hw-cpu-cycles"};
    recordCmd.selectGroups_ = {{"hw-instructions", "hw-cache-misses"}};
    recordCmd.offCPU_ = false;
    EXPECT_TRUE(recordCmd.AddEventsAndHandleOffCpu());
}

HWTEST_F(SubCommandRecordTest, TestAddEventsFail, TestSize.Level2)
{
    SubCommandRecord recordCmd;
    recordCmd.selectEvents_ = {"invalid-event"};
    recordCmd.selectGroups_ = {};
    recordCmd.offCPU_ = false;
    EXPECT_FALSE(recordCmd.AddEventsAndHandleOffCpu());
}

/**
 * @tc.name: ProcessUserSymbols
 * @tc.desc: Test ProcessUserSymbols
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, ProcessUserSymbols, TestSize.Level2)
{
    SubCommandRecord recordCmd;
    recordCmd.dedupStack_ = true;
    recordCmd.fileWriter_ = std::make_unique<PerfFileWriter>();
    bool result = recordCmd.ProcessUserSymbols();
    EXPECT_TRUE(result);
}

HWTEST_F(SubCommandRecordTest, UseJsvm, TestSize.Level2)
{
    SubCommandRecord cmd;
    cmd.ParseCallStackOption({"dwarf"});
    EXPECT_TRUE(SymbolsFile::needJsvm_);
}
/**
 * @tc.name: SetSelectGroups
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandRecordTest, SetSelectGroups, TestSize.Level2)
{
    EXPECT_EQ(CheckTraceCommandOutput("hiperf record -d 2 -a -g hw-cpu-cycles,hw-instructions --dumpoptions",
        {"hw-cpu-cycles,hw-instructions"}), true);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
