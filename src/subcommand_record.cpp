/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#define HILOG_TAG "Record"

#include "subcommand_record.h"

#include <csignal>
#include <cstdlib>
#include <ctime>
#include <memory>
#include <poll.h>
#if defined(CONFIG_HAS_SYSPARA)
#include <parameters.h>
#endif
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "command.h"
#include "debug_logger.h"
#include "hiperf_client.h"
#include "ipc_utilities.h"
#if defined(is_ohos) && is_ohos
#include "hiperf_hilog.h"
#endif
#include "option.h"
#include "perf_event_record.h"
#include "perf_file_reader.h"
#include "utilities.h"
#include "subcommand_report.h"

using namespace std::chrono;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
const std::string CONTROL_CMD_PREPARE = "prepare";
const std::string CONTROL_CMD_START = "start";
const std::string CONTROL_CMD_PAUSE = "pause";
const std::string CONTROL_CMD_RESUME = "resume";
const std::string CONTROL_CMD_STOP = "stop";
const std::string CONTROL_FIFO_FILE_C2S = "/data/local/tmp/.hiperf_record_control_c2s";
const std::string CONTROL_FIFO_FILE_S2C = "/data/local/tmp/.hiperf_record_control_s2c";

const std::string PERF_CPU_TIME_MAX_PERCENT = "/proc/sys/kernel/perf_cpu_time_max_percent";
const std::string PERF_EVENT_MAX_SAMPLE_RATE = "/proc/sys/kernel/perf_event_max_sample_rate";
const std::string PERF_EVENT_MLOCK_KB = "/proc/sys/kernel/perf_event_mlock_kb";
const std::string SCHED_SWITCH = "/sys/kernel/tracing/events/sched/sched_switch/enable";
const std::string SCHED_SWITCH_DEBUG = "/sys/kernel/debug/tracing/events/sched/sched_switch/enable";
const std::string PROC_VERSION = "/proc/version";
const std::string SAVED_CMDLINES_SIZE = "/sys/kernel/tracing/saved_cmdlines_size";

// when there are many events, start record will take more time.
const std::chrono::milliseconds CONTROL_WAITREPY_TOMEOUT = 2000ms;
const std::chrono::milliseconds CONTROL_WAITREPY_TOMEOUT_CHECK = 1000ms;

constexpr uint64_t MASK_ALIGNED_8 = 7;
constexpr size_t MAX_DWARF_CALL_CHAIN = 2;
constexpr uint64_t TYPE_PERF_SAMPLE_BRANCH = PERF_SAMPLE_BRANCH_ANY | PERF_SAMPLE_BRANCH_ANY_CALL |
                                             PERF_SAMPLE_BRANCH_ANY_RETURN | PERF_SAMPLE_BRANCH_IND_JUMP |
                                             PERF_SAMPLE_BRANCH_IND_CALL | PERF_SAMPLE_BRANCH_COND |
                                             PERF_SAMPLE_BRANCH_CALL;

int GetClockId(const std::string &name)
{
    static std::map<std::string, int> mapClockid = {
        {"realtime", CLOCK_REALTIME},   {"boottime", CLOCK_BOOTTIME},
        {"monotonic", CLOCK_MONOTONIC}, {"monotonic_raw", CLOCK_MONOTONIC_RAW},
        {"clock_tai", CLOCK_TAI},
    };

    auto it = mapClockid.find(name);
    if (it == mapClockid.end()) {
        return -1;
    } else {
        return it->second;
    }
}

uint64_t GetBranchSampleType(const std::string &name)
{
    static std::map<std::string, uint64_t> mapBranchSampleType = {
        {"u", PERF_SAMPLE_BRANCH_USER},
        {"k", PERF_SAMPLE_BRANCH_KERNEL},
        {"any", PERF_SAMPLE_BRANCH_ANY},
        {"any_call", PERF_SAMPLE_BRANCH_ANY_CALL},
        {"any_ret", PERF_SAMPLE_BRANCH_ANY_RETURN},
        {"ind_call", PERF_SAMPLE_BRANCH_IND_CALL},
        {"ind_jmp", PERF_SAMPLE_BRANCH_IND_JUMP},
        {"cond", PERF_SAMPLE_BRANCH_COND},
        {"call", PERF_SAMPLE_BRANCH_CALL},
    };

    auto it = mapBranchSampleType.find(name);
    if (it == mapBranchSampleType.end()) {
        return 0;
    } else {
        return it->second;
    }
}

SubCommandRecord::~SubCommandRecord()
{
    CloseClientThread();
}

void SubCommandRecord::DumpOptions() const
{
    printf("DumpOptions:\n");
    printf(" targetSystemWide:\t%s\n", targetSystemWide_ ? "true" : "false");
    printf(" selectCpus:\t%s\n", VectorToString(selectCpus_).c_str());
    printf(" timeStopSec:\t%f sec\n", timeStopSec_);
    printf(" frequency:\t%d\n", frequency_);
    printf(" selectEvents:\t%s\n", VectorToString(selectEvents_).c_str());
    int i = 0;
    for (auto &group : selectGroups_) {
        i++;
        printf(" selectGroups:\t%2d:%s\n", i, VectorToString(group).c_str());
    }
    printf(" no_inherit:\t%s\n", noInherit_ ? "true" : "false");
    printf(" selectPids:\t%s\n", VectorToString(selectPids_).c_str());
    printf(" selectTids:\t%s\n", VectorToString(selectTids_).c_str());
    printf(" excludeTids:\t%s\n", VectorToString(excludeTids_).c_str());
    printf(" excludeThreads:\t%s\n", VectorToString(excludeThreadNames_).c_str());
    printf(" kernelCallChain:\t%s\n", kernelCallChain_ ? "true" : "false");
    printf(" callChainUserOnly_:\t%s\n", callChainUserOnly_ ? "true" : "false");
    printf(" restart:\t%s\n", restart_ ? "true" : "false");
    printf(" verbose:\t%s\n", verboseReport_ ? "true" : "false");
    printf(" excludePerf:\t%d\n", excludeHiperf_);
    printf(" cpuPercent:\t%d\n", cpuPercent_);
    printf(" offCPU_:\t%d\n", offCPU_);
    printf(" delayUnwind_:\t%d\n", delayUnwind_);
    printf(" disableUnwind_:\t%d\n", disableUnwind_);
    printf(" disableCallstackExpend_:\t%d\n", disableCallstackExpend_);
    printf(" enableDebugInfoSymbolic:\t%d\n", enableDebugInfoSymbolic_);
    printf(" symbolDir_:\t%s\n", VectorToString(symbolDir_).c_str());
    printf(" outputFilename_:\t%s\n", outputFilename_.c_str());
    printf(" appPackage_:\t%s\n", appPackage_.c_str());
    printf(" checkAppMs_:\t%d\n", checkAppMs_);
    printf(" clockId_:\t%s\n", clockId_.c_str());
    printf(" mmapPages_:\t%d\n", mmapPages_);
    printf(" dataLimit:\t%s\n", strLimit_.c_str());
    printf(" callStack:\t%s\n", VectorToString(callStackType_).c_str());
    printf(" branchSampleTypes:\t%s\n", VectorToString(vecBranchFilters_).c_str());
    printf(" trackedCommand:\t%s\n", VectorToString(trackedCommand_).c_str());
    printf(" pipe_input:\t%d\n", clientPipeInput_);
    printf(" pipe_output:\t%d\n", clientPipeOutput_);
    printf(" cmdlinesSize_:\t%d\n", cmdlinesSize_);
    printf(" report_:\t%s\n", report_ ? "true" : "false");
}

bool SubCommandRecord::GetSpeOptions()
{
    std::string speName;

    for (size_t i = 0; i < selectEvents_.size(); i++) {
        std::string optionValue = selectEvents_[i];

        std::vector<std::string> valueExpressions = StringSplit(optionValue, "/");
        if (i == 0) {
            if (valueExpressions.size() > 1) {
                speName = valueExpressions[0];
                valueExpressions.erase(valueExpressions.begin());
            } else {
                break;
            }
        }

        for (auto item: valueExpressions) {
            std::vector<std::string> expressions = StringSplit(item, "=");
            size_t itemNum = 2;
            if (expressions.size() == itemNum && IsNumeric(expressions[1])) {
                std::string name = expressions[0];
                unsigned long long num = std::stoull(expressions[1]);
                if (speOptMap_.find(name) != speOptMap_.end()) {
                    speOptMap_[name] = num;
                }
                if (num != 0) {
                    speOptions_.emplace_back(name);
                }
            }
        }
    }
    if (speName.size() > 0) {
        selectEvents_.clear();
        selectEvents_.emplace_back(speName);
    }
    return true;
}

bool SubCommandRecord::GetOptions(std::vector<std::string> &args)
{
    if (!Option::GetOptionValue(args, "-a", targetSystemWide_)) {
        return false;
    }
    if (targetSystemWide_ && !IsSupportNonDebuggableApp()) {
        HLOGD("-a option needs root privilege for system wide profiling.");
        printf("-a option needs root privilege for system wide profiling.\n");
        return false;
    }
    if (!Option::GetOptionValue(args, "--exclude-hiperf", excludeHiperf_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--control", controlCmd_)) {
        return false;
    }
    allowIpc_ = controlCmd_ != CONTROL_CMD_PREPARE;
    if (!Option::GetOptionValue(args, "-z", compressData_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--no-inherit", noInherit_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--offcpu", offCPU_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--delay-unwind", delayUnwind_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--disable-unwind", disableUnwind_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--disable-callstack-expand", disableCallstackExpend_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--enable-debuginfo-symbolic", enableDebugInfoSymbolic_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--verbose", verboseReport_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "-d", timeStopSec_)) {
        return false;
    }
    if (!GetOptionFrequencyAndPeriod(args)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--cpu-limit", cpuPercent_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "-m", mmapPages_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--symbol-dir", symbolDir_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "-o", outputFilename_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--app", appPackage_)) {
        return false;
    }
    std::string err = "";
    if (allowIpc_ && !IsExistDebugByApp(appPackage_, err)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--chkms", checkAppMs_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--clockid", clockId_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "-c", selectCpus_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "-p", selectPids_)) {
        return false;
    }
    if (allowIpc_ && !IsExistDebugByPid(selectPids_, err)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "-t", selectTids_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "-e", selectEvents_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "-g", selectGroups_)) {
        return false;
    }
    if (!GetSpeOptions()) {
        return false;
    }
    if (!Option::GetOptionValue(args, "-s", callStackType_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--kernel-callchain", kernelCallChain_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--callchain-useronly", callChainUserOnly_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--exclude-tid", excludeTids_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--exclude-thread", excludeThreadNames_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--restart", restart_)) {
        return false;
    }
    std::vector<std::string> callStackType = {};
    if (!Option::GetOptionValue(args, "--call-stack", callStackType)) {
        return false;
    }
    if (!callStackType_.empty()) {
        if (!callStackType.empty()) {
            printf("'-s %s --call-stack %s' option usage error, please check usage.\n",
                VectorToString(callStackType_).c_str(), VectorToString(callStackType).c_str());
            return false;
        }
    } else {
        callStackType_ = callStackType;
    }
    if (!Option::GetOptionValue(args, "--data-limit", strLimit_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "-j", vecBranchFilters_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--pipe_input", clientPipeInput_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--pipe_output", clientPipeOutput_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--dedup_stack", dedupStack_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--cmdline-size", cmdlinesSize_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--report", report_)) {
        return false;
    }
    if (targetSystemWide_ && dedupStack_) {
        printf("-a option is conflict with --dedup_stack.\n");
        return false;
    }
    CHECK_TRUE(!Option::GetOptionTrackedCommand(args, trackedCommand_), false, 0, "");
    CHECK_TRUE(!args.empty(), false, LOG_TYPE_PRINTF,
               "'%s' option usage error, please check usage.\n", VectorToString(args).c_str());
    return true;
}

bool SubCommandRecord::GetOptionFrequencyAndPeriod(std::vector<std::string> &args)
{
    if (Option::FindOption(args, "-f") != args.end()) {
        if (!Option::GetOptionValue(args, "-f", frequency_)) {
            return false;
        }
        if (frequency_ < MIN_SAMPLE_FREQUENCY || frequency_ > MAX_SAMPLE_FREQUENCY) {
            printf("Invalid -f value '%d', frequency should be in %d~%d \n", frequency_,
                   MIN_SAMPLE_FREQUENCY, MAX_SAMPLE_FREQUENCY);
            return false;
        }
    }
    if (Option::FindOption(args, "--period") != args.end()) {
        if (frequency_ != 0) {
            printf("option -f and --period is conflict, please check usage\n");
            return false;
        }
        if (!Option::GetOptionValue(args, "--period", period_)) {
            return false;
        }
        if (period_ <= 0) {
            printf("Invalid --period value '%d', period should be greater than 0\n", period_);
            return false;
        }
    }
    return true;
}

bool SubCommandRecord::CheckDataLimitOption()
{
    if (!strLimit_.empty()) {
        if (!ParseDataLimitOption(strLimit_)) {
            printf("Invalid --data-limit value %s\n", strLimit_.c_str());
            return false;
        }
    }
    return true;
}

bool SubCommandRecord::CheckSelectCpuPidOption()
{
    if (!selectCpus_.empty()) {
        int cpuCount = sysconf(_SC_NPROCESSORS_CONF);
        if (cpuCount == -1) {
            printf("sysconf failed.\n");
            return false;
        }
        int maxCpuid = cpuCount - 1;
        for (auto cpu : selectCpus_) {
            if (cpu < 0 || cpu > maxCpuid) {
                printf("Invalid -c value '%d', the CPU ID should be in 0~%d \n", cpu, maxCpuid);
                return false;
            }
        }
    }

    if (!selectPids_.empty()) {
        for (auto pid : selectPids_) {
            if (pid <= 0) {
                printf("Invalid -p value '%d', the pid should be larger than 0\n", pid);
                return false;
            }
        }
    }
    if (!selectTids_.empty()) {
        for (auto tid : selectTids_) {
            if (tid <= 0) {
                printf("Invalid -t value '%d', the tid should be larger than 0\n", tid);
                return false;
            }
        }
    }
    return true;
}

bool SubCommandRecord::CheckArgsRange()
{
    if (timeStopSec_ < MIN_STOP_SECONDS || timeStopSec_ > MAX_STOP_SECONDS) {
        printf("Invalid -d value '%.3f', the seconds should be in %.3f~%.3f  \n", timeStopSec_,
               MIN_STOP_SECONDS, MAX_STOP_SECONDS);
        return false;
    }
    if (cpuPercent_ < MIN_CPU_PERCENT || cpuPercent_ > MAX_CPU_PERCENT) {
        printf("Invalid --cpu-limit value '%d', CPU percent should be in %d~%d \n", cpuPercent_,
               MIN_CPU_PERCENT, MAX_CPU_PERCENT);
        return false;
    }
    if (checkAppMs_ < MIN_CHECK_APP_MS || checkAppMs_ > MAX_CHECK_APP_MS) {
        printf("Invalid --chkms value '%d', the milliseconds should be in %d~%d \n", checkAppMs_,
               MIN_CHECK_APP_MS, MAX_CHECK_APP_MS);
        return false;
    }
    if (mmapPages_ < MIN_PERF_MMAP_PAGE || mmapPages_ > MAX_PERF_MMAP_PAGE ||
        !PowerOfTwo(mmapPages_)) {
        printf("Invalid -m value '%d', value should be in %d~%d and must be a power of two \n",
               mmapPages_, MIN_PERF_MMAP_PAGE, MAX_PERF_MMAP_PAGE);
        return false;
    }
    if (cmdlinesSize_ < MIN_SAVED_CMDLINES_SIZE || cmdlinesSize_ > MAX_SAVED_CMDLINES_SIZE ||
        !PowerOfTwo(cmdlinesSize_)) {
        printf("Invalid --cmdline-size value '%d', value should be in %d~%d and must be a power of two \n",
               cmdlinesSize_, MIN_SAVED_CMDLINES_SIZE, MAX_SAVED_CMDLINES_SIZE);
        return false;
    }
    if (!clockId_.empty() && GetClockId(clockId_) == -1) {
        printf("Invalid --clockid value %s\n", clockId_.c_str());
        return false;
    }
    if (!targetSystemWide_ && excludeHiperf_) {
        printf("--exclude-hiperf must be used with -a\n");
        return false;
    }
    return true;
}

bool SubCommandRecord::CheckOptions()
{
    if (!CheckArgsRange()) {
        return false;
    }
    if (!CheckDataLimitOption()) {
        return false;
    }
    if (!ParseCallStackOption(callStackType_)) {
        return false;
    }
    if (!ParseBranchSampleType(vecBranchFilters_)) {
        return false;
    }
    if (!CheckSelectCpuPidOption()) {
        return false;
    }
    if (!ParseControlCmd(controlCmd_)) {
        return false;
    }
    if (!CheckTargetProcessOptions()) {
        return false;
    }
    if (!CheckReportOption()) {
        return false;
    }
    return true;
}

bool SubCommandRecord::ParseOption(std::vector<std::string> &args)
{
    if (!GetOptions(args)) {
        return false;
    }
    CHECK_TRUE(!args.empty(), false, LOG_TYPE_PRINTF, "unknown option %s\n", args.begin()->c_str());
    if (controlCmd_.empty()) {
        if (!CheckRestartOption(appPackage_, targetSystemWide_, restart_, selectPids_)) {
            return false;
        }
    }
    return CheckOptions();
}

bool SubCommandRecord::CheckTargetProcessOptions()
{
    bool hasTarget = false;
    if (targetSystemWide_) {
        hasTarget = true;
    }
    if (!selectPids_.empty() || !selectTids_.empty()) {
        CHECK_TRUE(hasTarget, false, LOG_TYPE_PRINTF,
                   "-p/-t %s options conflict, please check usage\n", VectorToString(selectPids_).c_str());
        hasTarget = true;
    }
    if (!trackedCommand_.empty()) {
        if (hasTarget) {
            printf("%s options conflict, please check usage\n",
                   VectorToString(trackedCommand_).c_str());
            return false;
        }
        if (!IsRoot()) {
            printf("%s options needs root privilege, please check usage\n",
                   VectorToString(trackedCommand_).c_str());
            return false;
        }
        hasTarget = true;
    }
    if (appPackage_ != "") {
        if (hasTarget) {
            printf("--app %s options conflict, please check usage\n", appPackage_.c_str());
            return false;
        }
        hasTarget = true;
    }
    if (!hasTarget && (controlCmd_.empty() || controlCmd_ == CONTROL_CMD_PREPARE)) {
        printf("please select a target process\n");
        return false;
    }
    if (controlCmd_ == CONTROL_CMD_PREPARE) {
        CHECK_TRUE(!CheckRestartOption(appPackage_, targetSystemWide_, restart_, selectPids_), false, 0, "");
    }
    return CheckTargetPids();
}

bool SubCommandRecord::CheckTargetPids()
{
    for (auto pid : selectPids_) {
        if (!IsDir("/proc/" + std::to_string(pid))) {
            printf("not exist pid %d\n", pid);
            return false;
        }
    }
    for (auto tid : selectTids_) {
        if (!IsDir("/proc/" + std::to_string(tid))) {
            printf("not exist tid %d\n", tid);
            return false;
        }
    }
    if (!CheckAppIsRunning(selectPids_, appPackage_, checkAppMs_)) {
        return false;
    }
    if (!selectPids_.empty()) {
        for (auto pid : selectPids_) {
            auto tids = GetSubthreadIDs(pid);
            if (!tids.empty()) {
                selectTids_.insert(selectTids_.end(), tids.begin(), tids.end());
                mapPids_[pid] = tids;
            }
        }
    }
    if (!SubCommand::HandleSubCommandExclude(excludeTids_, excludeThreadNames_, selectTids_)) {
        return false;
    }
    selectPids_.insert(selectPids_.end(), selectTids_.begin(), selectTids_.end());

    return true;
}

bool SubCommandRecord::CheckReportOption()
{
    if (targetSystemWide_ && report_) {
        printf("--report options conflict, please check usage\n");
        return false;
    }
    return true;
}

bool SubCommandRecord::ParseDataLimitOption(const std::string &str)
{
    uint unit = 1;
    char c = str.at(str.size() >= 1 ? str.size() - 1 : 0);
    if (c == 'K' || c == 'k') {
        unit = KILO;
    } else if (c == 'm' || c == 'M') {
        unit = KILO * KILO;
    } else if (c == 'g' || c == 'G') {
        unit = KILO * KILO * KILO;
    } else {
        return false;
    }

    std::string num = str.substr(0, str.size() >= 1 ? str.size() - 1 : 0);
    int64_t size = 0;
    try {
        size = std::stoul(num);
    } catch (...) {
        return false;
    }
    if (size <= 0) {
        return false;
    }

    dataSizeLimit_ = size * unit;

    return true;
}

bool SubCommandRecord::ParseCallStackOption(const std::vector<std::string> &callStackType)
{
    if (callStackType.empty()) {
        return true;
    } else if (callStackType[0] == "fp") {
        if (callStackType.size() != 1) {
            printf("Invalid -s value %s.\n", VectorToString(callStackType).c_str());
            return false;
        }
        isCallStackFp_ = true;
    } else if (callStackType[0] == "dwarf") {
        if (callStackType.size() > MAX_DWARF_CALL_CHAIN) {
            printf("Invalid -s value %s.\n", VectorToString(callStackType).c_str());
            return false;
        } else if (callStackType.size() == MAX_DWARF_CALL_CHAIN) {
            try {
                callStackDwarfSize_ = std::stoul(callStackType.at(1));
            } catch (...) {
                printf("Invalid -s value, dwarf stack size, '%s' is illegal.\n",
                       callStackType.at(1).c_str());
                return false;
            }
            if (callStackDwarfSize_ < MIN_SAMPLE_STACK_SIZE) {
                printf("Invalid -s value, dwarf stack size, '%s' is too small.\n",
                       callStackType.at(1).c_str());
                return false;
            }
            if (callStackDwarfSize_ > MAX_SAMPLE_STACK_SIZE) {
                printf("Invalid -s value, dwarf stack size, '%s' is bigger than max value %u.\n",
                       callStackType.at(1).c_str(), MAX_SAMPLE_STACK_SIZE);
                return false;
            }
            if ((callStackDwarfSize_ & MASK_ALIGNED_8) != 0) {
                printf("Invalid -s value, dwarf stack size, '%s' is not 8 byte aligned.\n",
                       callStackType.at(1).c_str());
                return false;
            }
        }
        isCallStackDwarf_ = true;
        SymbolsFile::needParseJsFunc_ = true; // only in record and dwarf mode need to parse
    } else {
        printf("Invalid -s value '%s'.\n", callStackType.at(0).c_str());
        return false;
    }
    return true;
}

bool SubCommandRecord::ParseBranchSampleType(const std::vector<std::string> &vecBranchSampleTypes)
{
    if (!vecBranchSampleTypes.empty()) {
        for (auto &item : vecBranchSampleTypes) {
            uint64_t type = GetBranchSampleType(item);
            if (type != 0) {
                branchSampleType_ |= type;
            } else {
                printf("Invalid -j value '%s'\n", item.c_str());
                return false;
            }
        }
        if ((branchSampleType_ & TYPE_PERF_SAMPLE_BRANCH) == 0) {
            printf("Invalid -j value, requires at least one of "
                   "any, any_call, any_ret, ind_call, ind_jmp, cond, call.\n");
            return false;
        }
    }
    return true;
}

bool SubCommandRecord::ParseControlCmd(const std::string cmd)
{
    if (cmd.empty() || cmd == CONTROL_CMD_PREPARE || cmd == CONTROL_CMD_START ||
        cmd == CONTROL_CMD_PAUSE || cmd == CONTROL_CMD_RESUME || cmd == CONTROL_CMD_STOP) {
        return true;
    }

    printf("Invalid --control %s option, command should be: prepare, start, pause, resume, stop.\n",
           cmd.c_str());
    return false;
}

bool SubCommandRecord::SetPerfLimit(const std::string& file, int value, std::function<bool (int, int)> const& cmp,
    const std::string& param)
{
    int oldValue = 0;
    CHECK_TRUE(!ReadIntFromProcFile(file, oldValue), false, LOG_TYPE_PRINTF, "read %s fail.\n", file.c_str());

    if (cmp(oldValue, value)) {
        HLOGI("cmp return true.");
        return true;
    }

    if (IsRoot()) {
        bool ret = WriteIntToProcFile(file, value);
        if (!ret) {
            printf("please set %s to %d manually if perf limit is wanted.\n", file.c_str(), value);
        }
    }

    CHECK_TRUE(!OHOS::system::SetParameter(param, std::to_string(value)), false, LOG_TYPE_PRINTF,
               "set parameter %s fail.\n", param.c_str());
    isNeedSetPerfHarden_ = true;
    return true;
}

bool SubCommandRecord::SetPerfCpuMaxPercent()
{
    auto cmp = [](int oldValue, int newValue) { return oldValue == newValue; };
    return SetPerfLimit(PERF_CPU_TIME_MAX_PERCENT, cpuPercent_, cmp, "hiviewdfx.hiperf.perf_cpu_time_max_percent");
}

bool SubCommandRecord::SetPerfMaxSampleRate()
{
    auto cmp = [](int oldValue, int newValue) { return oldValue == newValue; };
    int frequency = frequency_ != 0 ? frequency_ : PerfEvents::DEFAULT_SAMPLE_FREQUNCY;
    int maxRate = 0;
    CHECK_TRUE(!ReadIntFromProcFile(PERF_EVENT_MAX_SAMPLE_RATE, maxRate), false, LOG_TYPE_PRINTF,
               "read %s fail.\n", PERF_EVENT_MAX_SAMPLE_RATE.c_str());
    if (maxRate > frequency) {
        return true;
    }
    int newRate = frequency > static_cast<int>(PerfEvents::DEFAULT_EVENT_MAX_SAMPLE_RATE) ? frequency :
                  static_cast<int>(PerfEvents::DEFAULT_EVENT_MAX_SAMPLE_RATE);
    return SetPerfLimit(PERF_EVENT_MAX_SAMPLE_RATE, newRate, cmp,
                        "hiviewdfx.hiperf.perf_event_max_sample_rate");
}

bool SubCommandRecord::SetPerfEventMlock()
{
    auto cmp = [](int oldValue, int newValue) { return oldValue == newValue; };
    int mlock_kb = sysconf(_SC_NPROCESSORS_CONF) * (mmapPages_ + 1) * 4;
    return SetPerfLimit(PERF_EVENT_MLOCK_KB, mlock_kb, cmp, "hiviewdfx.hiperf.perf_event_mlock_kb");
}

bool SubCommandRecord::SetPerfHarden()
{
    if (!isNeedSetPerfHarden_) {
        return true;
    }

    std::string perfHarden = OHOS::system::GetParameter(PERF_DISABLE_PARAM, "1");
    if (perfHarden == "1") {
        CHECK_TRUE(!OHOS::system::SetParameter(PERF_DISABLE_PARAM, "0"), false, LOG_TYPE_PRINTF,
                   "set parameter security.perf_harden to 0 fail.");
    }

    CHECK_TRUE(!OHOS::system::SetParameter(PERF_DISABLE_PARAM, "1"), false, LOG_TYPE_PRINTF,
               "set parameter security.perf_harden to 1 fail.");
    return true;
}

bool SubCommandRecord::TraceOffCpu()
{
    // whether system support sched_switch event
    int enable = -1;
    std::string node = SCHED_SWITCH;
    const std::string nodeDebug = SCHED_SWITCH_DEBUG;
    CHECK_TRUE(!ReadIntFromProcFile(node.c_str(), enable) && !ReadIntFromProcFile(nodeDebug.c_str(), enable),
               false, LOG_TYPE_PRINTF, "Cannot trace off CPU, event sched:sched_switch is not available (%s or %s)\n",
               node.c_str(), nodeDebug.c_str());

    return true;
}

void SubCommandRecord::SetSavedCmdlinesSize()
{
    if (!ReadIntFromProcFile(SAVED_CMDLINES_SIZE, oldCmdlinesSize_)) {
        printf("Failed to read from %s.\n", SAVED_CMDLINES_SIZE.c_str());
    }
    if (!WriteIntToProcFile(SAVED_CMDLINES_SIZE, cmdlinesSize_)) {
        printf("Failed to write size:%d to %s.\n", cmdlinesSize_, SAVED_CMDLINES_SIZE.c_str());
    }
}

void SubCommandRecord::RecoverSavedCmdlinesSize()
{
    CHECK_TRUE(oldCmdlinesSize_ == 0, NO_RETVAL, 0, "");
    if (!WriteIntToProcFile(SAVED_CMDLINES_SIZE, oldCmdlinesSize_)) {
        printf("Failed to recover value of %s.\n", SAVED_CMDLINES_SIZE.c_str());
    }
}

bool SubCommandRecord::PreparePerfEvent()
{
    // we need to notify perfEvents_ sampling mode by SetRecordCallBack first
    auto processRecord = [this](PerfEventRecord& record) -> bool {
        return this->ProcessRecord(record);
    };
    perfEvents_.SetRecordCallBack(processRecord);

    if (selectEvents_.size() > 0 && selectEvents_[0] == "arm_spe_0") {
        if (!IsRoot()) {
            printf("%s options needs root privilege, please check usage\n", selectEvents_[0].c_str());
            return false;
        }
        selectEvents_.insert(selectEvents_.begin(), "sw-dummy");
        perfEvents_.isSpe_ = true;
        perfEvents_.SetConfig(speOptMap_);
        isSpe_ = true;
    }

    perfEvents_.SetCpu(selectCpus_);
    perfEvents_.SetPid(selectPids_); // Tids has insert Pids in CheckTargetProcessOptions()

    perfEvents_.SetSystemTarget(targetSystemWide_);
    perfEvents_.SetTimeOut(timeStopSec_);
    perfEvents_.SetVerboseReport(verboseReport_);
    perfEvents_.SetMmapPages(mmapPages_);
    if (isCallStackFp_) {
        perfEvents_.SetSampleStackType(PerfEvents::SampleStackType::FP);
    } else if (isCallStackDwarf_) {
        perfEvents_.SetSampleStackType(PerfEvents::SampleStackType::DWARF);
        perfEvents_.SetDwarfSampleStackSize(callStackDwarfSize_);
    }
    if (!perfEvents_.SetBranchSampleType(branchSampleType_)) {
        printf("branch sample %s is not supported\n", VectorToString(vecBranchFilters_).c_str());
        HLOGE("Fail to SetBranchSampleType %" PRIx64 "", branchSampleType_);
        return false;
    }
    if (!clockId_.empty()) {
        perfEvents_.SetClockId(GetClockId(clockId_));
    }

    if (frequency_ > 0) {
        perfEvents_.SetSampleFrequency(frequency_);
    } else if (period_ > 0) {
        perfEvents_.SetSamplePeriod(period_);
    }

    perfEvents_.SetInherit(!noInherit_);
    perfEvents_.SetTrackedCommand(trackedCommand_);

    // set default sample event
    if (selectEvents_.empty() && selectGroups_.empty()) {
        selectEvents_.push_back("hw-cpu-cycles");
    }

    CHECK_TRUE(!perfEvents_.AddEvents(selectEvents_), false, 1, "Fail to AddEvents events");
    for (auto &group : selectGroups_) {
        CHECK_TRUE(!perfEvents_.AddEvents(group, true), false, 1, "Fail to AddEvents groups");
    }
    // cpu off add after default event (we need both sched_switch and user selected events)
    if (offCPU_) {
        CHECK_TRUE(std::find(selectEvents_.begin(), selectEvents_.end(), "sched_switch") != selectEvents_.end(),
                   false, LOG_TYPE_PRINTF, "--offcpu is not supported event sched_switch\n");
        // insert a sched_switch event to trace offcpu event
        CHECK_TRUE(!perfEvents_.AddOffCpuEvent(), false, 1, "Fail to AddEOffCpuvent");
    }

    return true;
}

bool SubCommandRecord::PrepareSysKernel()
{
    SetHM();
    SetSavedCmdlinesSize();
    CHECK_TRUE(!SetPerfMaxSampleRate(), false, 1, "Fail to call SetPerfMaxSampleRate(%d)", frequency_);

    CHECK_TRUE(!SetPerfCpuMaxPercent(), false, 1, "Fail to set perf event cpu limit to %d\n", cpuPercent_);

    CHECK_TRUE(!SetPerfEventMlock(), false, 1, "Fail to set perf event mlock limit\n");

    CHECK_TRUE(!SetPerfHarden(), false, 1, "Fail to set perf event harden\n");

    CHECK_TRUE(offCPU_ && !TraceOffCpu(), false, 1, "Fail to TraceOffCpu");

    return true;
}

bool SubCommandRecord::PrepareVirtualRuntime()
{
    auto saveRecord = [this](PerfEventRecord& record) -> bool {
        return this->SaveRecord(record, false);
    };
    virtualRuntime_.SetRecordMode(saveRecord);

    // do some config for virtualRuntime_
    virtualRuntime_.SetCallStackExpend(disableCallstackExpend_ ? 0 : 1);
    // these is same for virtual runtime
    virtualRuntime_.SetDisableUnwind(disableUnwind_ || delayUnwind_);
    virtualRuntime_.EnableDebugInfoSymbolic(enableDebugInfoSymbolic_);
    if (!symbolDir_.empty()) {
        if (!virtualRuntime_.SetSymbolsPaths(symbolDir_)) {
            printf("Failed to set symbol path(%s)\n", VectorToString(symbolDir_).c_str());
            return false;
        }
    }

    // load vsdo first
    virtualRuntime_.LoadVdso();

    if (!callChainUserOnly_) {
        // prepare from kernel and ko
        virtualRuntime_.SetNeedKernelCallChain(!callChainUserOnly_);
        virtualRuntime_.UpdateKernelSpaceMaps();
        virtualRuntime_.UpdateKernelModulesSpaceMaps();
        if (isHM_) {
            virtualRuntime_.UpdateServiceSpaceMaps();
        }
    }

    if (isHM_) {
        virtualRuntime_.UpdateDevhostSpaceMaps();
    }
    if (dedupStack_) {
        virtualRuntime_.SetDedupStack();
        auto collectSymbol = [this](PerfRecordSample *sample) {
            this->CollectSymbol(std::move(sample));
        };
        virtualRuntime_.SetCollectSymbolCallBack(collectSymbol);
    }
    return true;
}

void SubCommandRecord::WriteCommEventBeforeSampling()
{
    CHECK_TRUE(restart_, NO_RETVAL, 0, "");
    for (auto it = mapPids_.begin(); it != mapPids_.end(); ++it) {
        virtualRuntime_.GetThread(it->first, it->first);
        for (auto tid : it->second) {
            virtualRuntime_.GetThread(it->first, tid);
        }
    }
    if (mapPids_.empty()) {
        if (!selectPids_.empty()) {
            for (auto pid : selectPids_) {
                virtualRuntime_.GetThread(pid, pid);
            }
        }
    }
}

bool SubCommandRecord::ClientCommandResponse(bool response)
{
    return ClientCommandResponse(response ? HiperfClient::ReplyOK : HiperfClient::ReplyFAIL);
}

bool SubCommandRecord::ClientCommandResponse(const std::string& str)
{
    size_t size = write(clientPipeOutput_, str.c_str(), str.size());
    if (size != str.size()) {
        char errInfo[ERRINFOLEN] = { 0 };
        strerror_r(errno, errInfo, ERRINFOLEN);
        HLOGD("Server:%s -> %d : %zd %d:%s", str.c_str(), clientPipeOutput_, size, errno, errInfo);
        return false;
    }
    return true;
}

bool SubCommandRecord::IsSamplingRunning()
{
    constexpr int maxWaitTrackingCount = 3000 / 100; // wait 3 second
    int waitTrackingCount = maxWaitTrackingCount;
    while (!perfEvents_.IsTrackRunning()) {
        waitTrackingCount--;
        if (waitTrackingCount <= 0) {
            return false;
        }
        constexpr uint64_t waitTrackingSleepMs = 100;
        std::this_thread::sleep_for(milliseconds(waitTrackingSleepMs));
    }
    return true;
}

void SubCommandRecord::ClientCommandHandle()
{
    using namespace HiperfClient;
    CHECK_TRUE(!IsSamplingRunning(), NO_RETVAL, 0, "");
    // tell the caller if Exist
    ClientCommandResponse(true);

    bool hasRead = true;
    while (!clientExit_) {
        if (isFifoServer_ && hasRead) {
            if (clientPipeInput_ != -1) {
                // after read(), block is disabled, the poll will be waked neven if no data
                close(clientPipeInput_);
            }
            clientPipeInput_ = open(CONTROL_FIFO_FILE_C2S.c_str(), O_RDONLY | O_NONBLOCK);
        }
        struct pollfd pollFd {
            clientPipeInput_, POLLIN, 0
        };
        int polled = poll(&pollFd, 1, CONTROL_WAITREPY_TOMEOUT.count());
        if (polled <= 0) {
            hasRead = false;
            continue;
        }
        hasRead = true;
        std::string command;
        while (true) {
            char c;
            ssize_t result = TEMP_FAILURE_RETRY(read(clientPipeInput_, &c, 1));
            if (result <= 0) {
                HLOGD("server :read from pipe file failed");
                break;
            }
            command.push_back(c);
            if (c == '\n') {
                break;
            }
        }
        HLOGD("server:new command %s", command.c_str());
        if (command == ReplyStart) {
            ClientCommandResponse(perfEvents_.EnableTracking());
        } else if (command == ReplyCheck) {
            ClientCommandResponse(!clientExit_);
        } else if (command == ReplyStop) {
            ClientCommandResponse(perfEvents_.StopTracking());
        } else if (command == ReplyPause) {
            ClientCommandResponse(perfEvents_.PauseTracking());
        } else if (command == ReplyResume) {
            ClientCommandResponse(perfEvents_.ResumeTracking());
        }
    }
}

bool SubCommandRecord::ProcessControl()
{
    if (controlCmd_.empty()) {
        return true;
    }

    if (controlCmd_ == CONTROL_CMD_PREPARE) {
        CHECK_TRUE(!CreateFifoServer(), false, 0, "");
        return true;
    }

    isFifoClient_ = true;
    bool ret = false;
    if (controlCmd_ == CONTROL_CMD_START) {
        ret = SendFifoAndWaitReply(HiperfClient::ReplyStart, CONTROL_WAITREPY_TOMEOUT);
    } else if (controlCmd_ == CONTROL_CMD_RESUME) {
        ret = SendFifoAndWaitReply(HiperfClient::ReplyResume, CONTROL_WAITREPY_TOMEOUT);
    } else if (controlCmd_ == CONTROL_CMD_PAUSE) {
        ret = SendFifoAndWaitReply(HiperfClient::ReplyPause, CONTROL_WAITREPY_TOMEOUT);
    } else if (controlCmd_ == CONTROL_CMD_STOP) {
        ret = SendFifoAndWaitReply(HiperfClient::ReplyStop, CONTROL_WAITREPY_TOMEOUT);
        if (ret) {
            // wait sampling process exit really
            static constexpr uint64_t waitCheckSleepMs = 200;
            std::this_thread::sleep_for(milliseconds(waitCheckSleepMs));
            while (SendFifoAndWaitReply(HiperfClient::ReplyCheck, CONTROL_WAITREPY_TOMEOUT_CHECK)) {
                std::this_thread::sleep_for(milliseconds(waitCheckSleepMs));
            }
            HLOGI("wait reply check end.");
        }
        remove(CONTROL_FIFO_FILE_C2S.c_str());
        remove(CONTROL_FIFO_FILE_S2C.c_str());
    }

    if (ret) {
        printf("%s sampling success.\n", controlCmd_.c_str());
    } else {
        printf("%s sampling failed.\n", controlCmd_.c_str());
    }
    return ret;
}

bool SubCommandRecord::CreateFifoServer()
{
    char errInfo[ERRINFOLEN] = { 0 };
    const mode_t fifoMode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
    if (mkfifo(CONTROL_FIFO_FILE_S2C.c_str(), fifoMode) != 0 ||
        mkfifo(CONTROL_FIFO_FILE_C2S.c_str(), fifoMode) != 0) {
        if (errno == EEXIST) {
            printf("another sampling service is running.\n");
        } else {
            remove(CONTROL_FIFO_FILE_S2C.c_str());
            remove(CONTROL_FIFO_FILE_C2S.c_str());
        }
        strerror_r(errno, errInfo, ERRINFOLEN);
        HLOGE("create fifo file failed. %d:%s", errno, errInfo);
        return false;
    }

    CheckIpcBeforeFork();
    pid_t pid = fork();
    allowIpc_ = true;

    if (pid == -1) {
        strerror_r(errno, errInfo, ERRINFOLEN);
        HLOGE("fork failed. %d:%s", errno, errInfo);
        return false;
    } else if (pid == 0) { // child process
        close(STDIN_FILENO);
        close(STDERR_FILENO);
        isFifoServer_ = true;
        clientPipeOutput_ = open(CONTROL_FIFO_FILE_S2C.c_str(), O_WRONLY);
        if (clientPipeOutput_ == -1) {
            strerror_r(errno, errInfo, ERRINFOLEN);
            HLOGE("open fifo file(%s) failed. %d:%s", CONTROL_FIFO_FILE_S2C.c_str(), errno, errInfo);
            return false;
        }
        std::string err = HandleAppInfo();
        if (!err.empty()) {
            ClientCommandResponse(err);
            return false;
        }
        nullFd_ = open("/dev/null", O_WRONLY);
        (void)dup2(nullFd_, STDOUT_FILENO); // redirect stdout to /dev/null
    } else {            // parent process
        isFifoClient_ = true;
        int fd = open(CONTROL_FIFO_FILE_S2C.c_str(), O_RDONLY | O_NONBLOCK);
        std::string reply = "";
        if (fd != -1) {
            WaitFifoReply(fd, CONTROL_WAITREPY_TOMEOUT, reply);
        }
        if (fd == -1 || reply != HiperfClient::ReplyOK) {
            if (reply != HiperfClient::ReplyOK) {
                printf("%s\n", reply.c_str());
            }
            close(fd);
            kill(pid, SIGKILL);
            remove(CONTROL_FIFO_FILE_C2S.c_str());
            remove(CONTROL_FIFO_FILE_S2C.c_str());
            strerror_r(errno, errInfo, ERRINFOLEN);
            printf("create control hiperf sampling failed. %d:%s\n", errno, errInfo);
            return false;
        }
        close(fd);
        printf("%s control hiperf sampling success.\n", restart_ ? "start" : "create");
    }
    return true;
}

bool SubCommandRecord::SendFifoAndWaitReply(const std::string &cmd, const std::chrono::milliseconds &timeOut)
{
    // need open for read first, because server maybe send reply before client wait to read
    int fdRead = open(CONTROL_FIFO_FILE_S2C.c_str(), O_RDONLY | O_NONBLOCK);
    if (fdRead == -1) {
        HLOGE("can not open fifo file(%s)", CONTROL_FIFO_FILE_S2C.c_str());
        return false;
    }
    int fdWrite = open(CONTROL_FIFO_FILE_C2S.c_str(), O_WRONLY | O_NONBLOCK);
    if (fdWrite == -1) {
        HLOGE("can not open fifo file(%s)", CONTROL_FIFO_FILE_C2S.c_str());
        close(fdRead);
        return false;
    }
    size_t size = write(fdWrite, cmd.c_str(), cmd.size());
    if (size != cmd.size()) {
        HLOGE("failed to write fifo file(%s) command(%s)", CONTROL_FIFO_FILE_C2S.c_str(),
              cmd.c_str());
        close(fdWrite);
        close(fdRead);
        return false;
    }
    close(fdWrite);

    bool ret = WaitFifoReply(fdRead, timeOut);
    close(fdRead);
    return ret;
}

bool SubCommandRecord::WaitFifoReply(int fd, const std::chrono::milliseconds &timeOut)
{
    std::string reply;
    WaitFifoReply(fd, timeOut, reply);
    return reply == HiperfClient::ReplyOK;
}

void SubCommandRecord::WaitFifoReply(int fd, const std::chrono::milliseconds &timeOut, std::string& reply)
{
    struct pollfd pollFd {
        fd, POLLIN, 0
    };
    int polled = poll(&pollFd, 1, timeOut.count());
    reply.clear();
    if (polled > 0) {
        while (true) {
            char c;
            ssize_t result = TEMP_FAILURE_RETRY(read(fd, &c, 1));
            if (result <= 0) {
                HLOGD("read from fifo file(%s) failed", CONTROL_FIFO_FILE_S2C.c_str());
                break;
            }
            reply.push_back(c);
            if (c == '\n') {
                break;
            }
        }
    } else if (polled == 0) {
        HLOGD("wait fifo file(%s) timeout", CONTROL_FIFO_FILE_S2C.c_str());
    } else {
        HLOGD("wait fifo file(%s) failed", CONTROL_FIFO_FILE_S2C.c_str());
    }
}

bool SubCommandRecord::OnSubCommand(std::vector<std::string> &args)
{
    HIPERF_HILOGI(MODULE_DEFAULT, "SubCommandRecord onSubCommand start");
    if (!ProcessControl()) {
        return false;
    } else if (isFifoClient_) {
        return true;
    }

    // prepare PerfEvents
    if (!PrepareSysKernel() || !PreparePerfEvent()) {
        return false;
    }

    // prepar some attr before CreateInitRecordFile
    CHECK_TRUE(!perfEvents_.PrepareTracking(), false, LOG_TYPE_WITH_HILOG, "Fail to prepare tracking ");
    HIPERF_HILOGI(MODULE_DEFAULT, "SubCommandRecord perfEvents prepared");

    if (!CreateInitRecordFile(delayUnwind_ ? false : compressData_)) {
        HLOGE("Fail to create record file %s", outputFilename_.c_str());
        HIPERF_HILOGE(MODULE_DEFAULT, "Fail to create record file %s", outputFilename_.c_str());
        return false;
    }

    if (!PrepareVirtualRuntime()) {
        return false;
    }

    HIPERF_HILOGI(MODULE_DEFAULT, "SubCommandRecord virtualRuntime prepared");

    // make a thread wait the other command
    if (clientPipeOutput_ != -1) {
        clientCommandHanle_ = std::thread(&SubCommandRecord::ClientCommandHandle, this);
    }

    //write comm event
    WriteCommEventBeforeSampling();
    HIPERF_HILOGI(MODULE_DEFAULT, "SubCommandRecord StartTracking");
    // start tracking
    if (isDataSizeLimitStop_) {
        // mmap record size has been larger than limit, dont start sampling.
    } else if (restart_ && controlCmd_ == CONTROL_CMD_PREPARE) {
        CHECK_TRUE(!perfEvents_.StartTracking(isFifoServer_), false, 0, "");
    } else {
        if (!perfEvents_.StartTracking((!isFifoServer_) && (clientPipeInput_ == -1))) {
            return false;
        }
    }
    HIPERF_HILOGI(MODULE_DEFAULT, "SubCommandRecord perfEvents tracking finish");

    if (isSpe_) {
        HLOGD("stop write spe record");
        fileWriter_->SetWriteRecordStat(false);
    }
    startSaveFileTimes_ = steady_clock::now();
    if (!FinishWriteRecordFile()) {
        HLOGE("Fail to finish record file %s", outputFilename_.c_str());
        HIPERF_HILOGE(MODULE_DEFAULT, "Fail to finish record file %s", outputFilename_.c_str());
        return false;
    } else if (!PostProcessRecordFile()) {
        HLOGE("Fail to post process record file");
        HIPERF_HILOGE(MODULE_DEFAULT, "Fail to post process record file");
        return false;
    }

    HIPERF_HILOGI(MODULE_DEFAULT, "SubCommandRecord final report");
    // finial report
    RecordCompleted();
    RecoverSavedCmdlinesSize();
    OnlineReportData();
    CloseClientThread();
    RemoveVdsoTmpFile();
    HIPERF_HILOGI(MODULE_DEFAULT, "SubCommandRecord finish");
    return true;
}

void SubCommandRecord::CloseClientThread()
{
    if (clientCommandHanle_.joinable()) {
        clientExit_ = true;
        HLOGI("CloseClientThread");
        if (nullFd_ != -1) {
            close(nullFd_);
        }
        clientCommandHanle_.join();
        close(clientPipeInput_);
        close(clientPipeOutput_);
        if (isFifoServer_) {
            remove(CONTROL_FIFO_FILE_C2S.c_str());
            remove(CONTROL_FIFO_FILE_S2C.c_str());
        }
    }
}

void SubCommandRecord::RemoveVdsoTmpFile()
{
    std::vector<std::string> fileName = {"/data/local/tmp/[shmm]", "/data/local/tmp/[vdso]"};
    for (auto name : fileName) {
        if (access(name.c_str(), F_OK) == 0) {
            if (remove(name.c_str()) != 0) {
                char errInfo[ERRINFOLEN] = { 0 };
                strerror_r(errno, errInfo, ERRINFOLEN);
                HLOGE("remove file %s failed,errno:%d,errinfo:%s", name.c_str(), errno, errInfo);
            }
        }
    }
}

bool SubCommandRecord::ProcessRecord(PerfEventRecord& record)
{
    CHECK_TRUE(record.GetName() == nullptr, false, 1, "record is null");
#if HIDEBUG_RECORD_NOT_PROCESS
    // some times we want to check performance
    // but we still want to see the record number
    if (record.GetType() == PERF_RECORD_SAMPLE) {
        recordSamples_++;
    } else {
        recordNoSamples_++;
    }
    return true;
#else
#ifdef HIPERF_DEBUG_TIME
    const auto startTime = steady_clock::now();
#endif
    if (excludeHiperf_) {
        static pid_t pid = getpid();
        if (record.GetPid() == pid) {
            // discard record
            return true;
        }
    }

    // May create some simulated events
    // it will call ProcessRecord before next line
#if !HIDEBUG_RECORD_NOT_PROCESS_VM
    virtualRuntime_.UpdateFromRecord(record);
#endif
#ifdef HIPERF_DEBUG_TIME
    prcessRecordTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif
    return SaveRecord(record, true);
#endif
}

bool SubCommandRecord::SaveRecord(const PerfEventRecord& record, bool ptrReleaseFlag)
{
#if HIDEBUG_RECORD_NOT_SAVE
    return true;
#endif
    if (dataSizeLimit_ > 0u) {
        if (dataSizeLimit_ <= fileWriter_->GetDataSize()) {
            CHECK_TRUE(isDataSizeLimitStop_, false, 0, "");
            printf("record size %" PRIu64 " is large than limit %" PRIu64 ". stop sampling.\n",
                fileWriter_->GetDataSize(), dataSizeLimit_);
            perfEvents_.StopTracking();
            isDataSizeLimitStop_ = true;
            return false;
        }
    }

    if (record.GetName() != nullptr) {
#ifdef HIPERF_DEBUG_TIME
        const auto saveTime = steady_clock::now();
#endif
        if (!fileWriter_->WriteRecord(record)) {
            // write file failed, need stop record
            perfEvents_.StopTracking();
            HLOGV("fail to write record %s", record.GetName());
            return false;
        }
        if (record.GetType() == PERF_RECORD_SAMPLE) {
            recordSamples_++;
        } else {
            recordNoSamples_++;
        }
        HLOGV(" write done. size=%zu name=%s", record.GetSize(), record.GetName());
#ifdef HIPERF_DEBUG_TIME
        saveRecordTimes_ += duration_cast<microseconds>(steady_clock::now() - saveTime);
#endif
        return true;
    }
    return false;
}

uint32_t SubCommandRecord::GetCountFromFile(const std::string &fileName)
{
    uint32_t ret = 0;
    std::string str = ReadFileToString(fileName);
    std::vector<std::string> subStrs = StringSplit(str);
    for (auto subStr : subStrs) {
        ret++;
        std::vector<std::string> vSubstr = StringSplit(subStr, "-");
        static const size_t BEGIN_END = 2;
        if (vSubstr.size() == BEGIN_END) {
            ret += (std::stoi(vSubstr[1]) - std::stoi(vSubstr[0]));
        }
    }
    return ret;
}

std::string SubCommandRecord::GetCpuDescFromFile()
{
    std::string str = ReadFileToString("/proc/cpuinfo");
    std::vector<std::string> subStrs = StringSplit(str, "\n");
    for (auto subStr : subStrs) {
        if (subStr.find("model name") == std::string::npos) {
            continue;
        }

        std::vector<std::string> vSubstr = StringSplit(subStr, ": ");
        static const size_t NAME_VALUE = 2;
        if (vSubstr.size() == NAME_VALUE) {
            return vSubstr[1];
        } else {
            return "";
        }
    }
    return "";
}

bool SubCommandRecord::AddCpuFeature()
{
    utsname unameBuf;
    if ((uname(&unameBuf)) != 0) {
        perror("uname() failed");
        return false;
    }

    fileWriter_->AddStringFeature(FEATURE::OSRELEASE, unameBuf.release);
    fileWriter_->AddStringFeature(FEATURE::HOSTNAME, unameBuf.nodename);
    fileWriter_->AddStringFeature(FEATURE::ARCH, unameBuf.machine);

    try {
        uint32_t cpuPresent = GetCountFromFile("/sys/devices/system/cpu/present");
        uint32_t cpuOnline = GetCountFromFile("/sys/devices/system/cpu/online");
        fileWriter_->AddNrCpusFeature(FEATURE::NRCPUS, cpuPresent - cpuOnline, cpuOnline);
    } catch (...) {
        HLOGD("get NRCPUS failed");
        return false;
    }
    std::string cpuDesc = GetCpuDescFromFile();
    if (!fileWriter_->AddStringFeature(FEATURE::CPUDESC, cpuDesc)) {
        return false;
    }

    // CPUID(vendor,family,model,stepping in /proc/cpuinfo) isn't supported on Hi3516DV300
    // CPU_TOPOLOGY(sockets,dies,threads), isn't supported on Hi3516DV300
    // NUMA_TOPOLOGY
    // HEADER_PMU_MAPPINGS(/sys/bus/event_source/devices/cpu/type) isn't supported on Hi3516DV300

    return true;
}

void SubCommandRecord::AddMemTotalFeature()
{
    std::string str = ReadFileToString("/proc/meminfo");
    std::vector<std::string> subStrs = StringSplit(str, " ");
    for (auto it = subStrs.begin(); it != subStrs.end(); it++) {
        if (it->find("MemTotal:") == std::string::npos) {
            continue;
        }

        if ((it + 1) != subStrs.end()) {
            uint64_t memTotal = std::stoul(*(it + 1));
            fileWriter_->AddU64Feature(FEATURE::TOTAL_MEM, memTotal);
        }
        break;
    }
}

void SubCommandRecord::AddEventDescFeature()
{
    fileWriter_->AddEventDescFeature(FEATURE::EVENT_DESC, perfEvents_.GetAttrWithId());
}

void SubCommandRecord::AddRecordTimeFeature()
{
    // create time
    std::time_t time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    // clang-format off
    char buf[256] = { 0 };
    ctime_r(&time, buf);
    fileWriter_->AddStringFeature(FEATURE::HIPERF_RECORD_TIME,
                                  StringReplace(buf, "\n", ""));
    // clang-format on
    return;
}

void SubCommandRecord::AddWorkloadCmdFeature()
{
    if (trackedCommand_.size() > 0) {
        fileWriter_->AddStringFeature(FEATURE::HIPERF_WORKLOAD_CMD, trackedCommand_.at(0));
    } else {
        HLOGD("no trackedCommand");
    }
}

void SubCommandRecord::AddCommandLineFeature()
{
    // cmdline may end with some no ascii code
    // so we cp it with c_str again
    std::string fullCommandline =
        ReadFileToString("/proc/self/cmdline").c_str() + Command::fullArgument;
    fileWriter_->AddStringFeature(FEATURE::CMDLINE, fullCommandline);
    HIPERF_HILOGI(MODULE_DEFAULT, "cmd : %{public}s", fullCommandline.c_str());
}

void SubCommandRecord::AddCpuOffFeature()
{
    if (offCPU_) {
        fileWriter_->AddBoolFeature(FEATURE::HIPERF_CPU_OFF);
    }
}

void SubCommandRecord::AddDevhostFeature()
{
    if (isHM_) {
        fileWriter_->AddStringFeature(FEATURE::HIPERF_HM_DEVHOST,
            StringPrintf("%d", virtualRuntime_.devhostPid_));
    }
}

bool SubCommandRecord::AddFeatureRecordFile()
{
    // VERSION
    CHECK_TRUE(!AddCpuFeature(), false, 0, "");
    AddMemTotalFeature();

    AddCommandLineFeature();

    AddEventDescFeature();

    AddRecordTimeFeature();

    AddWorkloadCmdFeature();

    AddCpuOffFeature();

    AddDevhostFeature();

    return true;
}

bool SubCommandRecord::CreateInitRecordFile(bool compressData)
{
    if (fileWriter_ == nullptr) {
        fileWriter_ = std::make_unique<PerfFileWriter>();
    }

    if (!fileWriter_->Open(outputFilename_, compressData)) {
        return false;
    }

    CHECK_TRUE(!fileWriter_->WriteAttrAndId(perfEvents_.GetAttrWithId()), false, 0, "");

    CHECK_TRUE(!AddFeatureRecordFile(), false, 0, "");

    HLOGD("create new record file %s", outputFilename_.c_str());
    return true;
}

bool SubCommandRecord::PostProcessRecordFile()
{
    if (delayUnwind_) {
        // 1. prepare file to rewrite
        std::string tempFileName = outputFilename_ + ".tmp";
        if (rename(outputFilename_.c_str(), tempFileName.c_str()) != 0) {
            HLOGE("rename failed. unabel to do delay unwind");
            perror("Fail to rename data file");
            return false;
        } else {
            HLOGD("use temp file '%s' for delay unwind", tempFileName.c_str());
        }

        // renew record file
        // release the old one
        fileWriter_.reset();
        if (!CreateInitRecordFile(compressData_)) {
            // create again
            HLOGEP("Fail to open data file %s ", outputFilename_.c_str());
            return false;
        }

        // read temp file
        auto fileReader = PerfFileReader::Instance(tempFileName);
        if (fileReader == nullptr) {
            HLOGEP("Fail to open data file %s ", tempFileName.c_str());
            return false;
        }

        // 2. read out the file and unwind
        auto record_callback = [&](PerfEventRecord& record) {
            if (record.GetName() == nullptr) {
                // return false in callback can stop the read process
                return false;
            } else if (record.GetType() == PERF_RECORD_SAMPLE) {
                HLOGM("readback record for unwind");
                virtualRuntime_.UnwindFromRecord(static_cast<PerfRecordSample&>(record));
            }
            SaveRecord(record);
            return true;
        };
        fileReader->ReadDataSection(record_callback);

        // 3. close again

        // lte FinishWriteRecordFile write matched only symbols
        delayUnwind_ = false;
        CHECK_TRUE(!FinishWriteRecordFile(), false, 1, "Fail to finish record file %s", outputFilename_.c_str());

        remove(tempFileName.c_str());
    }
    return true;
}

#if USE_COLLECT_SYMBOLIC
void SubCommandRecord::SymbolicHits()
{
    if (isHM_) {
        for (auto &processPair : kernelThreadSymbolsHits_) {
            for (auto &vaddr : processPair.second) {
                virtualRuntime_.GetSymbol(vaddr, processPair.first, processPair.first,
                                          PERF_CONTEXT_MAX);
            }
        }
    }

    for (auto &vaddr : kernelSymbolsHits_) {
        virtualRuntime_.GetSymbol(vaddr, 0, 0, PERF_CONTEXT_KERNEL);
    }

    for (auto &processPair : userSymbolsHits_) {
        for (auto &vaddr : processPair.second) {
            virtualRuntime_.GetSymbol(vaddr, processPair.first, processPair.first,
                                      PERF_CONTEXT_USER);
        }
    }
}
#endif

bool SubCommandRecord::CollectionSymbol(PerfEventRecord& record)
{
    CHECK_TRUE(record.GetName() == nullptr, false, 0, "");
    if (record.GetType() == PERF_RECORD_SAMPLE) {
        PerfRecordSample* sample = static_cast<PerfRecordSample*>(&record);
#if USE_COLLECT_SYMBOLIC
        CollectSymbol(sample);
#else
        virtualRuntime_.SymbolicRecord(*sample);
#endif
    }

    if (isSpe_ && record.GetType() == PERF_RECORD_AUXTRACE) {
        PerfRecordAuxtrace* sample = static_cast<PerfRecordAuxtrace*>(&record);
        virtualRuntime_.SymbolSpeRecord(*sample);
    }

    return true;
}

void SubCommandRecord::CollectSymbol(PerfRecordSample *sample)
{
    CHECK_TRUE(sample == nullptr, NO_RETVAL, 0, "");
    perf_callchain_context context = sample->InKernel() ? PERF_CONTEXT_KERNEL
                                                        : PERF_CONTEXT_USER;
    pid_t serverPid;
    // if no nr use ip ? remove stack nr == 0?
    if (sample->data_.nr == 0) {
        serverPid = sample->GetServerPidof(0);
        if (virtualRuntime_.IsKernelThread(serverPid)) {
            kernelThreadSymbolsHits_[serverPid].insert(sample->data_.ip);
        } else if (context == PERF_CONTEXT_KERNEL) {
            kernelSymbolsHits_.insert(sample->data_.ip);
        } else {
            userSymbolsHits_[sample->data_.pid].insert(sample->data_.ip);
        }
    } else {
        for (u64 i = 0; i < sample->data_.nr; i++) {
            if (sample->data_.ips[i] >= PERF_CONTEXT_MAX) {
                if (sample->data_.ips[i] == PERF_CONTEXT_KERNEL) {
                    context = PERF_CONTEXT_KERNEL;
                } else {
                    context = PERF_CONTEXT_USER;
                }
            } else {
                serverPid = sample->GetServerPidof(i);
                if (virtualRuntime_.IsKernelThread(serverPid)) {
                    kernelThreadSymbolsHits_[serverPid].insert(sample->data_.ips[i]);
                } else if (context == PERF_CONTEXT_KERNEL) {
                    kernelSymbolsHits_.insert(sample->data_.ips[i]);
                } else {
                    userSymbolsHits_[sample->data_.pid].insert(sample->data_.ips[i]);
                }
            }
        }
    }
}

// finish writing data file, then close file
bool SubCommandRecord::FinishWriteRecordFile()
{
#ifdef HIPERF_DEBUG_TIME
    const auto startTime = steady_clock::now();
#endif
#if !HIDEBUG_SKIP_PROCESS_SYMBOLS
    if (!delayUnwind_) {
#if !HIDEBUG_SKIP_LOAD_KERNEL_SYMBOLS
        if (!callChainUserOnly_) {
            virtualRuntime_.UpdateKernelSymbols();
            virtualRuntime_.UpdateKernelModulesSymbols();
            if (isHM_) {
                virtualRuntime_.UpdateServiceSymbols();
            }
        }
        if (isHM_) {
            virtualRuntime_.UpdateDevhostSymbols();
        }
#endif
        HLOGD("Load user symbols");
        if (dedupStack_) {
            virtualRuntime_.CollectDedupSymbol(kernelSymbolsHits_, userSymbolsHits_);
        } else {
            fileWriter_->ReadDataSection(
                [this] (PerfEventRecord& record) -> bool {
                    return this->CollectionSymbol(record);
                });
        }
#if USE_COLLECT_SYMBOLIC
        SymbolicHits();
#endif
#if HIDEBUG_SKIP_MATCH_SYMBOLS
        disableUnwind_ = true;
#endif
#if !HIDEBUG_SKIP_SAVE_SYMBOLS
        CHECK_TRUE(!fileWriter_->AddSymbolsFeature(virtualRuntime_.GetSymbolsFiles()),
                   false, 1, "Fail to AddSymbolsFeature");
#endif
    }
#endif
    CHECK_TRUE(dedupStack_ && !fileWriter_->AddUniStackTableFeature(virtualRuntime_.GetUniStackTable()), false, 0, "");
    CHECK_TRUE(!fileWriter_->Close(), false, 1, "Fail to close record file %s", outputFilename_.c_str());
#ifdef HIPERF_DEBUG_TIME
    saveFeatureTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif
    return true;
}

#ifdef HIPERF_DEBUG_TIME
void SubCommandRecord::ReportTime()
{
    printf("updateSymbolsTimes: %0.3f ms\n",
           virtualRuntime_.updateSymbolsTimes_.count() / MS_DURATION);
    printf("saveFeatureTimes: %0.3f ms\n", saveFeatureTimes_.count() / MS_DURATION);

    printf("prcessRecordTimes: %0.3f ms\n", prcessRecordTimes_.count() / MS_DURATION);
    printf("-prcessSampleRecordTimes: %0.3f ms\n",
           virtualRuntime_.processSampleRecordTimes_.count() / MS_DURATION);
    printf("--unwindFromRecordTimes: %0.3f ms\n",
           virtualRuntime_.unwindFromRecordTimes_.count() / MS_DURATION);
    printf("-prcessMmapRecordTimes: %0.3f ms\n",
           virtualRuntime_.processMmapRecordTimes_.count() / MS_DURATION);
    printf("-prcessMmap2RecordTimes: %0.3f ms\n",
           virtualRuntime_.processMmap2RecordTimes_.count() / MS_DURATION);
    printf("-prcessCommRecordTimes: %0.3f ms\n",
           virtualRuntime_.processCommRecordTimes_.count() / MS_DURATION);
    printf("-prcessMmap2RecordTimes: %0.3f ms\n",
           virtualRuntime_.processMmap2RecordTimes_.count() / MS_DURATION);
    printf("--updateThreadTimes: %0.3f ms\n",
           virtualRuntime_.updateThreadTimes_.count() / MS_DURATION);
    printf("---threadParseMapsTimes: %0.3f ms\n",
           virtualRuntime_.threadParseMapsTimes_.count() / MS_DURATION);
    printf("---threadCreateMmapTimes: %0.3f ms\n",
           virtualRuntime_.threadCreateMmapTimes_.count() / MS_DURATION);
    printf("--unwindCallStackTimes: %0.3f ms\n",
           virtualRuntime_.unwindCallStackTimes_.count() / MS_DURATION);
    printf("-symbolicRecordTimes: %0.3f ms\n",
           virtualRuntime_.symbolicRecordTimes_.count() / MS_DURATION);
    printf("saveRecordTimes: %0.3f ms\n", saveRecordTimes_.count() / MS_DURATION);
    printf("-writeTimes: %0.3f ms\n", fileWriter_->writeTimes_.count() / MS_DURATION);

    printf("logTimes: %0.3f ms\n", DebugLogger::GetInstance()->logTimes_.count() / MS_DURATION);
    printf("-logSprintfTimes: %0.3f ms\n",
           DebugLogger::GetInstance()->logSprintfTimes_.count() / MS_DURATION);
    printf("-logWriteTimes: %0.3f ms\n",
           DebugLogger::GetInstance()->logWriteTimes_.count() / MS_DURATION);
    printf("logCount: %zu (%4.2f ms/log)\n", DebugLogger::GetInstance()->logCount_,
           DebugLogger::GetInstance()->logTimes_.count() /
               static_cast<double>(DebugLogger::GetInstance()->logCount_) / MS_DURATION);
}
#endif

bool SubCommandRecord::RecordCompleted()
{
    if (verboseReport_) {
        printf("Save Record used %0.3f ms.\n",
               duration_cast<microseconds>(steady_clock::now() - startSaveFileTimes_).count() /
                   MS_DURATION);
    }
    HLOGV("Save Record used %0.3f ms.\n",
          duration_cast<microseconds>(steady_clock::now() - startSaveFileTimes_).count() /
              MS_DURATION);

    // print brief file info
    double mb = static_cast<double>(fileWriter_->GetDataSize()) / (KILO * KILO);
    if (compressData_) {
        printf("[ hiperf record: Captured and compressed %.3f MB perf data. ]\n", mb);
    } else {
        printf("[ hiperf record: Captured %.3f MB perf data. ]\n", mb);
    }
    printf("[ Sample records: %zu, Non sample records: %zu ]\n", recordSamples_, recordNoSamples_);
    // Show brief sample lost.
    size_t lostSamples = 0;
    size_t lostNonSamples = 0;
    perfEvents_.GetLostSamples(lostSamples, lostNonSamples);
    printf("[ Sample lost: %zu, Non sample lost: %zu ]\n", lostSamples, lostNonSamples);

#ifdef HIPERF_DEBUG_TIME
    ReportTime();
#endif
    return true;
}

bool SubCommandRecord::RegisterSubCommandRecord(void)
{
    return SubCommand::RegisterSubCommand("record", std::make_unique<SubCommandRecord>());
}

void SubCommandRecord::SetHM()
{
    utsname unameBuf;
    if ((uname(&unameBuf)) == 0) {
        std::string osrelease = unameBuf.release;
        isHM_ = osrelease.find(HMKERNEL) != std::string::npos;
    }
    virtualRuntime_.SetHM(isHM_);
    perfEvents_.SetHM(isHM_);
    HLOGD("Set isHM_: %d", isHM_);
    if (isHM_) {
        // find devhost pid
        const std::string basePath {"/proc/"};
        std::vector<std::string> subDirs = GetSubDirs(basePath);
        for (const auto &subDir : subDirs) {
            if (!IsDigits(subDir)) {
                continue;
            }
            pid_t pid = std::stoll(subDir);
            std::string cmdline = GetProcessName(pid);
            if (cmdline == "/bin/" + DEVHOST_FILE_NAME) {
                virtualRuntime_.SetDevhostPid(pid);
                break;
            }
        }
    }
}

bool SubCommandRecord::OnlineReportData()
{
    if (!report_) {
        return true;
    }
    HIPERF_HILOGI(MODULE_DEFAULT, "%" HILOG_PUBLIC "s begin to report file %" HILOG_PUBLIC "s",
                  __FUNCTION__, outputFilename_.c_str());
    bool ret = false;
    std::string tempFileName = outputFilename_ + ".tmp";
    if (rename(outputFilename_.c_str(), tempFileName.c_str()) != 0) {
        char errInfo[ERRINFOLEN] = { 0 };
        strerror_r(errno, errInfo, ERRINFOLEN);
        HIPERF_HILOGI(MODULE_DEFAULT, "%" HILOG_PUBLIC "s can't rename file %" HILOG_PUBLIC "s"
                      "errno:%" HILOG_PUBLIC "d , errInfo: %" HILOG_PUBLIC "s\n",
                      __FUNCTION__, outputFilename_.c_str(), errno, errInfo);
        return false;
    }

    std::unique_ptr<SubCommandReport> reporter = std::make_unique<SubCommandReport>();
    HLOGD("report the file %s to report file %s \n", tempFileName.c_str(), outputFilename_.c_str());
    std::vector<std::string> args;
    args.emplace_back("-i");
    args.emplace_back(tempFileName);
    args.emplace_back("-o");
    args.emplace_back(outputFilename_);
    args.emplace_back("-s");
    if (reporter->ParseOption(args)) {
        ret =  reporter->OnSubCommand(args);
    }

    if (remove(tempFileName.c_str()) != 0) {
        char errInfo[ERRINFOLEN] = { 0 };
        strerror_r(errno, errInfo, ERRINFOLEN);
        HIPERF_HILOGI(MODULE_DEFAULT, "%" HILOG_PUBLIC "s remove file failed %" HILOG_PUBLIC "s"
                      "errno:%" HILOG_PUBLIC "d , errInfo: %" HILOG_PUBLIC "s\n",
                      __FUNCTION__, tempFileName.c_str(), errno, errInfo);
    }
    HIPERF_HILOGI(MODULE_DEFAULT, "%" HILOG_PUBLIC "s report result %" HILOG_PUBLIC "s",
                  __FUNCTION__, ret ? "success" : "fail");
    return ret;
}

std::string SubCommandRecord::HandleAppInfo()
{
    std::string err = "";
    if (!IsExistDebugByApp(appPackage_, err)) {
        return err;
    }
    if (!IsExistDebugByPid(selectPids_, err)) {
        return err;
    }
    return err;
}

void SubCommandRecord::AddReportArgs(CommandReporter& reporter)
{
    if (targetSystemWide_) {
        reporter.targetProcess_ = "ALL";
    } else if (!appPackage_.empty()) {
        reporter.targetProcess_ = appPackage_;
    } else {
        std::unordered_set<std::string> processNames = {};
        for_each(selectPids_.begin(), selectPids_.end(), [&processNames] (const pid_t& pid) {
            processNames.insert(GetProcessName(pid));
        });
        reporter.targetProcess_ = SetToString<std::string>(processNames);
    }
}

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
