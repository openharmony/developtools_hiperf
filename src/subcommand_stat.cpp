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

#define HILOG_TAG "Stat"

#include "subcommand_stat.h"

#include <csignal>
#include <iostream>
#include <memory>

#include "debug_logger.h"
#include "utilities.h"

const uint16_t ONE_HUNDRED = 100;
const uint16_t THOUSNADS_SEPARATOR = 3;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
void SubCommandStat::DumpOptions() const
{
    HLOGV("enter");
    printf("DumpOptions:\n");
    printf(" targetSystemWide:\t%s\n", targetSystemWide_ ? "true" : "false");
    printf(" selectCpus:\t%s\n", VectorToString(selectCpus_).c_str());
    printf(" timeStopSec:\t%f sec\n", timeStopSec_);
    printf(" timeReportMs:\t%d ms\n", timeReportMs_);
    printf(" selectEvents:\t%s\n", VectorToString(selectEvents_).c_str());
    printf(" selectGroups:\t%s\n", VectorToString(selectGroups_).c_str());
    printf(" noCreateNew:\t%s\n", noCreateNew_ ? "true" : "false");
    printf(" selectPids:\t%s\n", VectorToString(selectPids_).c_str());
    printf(" selectTids:\t%s\n", VectorToString(selectTids_).c_str());
    printf(" verbose:\t%s\n", verboseReport_ ? "true" : "false");
}

bool SubCommandStat::ParseOption(std::vector<std::string> &args)
{
    HLOGV("enter");
    if (args.size() == 1 and args[0] == "-h") {
        args.clear();
        helpOption_ = true;
        PrintUsage();
        return true;
    }
    if (!Option::GetOptionValue(args, "-a", targetSystemWide_)) {
        HLOGD("get option -a failed");
        return false;
    }
    if (targetSystemWide_ && !IsRoot()) {
        HLOGD("-a option needs root privilege for system wide profiling.");
        printf("-a option needs root privilege for system wide profiling.\n");
        return false;
    }
    if (!Option::GetOptionValue(args, "-c", selectCpus_)) {
        HLOGD("get option -c failed");
        return false;
    }
    if (!Option::GetOptionValue(args, "-d", timeStopSec_)) {
        HLOGD("get option -d failed");
        return false;
    }
    if (!Option::GetOptionValue(args, "-i", timeReportMs_)) {
        HLOGD("get option -i failed");
        return false;
    }
    if (!Option::GetOptionValue(args, "-e", selectEvents_)) {
        HLOGD("get option -e failed");
        return false;
    }
    if (!Option::GetOptionValue(args, "-g", selectGroups_)) {
        HLOGD("get option -g failed");
        return false;
    }
    if (!Option::GetOptionValue(args, "--no-inherit", noCreateNew_)) {
        HLOGD("get option --no-inherit failed");
        return false;
    }
    if (!Option::GetOptionValue(args, "-p", selectPids_)) {
        HLOGD("get option -p failed");
        return false;
    }
    if (!IsExistDebugByPid(selectPids_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "-t", selectTids_)) {
        HLOGD("get option -t failed");
        return false;
    }
    if (!Option::GetOptionValue(args, "--verbose", verboseReport_)) {
        HLOGD("get option --verbose failed");
        return false;
    }
    if (!Option::GetOptionTrackedCommand(args, trackedCommand_)) {
        HLOGD("get cmd failed");
        return false;
    }
    if (!args.empty()) {
        HLOGD("redundant option(s)");
        return false;
    }
    return true;
}

void SubCommandStat::PrintUsage()
{
    printf("%s\n", Help().c_str());
}

void SubCommandStat::Report(
    const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &countEvents)
{
    // head
    printf(" %24s  %-30s | %-32s | %s\n", "count", "name", "comment", "coverage");

    std::map<std::string, std::string> comments;
    GetComments(countEvents, comments);
    for (auto it = countEvents.begin(); it != countEvents.end(); it++) {
        double scale = 1.0;
        std::string configName = it->first;
        std::string comment = comments[configName];
        constexpr float ratio {100.0};
        std::string strEventCount = std::to_string(it->second->eventCount);
        for (size_t i = strEventCount.size() - 1, j = 1; i > 0; --i, ++j) {
            if (j == THOUSNADS_SEPARATOR) {
                strEventCount.insert(strEventCount.begin() + i, ',');
                j = 0;
            }
        }
        if (it->second->time_running < it->second->time_enabled && it->second->time_running != 0) {
            scale = 1 / (static_cast<double>(it->second->time_enabled) / it->second->time_running);
        }
        printf(" %24s  %-30s | %-32s | (%.0lf%%)\n", strEventCount.c_str(), configName.c_str(),
               comment.c_str(), scale * ratio);

        fflush(stdout);
    }
}

bool SubCommandStat::FindEventCount(
    const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &countEvents,
    const std::string &configName, const __u64 group_id, __u64 &eventCount, double &scale)
{
    auto itr = countEvents.find(configName);
    if (itr != countEvents.end()) {
        eventCount = itr->second->eventCount;
        if (itr->second->id == group_id
            && itr->second->time_running < itr->second->time_enabled
            && itr->second->time_running != 0) {
            scale = static_cast<double>(itr->second->time_enabled) / itr->second->time_running;
            return true;
        }
    }
    return false;
}

std::string SubCommandStat::GetCommentConfigName(
    const std::unique_ptr<PerfEvents::CountEvent> &countEvent, std::string eventName)
{
    std::string commentConfigName = "";
    if (countEvent == nullptr || eventName.length() == 0) {
        return commentConfigName;
    }
    if (countEvent->userOnly) {
        commentConfigName = eventName + ":u";
    } else if (countEvent->kernelOnly) {
        commentConfigName = eventName + ":k";
    } else {
        commentConfigName = eventName;
    }
    return commentConfigName;
}

bool SubCommandStat::IsMonitoredAtAllTime(const double &scale)
{
    constexpr double SCALE_ERROR_LIMIT = 1e-5;
    return (fabs(scale - 1.0) < SCALE_ERROR_LIMIT);
}

void SubCommandStat::GetComments(const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &countEvents,
    std::map<std::string, std::string> &comments)
{
    double running_time_in_sec = 0;
    __u64 group_id = 0;
    double main_scale = 1.0;
    bool findRunningTime = FindRunningTime(countEvents, running_time_in_sec, group_id, main_scale);
    for (auto it = countEvents.begin(); it != countEvents.end(); it++) {
        std::string configName = it->first;
        std::string commentConfigName = GetCommentConfigName(it->second, "sw-cpu-clock");
        if (configName == commentConfigName) {
            comments[configName] = "";
            continue;
        }
        double scale = 1.0;
        if (it->second->time_running < it->second->time_enabled && it->second->time_running != 0) {
            scale = static_cast<double>(it->second->time_enabled) / it->second->time_running;
        }
        commentConfigName = GetCommentConfigName(it->second, "sw-task-clock");
        if (configName == commentConfigName) {
            double used_cpus = it->second->used_cpus * scale;
            comments[configName] = StringPrintf("%lf cpus used", used_cpus);
            continue;
        }
        commentConfigName = GetCommentConfigName(it->second, "hw-cpu-cycles");
        if (configName == commentConfigName) {
            if (findRunningTime &&
                ((group_id == it->second->id) ||
                 (IsMonitoredAtAllTime(main_scale) && IsMonitoredAtAllTime(scale)))) {
                double hz = 0;
                if (running_time_in_sec != 0) {
                    hz = it->second->eventCount / (running_time_in_sec / scale);
                }
                comments[configName] = StringPrintf("%lf GHz", hz / 1e9);
            } else {
                comments[configName] = "";
            }
            continue;
        }
        commentConfigName = GetCommentConfigName(it->second, "hw-instructions");
        if (configName == commentConfigName && it->second->eventCount != 0) {
            std::string cpuSyclesName = GetCommentConfigName(it->second, "hw-cpu-cycles");
            double otherScale = 1.0;
            __u64 cpuCyclesCount = 0;
            bool other = FindEventCount(countEvents, cpuSyclesName, it->second->id, cpuCyclesCount,
                                        otherScale);
            if (other || (IsMonitoredAtAllTime(otherScale) && IsMonitoredAtAllTime(scale))) {
                double cpi = static_cast<double>(cpuCyclesCount) / it->second->eventCount;
                comments[configName] = StringPrintf("%lf cycles per instruction", cpi);
                continue;
            }
        }
        commentConfigName = GetCommentConfigName(it->second, "hw-branch-misses");
        if (configName == commentConfigName) {
            std::string branchInsName = GetCommentConfigName(it->second, "hw-branch-instructions");
            double otherScale = 1.0;
            __u64 branchInstructionsCount = 0;
            bool other = FindEventCount(countEvents, branchInsName, it->second->id,
                                        branchInstructionsCount, otherScale);
            if ((other || (IsMonitoredAtAllTime(otherScale) && IsMonitoredAtAllTime(scale))) &&
                branchInstructionsCount != 0) {
                double miss_rate =
                    static_cast<double>(it->second->eventCount) / branchInstructionsCount;
                comments[configName] = StringPrintf("%lf miss rate", miss_rate * ONE_HUNDRED);
                continue;
            }
        }
        if (findRunningTime && ((group_id == it->second->id) || (IsMonitoredAtAllTime(main_scale) &&
                                                                 IsMonitoredAtAllTime(scale)))) {
            double rate = it->second->eventCount / (running_time_in_sec / scale);
            if (rate > 1e9) {
                comments[configName] = StringPrintf("%.3lf G/sec", rate / 1e9);
                continue;
            }
            if (rate > 1e6) {
                comments[configName] = StringPrintf("%.3lf M/sec", rate / 1e6);
                continue;
            }
            if (rate > 1e3) {
                comments[configName] = StringPrintf("%.3lf K/sec", rate / 1e3);
                continue;
            }
            comments[configName] = StringPrintf("%.3lf /sec", rate);
        } else {
            comments[configName] = "";
        }
    }
}

bool SubCommandStat::FindRunningTime(
    const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &countEvents,
    double &running_time_in_sec, __u64 &group_id, double &main_scale)
{
    for (auto it = countEvents.begin(); it != countEvents.end(); it++) {
        if ((it->first == "sw-task-clock" || it->first == "sw-task-clock:u" ||
             it->first == "sw-task-clock:k" || it->first == "sw-cpu-clock" ||
             it->first == "sw-cpu-clock:u" || it->first == "sw-cpu-clock:k") &&
            it->second->eventCount != 0u) {
            group_id = it->second->id;
            running_time_in_sec = it->second->eventCount / 1e9;
            if (it->second->time_running < it->second->time_enabled &&
                it->second->time_running != 0) {
                main_scale =
                    static_cast<double>(it->second->time_enabled) / it->second->time_running;
            }
            return true;
        }
    }
    return false;
}

bool SubCommandStat::CheckOptionPid(std::vector<pid_t> pids)
{
    if (pids.empty()) {
        return true;
    }

    for (auto pid : pids) {
        if (!IsDir("/proc/" + std::to_string(pid))) {
            printf("not exit pid %d\n", pid);
            return false;
        }
    }
    return true;
}

bool SubCommandStat::OnSubCommand(std::vector<std::string> &args)
{
    HLOGV("enter");

    if (HelpOption()) {
        return true;
    }
    // check option
    if (!CheckSelectCpuPidOption()) {
        return false;
    }

    perfEvents_.SetCpu(selectCpus_);
    std::vector<pid_t> pids;
    for (auto selectPid : selectPids_) {
        pids.push_back(selectPid);
        std::vector<pid_t> subTids = GetSubthreadIDs(selectPid);
        if (!subTids.empty()) {
            pids.insert(pids.end(), subTids.begin(), subTids.end());
        }
    }
    pids.insert(pids.end(), selectTids_.begin(), selectTids_.end());
    perfEvents_.SetPid(pids);
    if (!CheckOptions(pids)) {
        HLOGV("CheckOptions() failed");
        return false;
    }
    if (!CheckOptionPid(pids)) {
        printf("Problems finding threads of monitor\n\n");
        printf("Usage: perf stat [<options>] [<command>]\n\n");
        printf("-p <pid>        stat events on existing process id\n");
        printf("-t <tid>        stat events on existing thread id\n");
        return false;
    }
    perfEvents_.SetSystemTarget(targetSystemWide_);
    perfEvents_.SetTimeOut(timeStopSec_);
    perfEvents_.SetTimeReport(timeReportMs_);
    perfEvents_.SetVerboseReport(verboseReport_);
    perfEvents_.SetInherit(!noCreateNew_);
    perfEvents_.SetTrackedCommand(trackedCommand_);
    // set report handle
    perfEvents_.SetStatCallBack(Report);
    if (!PrepairEvents()) {
        HLOGV("PrepairEvents() failed");
        return false;
    }

    // preapare fd
    perfEvents_.PrepareTracking();

    // start tracking
    perfEvents_.StartTracking();

    return true;
}

bool RegisterSubCommandStat()
{
    HLOGV("enter");
    return SubCommand::RegisterSubCommand("stat", std::make_unique<SubCommandStat>());
}

bool SubCommandStat::PrepairEvents()
{
    if (selectEvents_.empty() && selectGroups_.empty()) {
        perfEvents_.AddDefaultEvent(PERF_TYPE_HARDWARE);
        perfEvents_.AddDefaultEvent(PERF_TYPE_SOFTWARE);
    } else {
        for (auto events : selectEvents_) {
            if (!perfEvents_.AddEvents(events)) {
                HLOGV("add events failed");
                return false;
            }
        }
        for (auto events : selectGroups_) {
            if (!perfEvents_.AddEvents(events, true)) {
                HLOGV("add groups failed");
                return false;
            }
        }
    }
    return true;
}

bool SubCommandStat::CheckSelectCpuPidOption()
{
    if (!selectCpus_.empty()) {
        // the only value is not -1
        if (!(selectCpus_.size() == 1 && selectCpus_.front() == -1)) {
            int maxCpuid = GetProcessorNum() - 1;
            for (auto cpu : selectCpus_) {
                if (cpu < 0 || cpu > maxCpuid) {
                    printf("Invalid -c value '%d', the CPU ID should be in 0~%d \n", cpu, maxCpuid);
                    return false;
                }
            }
        }
    } else {
        // the cpu default -1
        if (!targetSystemWide_) {
            selectCpus_.push_back(-1);
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

bool SubCommandStat::CheckOptions(const std::vector<pid_t> &pids)
{
    if (targetSystemWide_ && !pids.empty()) {
        printf("You cannot specify -a and -t/-p at the same time\n");
        return false;
    }
    if (!targetSystemWide_ && trackedCommand_.empty() && pids.empty()) {
        printf("You need to set the -p option.\n");
        return false;
    }
    if (targetSystemWide_ && !trackedCommand_.empty()) {
        printf("You cannot specify -a and a cmd at the same time\n");
        return false;
    }
    if (!trackedCommand_.empty() && !pids.empty()) {
        printf("You cannot specify a cmd and -t/-p at the same time\n");
        return false;
    }
    if (timeStopSec_ < 0) {
        printf("monitoring duration should be positive but %f is given\n", timeStopSec_);
        return false;
    }
    if (timeReportMs_ < 0) {
        printf("print interval should be non-negative but %d is given\n", timeReportMs_);
        return false;
    }
    return true;
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
