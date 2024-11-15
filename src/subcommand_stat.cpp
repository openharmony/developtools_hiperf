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
#include "hiperf_hilog.h"
#include "utilities.h"

const uint16_t ONE_HUNDRED = 100;
const uint16_t THOUSNADS_SEPARATOR = 3;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
static std::map<pid_t, ThreadInfos> thread_map_;
static bool g_reportCpuFlag = false;
static bool g_reportThreadFlag = false;
static VirtualRuntime g_runtimeInstance;
void SubCommandStat::DumpOptions() const
{
    printf("DumpOptions:\n");
    printf(" targetSystemWide:\t%s\n", targetSystemWide_ ? "true" : "false");
    printf(" selectCpus:\t%s\n", VectorToString(selectCpus_).c_str());
    printf(" timeStopSec:\t%f sec\n", timeStopSec_);
    printf(" timeReportMs:\t%d ms\n", timeReportMs_);
    printf(" selectEvents:\t%s\n", VectorToString(selectEvents_).c_str());
    printf(" selectGroups:\t%s\n", VectorToString(selectGroups_).c_str());
    printf(" noCreateNew:\t%s\n", noCreateNew_ ? "true" : "false");
    printf(" appPackage:\t%s\n", appPackage_.c_str());
    printf(" checkAppMs_:\t%d\n", checkAppMs_);
    printf(" selectPids:\t%s\n", VectorToString(selectPids_).c_str());
    printf(" selectTids:\t%s\n", VectorToString(selectTids_).c_str());
    printf(" restart:\t%s\n", restart_ ? "true" : "false");
    printf(" perCore:\t%s\n", perCpus_ ? "true" : "false");
    printf(" perTread:\t%s\n", perThreads_ ? "true" : "false");
    printf(" verbose:\t%s\n", verboseReport_ ? "true" : "false");
}

bool SubCommandStat::ParseOption(std::vector<std::string> &args)
{
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
    if (targetSystemWide_ && !IsSupportNonDebuggableApp()) {
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
    if (!Option::GetOptionValue(args, "--app", appPackage_)) {
        HLOGD("get option --app failed");
        return false;
    }
    std::string err = "";
    if (!IsExistDebugByApp(appPackage_, err)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "--chkms", checkAppMs_)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "-p", selectPids_)) {
        HLOGD("get option -p failed");
        return false;
    }
    if (!IsExistDebugByPid(selectPids_, err)) {
        return false;
    }
    if (!Option::GetOptionValue(args, "-t", selectTids_)) {
        HLOGD("get option -t failed");
        return false;
    }
    if (!Option::GetOptionValue(args, "--restart", restart_)) {
        HLOGD("get option --restart failed");
        return false;
    }
    if (!Option::GetOptionValue(args, "--per-core", perCpus_)) {
        HLOGD("get option --per-core failed");
        return false;
    }
    if (!Option::GetOptionValue(args, "--per-thread", perThreads_)) {
        HLOGD("get option --per-thread failed");
        return false;
    }
    if (!Option::GetOptionValue(args, "--verbose", verboseReport_)) {
        HLOGD("get option --verbose failed");
        return false;
    }
    return ParseSpecialOption(args);
}

bool SubCommandStat::ParseSpecialOption(std::vector<std::string> &args)
{
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

void SubCommandStat::SetReportFlags(bool cpuFlag, bool threadFlag)
{
    g_reportCpuFlag = cpuFlag;
    g_reportThreadFlag = threadFlag;
}

void SubCommandStat::Report(const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &countEvents)
{
    bool isNeedPerCpuTid = false;
    for (auto it = countEvents.begin(); it != countEvents.end(); ++it) {
        if (!(it->second->summaries.empty())) {
            isNeedPerCpuTid = true;
            break;
        }
    }
    if (isNeedPerCpuTid) {
        PrintPerHead();
        ReportDetailInfos(countEvents);
    } else {
        ReportNormal(countEvents);
    }
}

void SubCommandStat::PrintPerHead()
{
    // print head
    if (g_reportCpuFlag && g_reportThreadFlag) {
        printf(" %24s  %-30s | %-30s %10s %10s %10s | %-32s | %s\n", "count", "event_name", "thread_name",
               "pid", "tid", "coreid", "comment", "coverage");
        return;
    }
    if (g_reportCpuFlag) {
        printf(" %24s  %-30s | %10s | %-32s | %s\n", "count", "event_name", "coreid", "comment", "coverage");
        return;
    }
    printf(" %24s  %-30s | %-30s %10s %10s | %-32s | %s\n", "count", "event_name", "thread_name", "pid", "tid",
           "comment", "coverage");
    return;
}

void SubCommandStat::PrintPerValue(const std::unique_ptr<PerfEvents::ReportSum> &reportSum, const float &ratio,
                                   std::string &configName)
{
    if (reportSum == nullptr) {
        return;
    }
    // print value
    std::string strEventCount = std::to_string(reportSum->eventCountSum);
    for (size_t i = strEventCount.size() >= 1 ? strEventCount.size() - 1 : 0, j = 1; i > 0; --i, ++j) {
        if (j == THOUSNADS_SEPARATOR) {
            j = 0;
            strEventCount.insert(strEventCount.begin() + i, ',');
        }
    }

    std::string commentStr;
    MakeComments(reportSum, commentStr);

    if (g_reportCpuFlag && g_reportThreadFlag) {
        printf(" %24s  %-30s | %-30s %10d %10d %10d | %-32s | (%.0lf%%)\n", strEventCount.c_str(), configName.c_str(),
               reportSum->threadName.c_str(), reportSum->pid, reportSum->tid, reportSum->cpu, commentStr.c_str(),
               reportSum->scaleSum * ratio);
    } else if (g_reportCpuFlag) {
        printf(" %24s  %-30s | %10d | %-32s | (%.0lf%%)\n", strEventCount.c_str(), configName.c_str(),
               reportSum->cpu, commentStr.c_str(), reportSum->scaleSum * ratio);
    } else {
        printf(" %24s  %-30s | %-30s %10d %10d | %-32s | (%.0lf%%)\n", strEventCount.c_str(), configName.c_str(),
               reportSum->threadName.c_str(), reportSum->pid, reportSum->tid, commentStr.c_str(),
               reportSum->scaleSum * ratio);
    }
    fflush(stdout);
}

void SubCommandStat::InitPerMap(const std::unique_ptr<PerfEvents::ReportSum> &newPerMap,
                                const PerfEvents::Summary &summary, VirtualRuntime& virtualInstance)
{
    CHECK_TRUE(newPerMap == nullptr, NO_RETVAL, 0, "");
    newPerMap->cpu = summary.cpu;
    if (g_reportCpuFlag && !g_reportThreadFlag) {
        return;
    }
    newPerMap->tid = summary.tid;
    newPerMap->pid = thread_map_.find(summary.tid)->second.pid;
    bool isTid = true;
    if (newPerMap->pid == newPerMap->tid) {
        isTid = false;
    }
    newPerMap->threadName = virtualInstance.ReadThreadName(summary.tid, isTid);
}

void SubCommandStat::GetPerKey(std::string &perKey, const PerfEvents::Summary &summary)
{
    perKey = "";
    if (g_reportCpuFlag) {
        perKey += std::to_string(summary.cpu);
        perKey += "|";
    }
    if (g_reportThreadFlag) {
        perKey += std::to_string(summary.tid);
    }
    return;
}

void SubCommandStat::ReportDetailInfos(
    const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &countEvents)
{
    std::string perKey = "";
    std::map<std::string, std::unique_ptr<PerfEvents::ReportSum>> perMaps;
    for (auto event = countEvents.begin(); event != countEvents.end(); ++event) {
        if (event->second == nullptr || event->second->eventCount == 0) {
            continue;
        }
        constexpr float ratio {100.0};
        std::string configName = event->first;
        perMaps.clear();
        for (auto &it : event->second->summaries) {
            GetPerKey(perKey, it);
            if (perMaps.count(perKey) == 0) {
                auto perMap = std::make_unique<PerfEvents::ReportSum>(PerfEvents::ReportSum {});
                InitPerMap(perMap, it, g_runtimeInstance);
                perMaps[perKey] = std::move(perMap);
            }
            if (perMaps[perKey] == nullptr) {
                continue;
            }
            perMaps[perKey]->configName = GetDetailComments(event->second, perMaps[perKey]->commentSum,
                                                            it, configName);
            perMaps[perKey]->eventCountSum += it.eventCount;
            if (it.timeRunning < it.timeEnabled && it.timeRunning != 0) {
                perMaps[perKey]->scaleSum = 1 / (static_cast<double>(it.timeEnabled) / it.timeRunning);
            }
        }
        for (auto iper = perMaps.begin(); iper != perMaps.end(); iper++) {
            PrintPerValue(iper->second, ratio, configName);
        }
    }
}

void SubCommandStat::ReportNormal(
    const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &countEvents)
{
    // print head
    printf(" %24s  %-30s | %-32s | %s\n", "count", "name", "comment", "coverage");
    std::map<std::string, std::string> comments;
    GetComments(countEvents, comments);
    for (auto it = countEvents.begin(); it != countEvents.end(); ++it) {
        double scale = 1.0;
        constexpr float ratio {100.0};
        std::string configName = it->first;
        std::string comment = comments[configName];
        std::string strEventCount = std::to_string(it->second->eventCount);
        for (size_t i = strEventCount.size() >= 1 ? strEventCount.size() - 1 : 0, j = 1; i > 0; --i, ++j) {
            if (j == THOUSNADS_SEPARATOR) {
                strEventCount.insert(strEventCount.begin() + i, ',');
                j = 0;
            }
        }
        if (it->second->timeRunning < it->second->timeEnabled && it->second->timeRunning != 0) {
            scale = 1 / (static_cast<double>(it->second->timeEnabled) / it->second->timeRunning);
        }
        printf(" %24s  %-30s | %-32s | (%.0lf%%)\n", strEventCount.c_str(), configName.c_str(),
               comment.c_str(), scale * ratio);

        fflush(stdout);
    }
}

bool SubCommandStat::FindEventCount(const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &countEvents,
    const std::string &configName, const __u64 group_id, __u64 &eventCount, double &scale)
{
    auto itr = countEvents.find(configName);
    if (itr != countEvents.end()) {
        eventCount = itr->second->eventCount;
        if (itr->second->id == group_id
            && itr->second->timeRunning < itr->second->timeEnabled
            && itr->second->timeRunning != 0) {
            scale = static_cast<double>(itr->second->timeEnabled) / itr->second->timeRunning;
            return true;
        }
    }
    return false;
}

bool SubCommandStat::FindPerCoreEventCount(PerfEvents::Summary &summary, __u64 &eventCount, double &scale)
{
    eventCount = summary.eventCount;
    if (summary.timeRunning < summary.timeEnabled && summary.timeRunning != 0) {
        scale = static_cast<double>(summary.timeEnabled) / summary.timeRunning;
        return true;
    }
    return false;
}

std::string SubCommandStat::GetCommentConfigName(
    const std::unique_ptr<PerfEvents::CountEvent> &countEvent, std::string eventName)
{
    std::string commentConfigName = "";
    CHECK_TRUE(countEvent == nullptr || eventName.length() == 0, commentConfigName, 1, "countEvent is nullptr");
    if (countEvent->userOnly) {
        commentConfigName = eventName + ":u";
    } else if (countEvent->kernelOnly) {
        commentConfigName = eventName + ":k";
    } else {
        commentConfigName = eventName;
    }
    return commentConfigName;
}

void SubCommandStat::MakeComments(const std::unique_ptr<PerfEvents::ReportSum> &reportSum, std::string &commentStr)
{
    CHECK_TRUE(reportSum == nullptr || reportSum->commentSum == 0, NO_RETVAL, 0, "");
    if (reportSum->configName == "sw-task-clock") {
        commentStr = StringPrintf("%lf cpus used", reportSum->commentSum);
        return;
    }
    if (reportSum->configName == "hw-cpu-cycles") {
        commentStr = StringPrintf("%lf GHz", reportSum->commentSum);
        return;
    }
    if (reportSum->configName == "hw-instructions") {
        commentStr = StringPrintf("%lf cycles per instruction", reportSum->commentSum);
        return;
    }
    if (reportSum->configName == "hw-branch-misses") {
        commentStr = StringPrintf("%lf miss rate", reportSum->commentSum);
        return;
    }

    if (reportSum->commentSum > 1e9) {
        commentStr = StringPrintf("%.3lf G/sec", reportSum->commentSum / 1e9);
        return;
    }
    if (reportSum->commentSum > 1e6) {
        commentStr = StringPrintf("%.3lf M/sec", reportSum->commentSum / 1e6);
        return;
    }
    if (reportSum->commentSum > 1e3) {
        commentStr = StringPrintf("%.3lf K/sec", reportSum->commentSum / 1e3);
        return;
    }
    commentStr = StringPrintf("%.3lf /sec", reportSum->commentSum);
}

std::string SubCommandStat::GetDetailComments(const std::unique_ptr<PerfEvents::CountEvent> &countEvent,
    double &comment, PerfEvents::Summary &summary, std::string &configName)
{
    double running_time_in_sec = 0;
    double main_scale = 1.0;
    bool findRunningTime = FindPercoreRunningTime(summary, running_time_in_sec, main_scale);
    if (configName == GetCommentConfigName(countEvent, "sw-cpu-clock")) {
        comment = 0;
        return "sw-cpu-clock";
    }
    double scale = 1.0;
    if (summary.timeRunning < summary.timeEnabled && summary.timeRunning != 0) {
        scale = static_cast<double>(summary.timeEnabled) / summary.timeRunning;
    }
    if (configName == GetCommentConfigName(countEvent, "sw-task-clock")) {
        comment += countEvent->usedCpus * scale;
        return "sw-task-clock";
    }
    if (configName == GetCommentConfigName(countEvent, "hw-cpu-cycles")) {
        if (findRunningTime) {
            double hz = 0;
            if (abs(running_time_in_sec) > ALMOST_ZERO) {
                hz = summary.eventCount / (running_time_in_sec / scale);
            }
            comment += hz / 1e9;
        } else {
            comment += 0;
        }
        return "hw-cpu-cycles";
    }
    if (configName == GetCommentConfigName(countEvent, "hw-instructions") && summary.eventCount != 0) {
        double otherScale = 1.0;
        __u64 cpuCyclesCount = 0;
        bool other = FindPerCoreEventCount(summary, cpuCyclesCount, otherScale);
        if (other || (IsMonitoredAtAllTime(otherScale) && IsMonitoredAtAllTime(scale))) {
            comment += static_cast<double>(cpuCyclesCount) / summary.eventCount;
            return "hw-instructions";
        }
    }
    if (configName == GetCommentConfigName(countEvent, "hw-branch-misses")) {
        double otherScale = 1.0;
        __u64 branchInstructionsCount = 0;
        bool other = FindPerCoreEventCount(summary, branchInstructionsCount, otherScale);
        if ((other || (IsMonitoredAtAllTime(otherScale) && IsMonitoredAtAllTime(scale))) &&
            branchInstructionsCount != 0) {
            comment += (static_cast<double>(summary.eventCount) / branchInstructionsCount) * ONE_HUNDRED;
            return "hw-branch-misses";
        }
    }
    return HandleOtherConfig(comment, summary, running_time_in_sec, scale, findRunningTime);
}

std::string SubCommandStat::HandleOtherConfig(double &comment, PerfEvents::Summary &summary, double running_time_in_sec,
                                              double scale, bool findRunningTime)
{
    comment = 0;
    if (findRunningTime) {
        double rate = 0;
        if (scale != 0) {
            rate = summary.eventCount / (running_time_in_sec / scale);
        }
        comment += rate;
    }
    return "";
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
        if (it->second->timeRunning < it->second->timeEnabled && it->second->timeRunning != 0) {
            scale = static_cast<double>(it->second->timeEnabled) / it->second->timeRunning;
        }
        commentConfigName = GetCommentConfigName(it->second, "sw-task-clock");
        if (configName == commentConfigName) {
            double usedCpus = it->second->usedCpus * scale;
            comments[configName] = StringPrintf("%lf cpus used", usedCpus);
            continue;
        }
        commentConfigName = GetCommentConfigName(it->second, "hw-cpu-cycles");
        if (configName == commentConfigName) {
            if (findRunningTime &&
                ((group_id == it->second->id) ||
                 (IsMonitoredAtAllTime(main_scale) && IsMonitoredAtAllTime(scale)))) {
                double hz = 0;
                if (abs(running_time_in_sec) > ALMOST_ZERO) {
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
            if (it->second->timeRunning < it->second->timeEnabled &&
                it->second->timeRunning != 0) {
                main_scale =
                    static_cast<double>(it->second->timeEnabled) / it->second->timeRunning;
            }
            return true;
        }
    }
    return false;
}

bool SubCommandStat::FindPercoreRunningTime(PerfEvents::Summary &summary, double &running_time_int_sec,
                                            double &main_scale)
{
    CHECK_TRUE(summary.eventCount == 0, false, 0, "");
    running_time_int_sec = summary.eventCount / 1e9;
    if (summary.timeRunning < summary.timeEnabled && summary.timeRunning != 0) {
        main_scale = static_cast<double>(summary.timeEnabled) / summary.timeRunning;
    }
    return true;
}

bool SubCommandStat::CheckOptionPidAndApp(std::vector<pid_t> pids)
{
    if (!CheckOptionPid(pids)) {
        printf("Problems finding threads of monitor\n\n");
        printf("Usage: perf stat [<options>] [<command>]\n\n");
        printf("-p <pid>        stat events on existing process id\n");
        printf("-t <tid>        stat events on existing thread id\n");
        return false;
    }
    return true;
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

void SubCommandStat::SetPerfEvent()
{
    SetReportFlags(perCpus_, perThreads_);
    perfEvents_.SetSystemTarget(targetSystemWide_);
    perfEvents_.SetTimeOut(timeStopSec_);
    perfEvents_.SetTimeReport(timeReportMs_);
    perfEvents_.SetPerCpu(perCpus_);
    perfEvents_.SetPerThread(perThreads_);
    perfEvents_.SetVerboseReport(verboseReport_);
    perfEvents_.SetInherit(!noCreateNew_);
    perfEvents_.SetTrackedCommand(trackedCommand_);
    // set report handle
    perfEvents_.SetStatCallBack(Report);
}

bool SubCommandStat::OnSubCommand(std::vector<std::string> &args)
{
    CHECK_TRUE(HelpOption(), true, 0, "");
    if (!CheckRestartOption(appPackage_, targetSystemWide_, restart_, selectPids_)) {
        return false;
    }
    // check option
    if (!CheckSelectCpuPidOption()) {
        return false;
    }
    if (!CheckOptions(selectPids_)) {
        HLOGV("CheckOptions() failed");
        return false;
    }
    if (!CheckAppIsRunning(selectPids_, appPackage_, checkAppMs_)) {
        HLOGV("CheckAppIsRunning() failed");
        return false;
    }
    if (!CheckOptionPid(selectPids_)) {
        HLOGV("CheckOptionPid() failed");
        return false;
    }

    perfEvents_.SetCpu(selectCpus_);
    std::vector<pid_t> pids;
    for (auto selectPid : selectPids_) {
        HLOGD("[OnSubCommand] selectPid %d\n", selectPid);
        std::vector<pid_t> subTids = GetSubthreadIDs(selectPid, thread_map_);
        if (!subTids.empty()) {
            pids.insert(pids.end(), subTids.begin(), subTids.end());
        } else {
            HLOGD("[OnSubCommand] subTids empty for %d\n", selectPid);
        }
    }
    pids.insert(pids.end(), selectTids_.begin(), selectTids_.end());
    perfEvents_.SetPid(pids);
    if (!CheckOptionPidAndApp(pids)) {
        HLOGV("CheckOptionPidAndApp() failed");
        return false;
    }
    SetPerfEvent();
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
            int maxCpuid = sysconf(_SC_NPROCESSORS_CONF) - 1;
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
    if (targetSystemWide_) {
        if (!pids.empty() || !selectTids_.empty()) {
            printf("You cannot specify -a and -t/-p at the same time\n");
            return false;
        }
        if (!appPackage_.empty()) {
            printf("You cannot specify -a and --app at the same time\n");
            return false;
        }
    }
    if (!appPackage_.empty() && (!pids.empty() || !selectTids_.empty())) {
        printf("You cannot specify --app and -t/-p at the same time\n");
        return false;
    }
    if (!targetSystemWide_ && trackedCommand_.empty() && pids.empty() && appPackage_.empty()
        && selectTids_.empty()) {
        printf("You need to set the -p option or --app option.\n");
        return false;
    }
    if (targetSystemWide_ && !trackedCommand_.empty()) {
        printf("You cannot specify -a and a cmd at the same time\n");
        return false;
    }
    if (!trackedCommand_.empty()) {
        if (!pids.empty() || !selectTids_.empty()) {
            printf("You cannot specify a cmd and -t/-p at the same time\n");
            return false;
        }
        if (!appPackage_.empty()) {
            printf("You cannot specify a cmd and --app at the same time\n");
            return false;
        }
        if (!IsRoot()) {
            printf("%s options needs root privilege, please check usage\n",
                   VectorToString(trackedCommand_).c_str());
            return false;
        }
    }
    if (checkAppMs_ < MIN_CHECK_APP_MS || checkAppMs_ > MAX_CHECK_APP_MS) {
        printf("Invalid --chkms value '%d', the milliseconds should be in %d~%d \n", checkAppMs_,
               MIN_CHECK_APP_MS, MAX_CHECK_APP_MS);
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

void SubCommandStat::AddReportArgs(CommandReporter& reporter)
{
    if (targetSystemWide_) {
        reporter.targetProcess_ = "ALL";
    } else if (!appPackage_.empty()) {
        reporter.targetProcess_ = appPackage_;
    } else {
        reporter.targetProcess_ = VectorToString<pid_t>(selectPids_);
    }
}

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
