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
#ifndef SUBCOMMAND_STAT_H_
#define SUBCOMMAND_STAT_H_

#include "option.h"
#include "perf_events.h"
#include "subcommand.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
class SubCommandStat : public SubCommand {
public:
    SubCommandStat()
        : SubCommand("stat", "Collect performance counter information",
                     // clang-format off
        "Usage: hiperf stat [options] [command [command-args]]\n"
        "       Collect performance counter information of running [command].\n"
        "       The default options are: -c -1 -d 10000.0\n"
        "   -a\n"
        "         Collect system-wide information.\n"
        "         for measures all processes/threads\n"
        "         This requires CAP_PERFMON (since Linux 5.8) or\n"
        "          CAP_SYS_ADMIN capability or a\n"
        "         /proc/sys/kernel/perf_event_paranoid value of less than 1.\n"
        "   -c <cpuid>[<,cpuid>]\n"
        "         cpuid should be 0,1,2...\n"
        "         Limit the CPU that collects data.\n"
        "         0 means cpu0, 1 means cpu1 ...\n"
        "   -d <sec>\n"
        "         stop in <sec> seconds.\n"
        "         floating point number.\n"
        "         default is 10000.0\n"
        "   -i <ms>\n"
        "         print stat info every <ms>.\n"
        "   -e event1[:<u|k>][,event1[:<u|k>]]...\n"
        "         Customize the name of the event that needs to be counted.\n"
        "         The name can use the names listed in the list parameter.\n"
        "         It can also be represented by the value of 0x<hex>.\n"
        "            u - monitor user space events only\n"
        "            k - monitor kernel space events only\n"
        "   -g <event1[:<u|k>]>[,event1[:<u|k>]]...\n"
        "         The grouping function is added on the basis of the function of the -e parameter\n"
        "         PMU is required to report data in designated groups\n"
        "         limited by HW capability, too many events cannot be reported in the same sampling)\n"
        "   --no-inherit\n"
        "         Don't track new processes/threads.\n"
        "   -p <pid1>[,pid2]...\n"
        "         Limit the process id of the collection target. Conflicts with the -a option.\n"
        "   -t <tid1>[,tid2]...\n"
        "         Limit the thread id of the collection target. Conflicts with the -a option.\n"
        "   --verbose\n"
        "         Show more detailed reports.\n"
                     // clang-format on
                     ),
          targetSystemWide_(false)
    {
    }

    bool OnSubCommand(std::vector<std::string> &args) override;
    bool ParseOption(std::vector<std::string> &args) override;
    void DumpOptions(void) const override;

private:
    PerfEvents perfEvents_;
    bool targetSystemWide_ {false};
    std::vector<int> selectCpus_ = {};
    float timeStopSec_ = PerfEvents::DEFAULT_TIMEOUT;
    int timeReportMs_ {0};
    std::vector<std::vector<std::string>> selectEvents_;
    std::vector<std::vector<std::string>> selectGroups_;
    bool noCreateNew_ {false};
    std::vector<pid_t> selectPids_;
    std::vector<pid_t> selectTids_;
    bool verboseReport_ {false};
    std::vector<std::string> trackedCommand_ {};
    bool helpOption_ {false};
    bool CheckOptionPid(std::vector<pid_t> pids);
    static bool FindEventCount(
        const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &countEvents,
        const std::string &configName, const __u64 group_id, __u64 &eventcount, double &scale);
    static void GetComments(
        const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &countEvents,
        std::map<std::string, std::string> &comments);
    static bool FindRunningTime(
        const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &countEvents,
        double &running_time_in_sec, __u64 &group_id, double &main_scale);
    static bool IsMonitoredAtAllTime(const double &scale);
    static std::string GetCommentConfigName(
        const std::unique_ptr<PerfEvents::CountEvent> &countEvent, std::string eventName);

    static void Report(const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &);

    void PrintUsage();
    inline bool HelpOption()
    {
        return helpOption_;
    }
    bool PrepairEvents();
    bool CheckOptions(const std::vector<pid_t> &pids);
    bool CheckSelectCpuPidOption();
};

bool RegisterSubCommandStat(void);
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // SUBCOMMAND_STAT_H_
