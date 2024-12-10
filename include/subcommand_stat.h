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
    static constexpr int DEFAULT_CHECK_APP_MS = 10;
    static constexpr int MIN_CHECK_APP_MS = 1;
    static constexpr int MAX_CHECK_APP_MS = 200;
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
        "   --app <package_name>\n"
        "         Collect profile info for an OHOS app, the app must be debuggable.\n"
        "         Record will exit if the process is not started within 10 seconds.\n"
        "   --chkms <millisec>\n"
        "         Set the interval of querying the <package_name>.\n"
        "         <millisec> is in range [1-200], default is 10.\n"
        "   --per-core\n"
        "         Print counters for each cpu core.\n"
        "   --per-thread\n"
        "         Print counters for each thread.\n"
        "   --restart\n"
        "         Collect performance counter information of application startup.\n"
        "         Record will exit if the process is not started within 30 seconds.\n"
        "   --verbose\n"
        "         Show more detailed reports.\n"
        "   --dumpoptions\n"
        "         Dump command options.\n"
                     // clang-format on
                     ),
          targetSystemWide_(false)
    {
    }

    bool OnSubCommand(std::vector<std::string> &args) override;
    bool ParseOption(std::vector<std::string> &args) override;
    bool ParseSpecialOption(std::vector<std::string> &args);
    void DumpOptions(void) const override;

    // add args for hisysevent
    void AddReportArgs(CommandReporter& reporter) override;

    static SubCommand* GetInstance();

private:
    PerfEvents perfEvents_;
    bool targetSystemWide_ {false};
    std::vector<int> selectCpus_ = {};
    float timeStopSec_ = PerfEvents::DEFAULT_TIMEOUT;
    int timeReportMs_ {0};
    std::vector<std::vector<std::string>> selectEvents_;
    std::vector<std::vector<std::string>> selectGroups_;
    bool restart_ {false};
    bool noCreateNew_ {false};
    std::string appPackage_ = {};
    int checkAppMs_ = DEFAULT_CHECK_APP_MS;
    std::vector<pid_t> selectPids_;
    std::vector<pid_t> selectTids_;
    bool perCpus_ {false};
    bool perThreads_ {false};
    bool verboseReport_ {false};
    std::vector<std::string> trackedCommand_ {};
    bool helpOption_ {false};
    bool CheckOptionPidAndApp(std::vector<pid_t> pids);
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

    static void Report(const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &countEvents);
    static void PrintPerHead();
    static void GetPerKey(std::string &perKey, const PerfEvents::Summary &summary);
    static void MakeComments(const std::unique_ptr<PerfEvents::ReportSum> &reportSum, std::string &commentStr);
    static void ReportNormal(const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &countEvents);
    static void ReportDetailInfos(const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &countEvents);
    static void PrintPerValue(const std::unique_ptr<PerfEvents::ReportSum> &reportSum, const float &ratio,
                              std::string &configName);
    static void InitPerMap(const std::unique_ptr<PerfEvents::ReportSum> &newPerMap,
                           const PerfEvents::Summary &summary, VirtualRuntime& virtualInstance);
    static bool FindPerCoreEventCount(PerfEvents::Summary &summary, __u64 &eventCount, double &scale);
    static bool FindPercoreRunningTime(PerfEvents::Summary &summary, double &running_time_in_sec, double &main_scale);
    static std::string GetDetailComments(const std::unique_ptr<PerfEvents::CountEvent> &countEvent, double &comment,
                                  PerfEvents::Summary &summary, std::string &configName);
    static std::string HandleOtherConfig(double &comment, PerfEvents::Summary &summary,
                                         double running_time_in_sec, double scale, bool findRunningTime);

    void PrintUsage();
    inline bool HelpOption()
    {
        return helpOption_;
    }
    bool PrepairEvents();
    bool CheckOptions(const std::vector<pid_t> &pids);
    bool CheckSelectCpuPidOption();
    void SetReportFlags(bool cpuFlag, bool threadFlag);
    void SetPerfEvent();

    FRIEND_TEST(SubCommandStatTest, ReportSampleAll);
    FRIEND_TEST(SubCommandStatTest, ReportSamplePid);
    FRIEND_TEST(SubCommandStatTest, ReportSampleApp);
};

bool RegisterSubCommandStat(void);
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // SUBCOMMAND_STAT_H_
