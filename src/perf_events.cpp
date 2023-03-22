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
#include "perf_events.h"

#include <cassert>
#include <cinttypes>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
#if defined(CONFIG_HAS_SYSPARA)
#include <parameters.h>
#endif

#include "debug_logger.h"
#include "register.h"
#include "subcommand_dump.h"
#include "symbols_file.h"
#include "utilities.h"

using namespace std;
using namespace std::chrono;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
static std::atomic_bool g_trackRunning = false;

OHOS::UniqueFd PerfEvents::Open(perf_event_attr &attr, pid_t pid, int cpu, int group_fd,
                                unsigned long flags)
{
    OHOS::UniqueFd fd = UniqueFd(syscall(__NR_perf_event_open, &attr, pid, cpu, group_fd, flags));
    if (fd < 0) {
        HLOGEP("syscall perf_event_open failed. ");
        // dump when open failed.
        SubCommandDump::DumpPrintEventAttr(attr, std::numeric_limits<int>::min());
    }
    HLOGV("perf_event_open: got fd %d for pid %d cpu %d group %d flags %lu", fd.Get(), pid, cpu, group_fd, flags);
    return fd;
}

PerfEvents::PerfEvents() : timeOut_(DEFAULT_TIMEOUT * THOUSANDS), timeReport_(0)
{
    pageSize_ = sysconf(_SC_PAGESIZE);
    HLOGI("BuildArch %s", GetArchName(buildArchType).c_str());
}

PerfEvents::~PerfEvents()
{
    // close mmap
    for (auto it = cpuMmap_.begin(); it != cpuMmap_.end();) {
        const MmapFd &mmapItem = it->second;
        munmap(mmapItem.mmapPage, (1 + mmapPages_) * pageSize_);
        it = cpuMmap_.erase(it);
    }

    // close file descriptor of perf_event_open() created
    for (auto eventGroupItem = eventGroupItem_.begin(); eventGroupItem != eventGroupItem_.end();) {
        for (const auto &eventItem : eventGroupItem->eventItems) {
            for (const auto &fdItem : eventItem.fdItems) {
                close(fdItem.fd);
            }
        }
        eventGroupItem = eventGroupItem_.erase(eventGroupItem);
    }

    ExitReadRecordBufThread();
}

bool PerfEvents::IsEventSupport(perf_type_id type, __u64 config)
{
    HLOGV("enter");
    unique_ptr<perf_event_attr> attr = PerfEvents::CreateDefaultAttr(type, config);
    UniqueFd fd = Open(*attr.get());
    if (fd < 0) {
        printf("event not support %s\n", GetStaticConfigName(type, config).c_str());
        return false;
    } else {
        return true;
    }
}
bool PerfEvents::IsEventAttrSupport(perf_event_attr &attr)
{
    HLOGV("enter");
    UniqueFd fd = Open(attr);
    if (fd < 0) {
        return false;
    } else {
        return true;
    }
}

bool PerfEvents::SetBranchSampleType(uint64_t value)
{
    if (value != 0) {
        // cpu-clcles event must be supported
        unique_ptr<perf_event_attr> attr =
            PerfEvents::CreateDefaultAttr(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES);
        attr->sample_type |= PERF_SAMPLE_BRANCH_STACK;
        attr->branch_sample_type = value;
        if (!IsEventAttrSupport(*attr.get())) {
            return false;
        }
    }
    branchSampleType_ = value;
    return true;
}

bool PerfEvents::AddDefaultEvent(perf_type_id type)
{
    HLOGV("enter");
    auto it = DEFAULT_TYPE_CONFIGS.find(type);
    if (it != DEFAULT_TYPE_CONFIGS.end()) {
        for (auto config : it->second) {
            AddEvent(type, config);
        }
    }
    return true;
}

bool PerfEvents::AddOffCpuEvent()
{
    std::string eventName = "sched:sched_switch";
    if (eventSpaceType_ == EventSpaceType::USER) {
        eventName += ":u";
    } else if (eventSpaceType_ == EventSpaceType::KERNEL) {
        eventName += ":k";
    }
    return AddEvent(eventName);
}

bool PerfEvents::AddEvents(const std::vector<std::string> &eventStrings, bool group)
{
    bool followGroup = false;
    HLOGV(" %s %s", VectorToString(eventStrings).c_str(), followGroup ? "followGroup" : "");

    for (std::string eventString : eventStrings) {
        if (!AddEvent(eventString, followGroup)) {
            return false;
        }
        // this is group request , Follow-up events need to follow the previous group
        if (group) {
            followGroup = true;
        }
    }
    return true;
}

// event name can have :k or :u suffix
// tracepoint event name is like sched:sched_switch
// clang-format off
bool PerfEvents::ParseEventName(const std::string &nameStr,
    std::string &name, bool &excludeUser, bool &excludeKernel, bool &isTracePoint)
// clang-format on
{
    name = nameStr;
    excludeUser = false;
    excludeKernel = false;
    isTracePoint = false;
    if (nameStr.find(":") != std::string::npos) {
        static constexpr size_t maxNumberTokensNoTracePoint = 2;
        static constexpr size_t maxNumberTokensTracePoint = 3;
        std::vector<std::string> eventTokens = StringSplit(nameStr, ":");
        if (eventTokens.size() == maxNumberTokensTracePoint) {
            // tracepoint event with :u or :k
            if (eventTokens.back() == "k") {
                excludeUser = true;
                HLOGV("kernelOnly event");
            } else if (eventTokens.back() == "u") {
                excludeKernel = true;
                HLOGV("userOnly event");
            } else {
                HLOGV("unknown event name %s", nameStr.c_str());
                return false;
            }
            name = eventTokens[0] + ":" + eventTokens[1];
            isTracePoint = true;
        } else if (eventTokens.size() == maxNumberTokensNoTracePoint) {
            name = eventTokens[0];
            if (eventTokens.back() == "k") {
                excludeUser = true;
                HLOGV("kernelOnly event");
            } else if (eventTokens.back() == "u") {
                excludeKernel = true;
                HLOGV("userOnly event");
            } else {
                name = nameStr;
                isTracePoint = true;
                HLOGV("tracepoint event is in form of xx:xxx");
            }
        } else {
            printf("unknown ':' format:'%s'\n", nameStr.c_str());
            return false;
        }
        if (reportCallBack_) {
            if ((eventTokens[0] == "sw-task-clock" || eventTokens[0] == "sw-cpu-clock") &&
                (excludeUser || excludeKernel)) {
                printf(
                    "event type %s with modifier u and modifier k is not supported by the kernel.",
                    eventTokens[0].c_str());
                return false;
            }
        }
    }
    return true;
}

bool PerfEvents::AddEvent(const std::string &eventString, bool followGroup)
{
    std::string eventName;
    bool excludeUser = false;
    bool excludeKernel = false;
    bool isTracePointEvent = false;
    if (!ParseEventName(eventString, eventName, excludeUser, excludeKernel, isTracePointEvent)) {
        return false;
    }
    if (excludeUser) {
        eventSpaceType_ |= EventSpaceType::KERNEL;
    } else if (excludeKernel) {
        eventSpaceType_ |= EventSpaceType::USER;
    } else {
        eventSpaceType_ |= EventSpaceType::USER_KERNEL;
    }

    // find if
    if (isTracePointEvent) {
        if (traceConfigTable.empty()) {
            LoadTracepointEventTypesFromSystem();
        }
        for (auto traceType : traceConfigTable) {
            if (traceType.second == eventName) {
                return AddEvent(PERF_TYPE_TRACEPOINT, traceType.first, excludeUser, excludeKernel,
                                followGroup);
            }
        }
    } else {
        for (auto type : TYPE_CONFIGS) {
            for (auto config : (type.second)) {
                if (config.second == eventName) {
                    return AddEvent(type.first, config.first, excludeUser, excludeKernel,
                                    followGroup);
                }
            }
        }
    }

    printf("%s event is not supported by the kernel.\n", eventName.c_str());
    return false;
}

bool PerfEvents::AddEvent(perf_type_id type, __u64 config, bool excludeUser, bool excludeKernel,
                          bool followGroup)
{
    HLOG_ASSERT(!excludeUser or !excludeKernel);
    if (followGroup && eventGroupItem_.empty()) {
        HLOGE("no group leader create before");
        return false;
    }
    // found the event name
    if (!IsEventSupport(type, config)) {
        return false;
    }
    HLOGV("type %d config %llu excludeUser %d excludeKernel %d followGroup %d", type, config,
          excludeUser, excludeKernel, followGroup);

    // if use follow ?
    EventGroupItem &eventGroupItem = followGroup ? eventGroupItem_.back()
                                                 : eventGroupItem_.emplace_back();
    // always new item
    EventItem &eventItem = eventGroupItem.eventItems.emplace_back();

    eventItem.typeName = GetTypeName(type);
    if (type == PERF_TYPE_TRACEPOINT) {
        eventItem.configName = GetTraceConfigName(config);
    } else {
        eventItem.configName = GetStaticConfigName(type, config);
    }

    // attr
    if (memset_s(&eventItem.attr, sizeof(perf_event_attr), 0, sizeof(perf_event_attr)) != EOK) {
        HLOGE("memset_s failed in PerfEvents::AddEvent");
        return false;
    }
    eventItem.attr.size = sizeof(perf_event_attr);
    eventItem.attr.type = type;
    eventItem.attr.config = config;
    eventItem.attr.disabled = 1;
    eventItem.attr.read_format =
        PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING | PERF_FORMAT_ID;

    eventItem.attr.inherit = (inherit_ ? 1 : 0);
    eventItem.attr.exclude_kernel = excludeKernel;
    eventItem.attr.exclude_user = excludeUser;

    // we also need mmap for record
    if (recordCallBack_) {
        if (samplePeriod_ > 0) {
            eventItem.attr.freq = 0;
            eventItem.attr.sample_freq = 0;
            eventItem.attr.sample_period = samplePeriod_;
        } else if (sampleFreq_ > 0) {
            eventItem.attr.freq = 1;
            eventItem.attr.sample_freq = sampleFreq_;
        } else {
            if (type == PERF_TYPE_TRACEPOINT) {
                eventItem.attr.freq = 0;
                eventItem.attr.sample_period = DEFAULT_SAMPLE_PERIOD;
            } else {
                eventItem.attr.freq = 1;
                eventItem.attr.sample_freq = DEFAULT_SAMPLE_FREQUNCY;
            }
        }

        eventItem.attr.watermark = 1;
        if (eventItem.attr.watermark == 1) {
            eventItem.attr.wakeup_watermark = (mmapPages_ * pageSize_) >> 1;
            static constexpr unsigned int maxWakeupMark = 1024 * 1024;
            if (eventItem.attr.wakeup_watermark > maxWakeupMark) {
                eventItem.attr.wakeup_watermark = maxWakeupMark;
            }
        }

        // for a group of events, only enable comm/mmap on the first event
        if (!followGroup) {
            eventItem.attr.comm = 1;
            eventItem.attr.mmap = 1;
            eventItem.attr.mmap2 = 1;
            eventItem.attr.mmap_data = 0;
        }

        if (sampleStackType_ == SampleStackType::DWARF) {
            eventItem.attr.sample_type = SAMPLE_TYPE | PERF_SAMPLE_CALLCHAIN |
                                         PERF_SAMPLE_STACK_USER | PERF_SAMPLE_REGS_USER;
            eventItem.attr.exclude_callchain_user = 1;
            eventItem.attr.sample_regs_user = GetSupportedRegMask(GetDeviceArch());
            eventItem.attr.sample_stack_user = dwarfSampleStackSize_;
        } else if (sampleStackType_ == SampleStackType::FP) {
            eventItem.attr.sample_type = SAMPLE_TYPE | PERF_SAMPLE_CALLCHAIN;
        } else {
            eventItem.attr.sample_type = SAMPLE_TYPE;
        }
    }

    // set clock id
    if (clockId_ != -1) {
        eventItem.attr.use_clockid = 1;
        eventItem.attr.clockid = clockId_;
    }
    if (branchSampleType_ != 0) {
        eventItem.attr.sample_type |= PERF_SAMPLE_BRANCH_STACK;
        eventItem.attr.branch_sample_type = branchSampleType_;
    }

    HLOGV("Add Event: '%s':'%s' %s %s %s", eventItem.typeName.c_str(), eventItem.configName.c_str(),
          excludeUser ? "excludeUser" : "", excludeKernel ? "excludeKernel" : "",
          followGroup ? "" : "group leader");

    return true;
}

std::unique_ptr<perf_event_attr> PerfEvents::CreateDefaultAttr(perf_type_id type, __u64 config)
{
    unique_ptr<perf_event_attr> attr = make_unique<perf_event_attr>();
    if (memset_s(attr.get(), sizeof(perf_event_attr), 0, sizeof(perf_event_attr)) != EOK) {
        HLOGE("memset_s failed in PerfEvents::CreateDefaultAttr");
        return nullptr;
    }
    attr->size = sizeof(perf_event_attr);
    attr->type = type;
    attr->config = config;
    attr->disabled = 1;
    return attr;
}

// should move to upper caller
static struct sigaction g_oldSig {
};
static bool CaptureSig()
{
    HLOGD("capture Ctrl + C to end sampling decently");
    struct sigaction sig {
    };

    sig.sa_handler = [](int sig) {
        printf("\n Ctrl + C detected.\n");
        g_trackRunning = false;
    };

    sig.sa_flags = 0;
    if (sigaction(SIGINT, &sig, &g_oldSig) < 0) {
        perror("Fail to call sigaction for SIGINT");
        return false;
    }
    return true;
}

static void RecoverCaptureSig()
{
    if (sigaction(SIGINT, &g_oldSig, nullptr) < 0) {
        perror("Fail to call sigaction for SIGINT");
    }
}

// split to two part
// because WriteAttrAndId need fd id before start tracking
bool PerfEvents::PrepareTracking(void)
{
    HLOGV("enter");
    // 1. prepare cpu pid
    if (!PrepareFdEvents()) {
        HLOGE("PrepareFdEvents() failed");
        return false;
    }

    // 2. create events
    if (!CreateFdEvents()) {
        HLOGE("CreateFdEvents() failed");
        return false;
    }

    HLOGV("success");
    prepared_ = true;
    return true;
}

void PerfEvents::ExitReadRecordBufThread()
{
    if (isLowPriorityThread_) {
        if (setpriority(PRIO_PROCESS, gettid(), 0) != 0) {
            HLOGW("failed to decrease priority of reading kernel");
        }
    }
    if (readRecordBufThread_.joinable()) {
        {
            std::lock_guard<std::mutex> lk(mtxRrecordBuf_);
            readRecordThreadRunning_ = false;
            __sync_synchronize();
            cvRecordBuf_.notify_one();
        }
        readRecordBufThread_.join();
    }
}

bool PerfEvents::PrepareRecordThread()
{
    try {
        recordBuf_ = std::make_unique<RingBuffer>(CalcBufferSize());
    } catch (const std::exception &e) {
        printf("create record buffer(size %zu) failed: %s\n", CalcBufferSize(), e.what());
        return false;
    }
    readRecordThreadRunning_ = true;
    readRecordBufThread_ = std::thread(&PerfEvents::ReadRecordFromBuf, this);

    rlimit rlim;
    int result = getrlimit(RLIMIT_NICE, &rlim);
    const rlim_t lowPriority = 40;
    if (result == 0 && rlim.rlim_cur == lowPriority) {
        const int highPriority = -20;
        result = setpriority(PRIO_PROCESS, gettid(), highPriority);
        if (result != 0) {
            HLOGW("failed to increase priority of reading kernel");
        } else {
            isLowPriorityThread_ = true;
        }
    }

    return true;
}

void PerfEvents::WaitRecordThread()
{
    printf("Process and Saving data...\n");
    ExitReadRecordBufThread();

    const auto usedTimeMsTick = duration_cast<milliseconds>(steady_clock::now() - trackingEndTime_);
    if (verboseReport_) {
        printf("Record Process Completed (wait %" PRId64 " ms)\n", (uint64_t)usedTimeMsTick.count());
    }
    HLOGV("Record Process Completed (wait %" PRId64 " ms)\n", (uint64_t)usedTimeMsTick.count());
#ifdef HIPERF_DEBUG_TIME
    printf("%zu record processed, used %0.3f ms(%4.2f us/record)\n", recordEventCount_,
           recordCallBackTime_.count() / MS_DUARTION,
           recordCallBackTime_.count() / static_cast<double>(recordEventCount_));
    printf("total wait sleep time %0.3f ms.\n", recordSleepTime_.count() / MS_DUARTION);
    printf("read from kernel time %0.3f ms.\n", recordKernelReadTime_.count() / MS_DUARTION);
#endif
}

bool PerfEvents::StartTracking(bool immediately)
{
    HLOGV("enter");
    if (!prepared_) {
        HLOGD("do not prepared_");
        return false;
    }

    HLOGD("step: 1. enable event");
    trackingStartTime_ = steady_clock::now();
    if (immediately) {
        if (!EnableTracking()) {
            HLOGE("PerfEvents::EnableTracking() failed");
            return false;
        }
    }

    if (recordCallBack_) {
        if (!PrepareRecordThread()) {
            return false;
        }
    }

    if (immediately) {
        printf("Profiling duration is %.3f seconds.\n", float(timeOut_.count()) / THOUSANDS);
        printf("Start Profiling...\n");
    }

    g_trackRunning = true;
    if (!CaptureSig()) {
        HLOGE("captureSig() failed");
        g_trackRunning = false;
        ExitReadRecordBufThread();
        return false;
    }

    HLOGD("step: 2. thread loop");
    if (recordCallBack_) {
        RecordLoop();
    } else {
        StatLoop();
    }

    HLOGD("step: 3. disable event");
    if (!PerfEventsEnable(false)) {
        HLOGE("PerfEvents::PerfEventsEnable() failed");
    }
    trackingEndTime_ = steady_clock::now();

    RecoverCaptureSig();

    if (recordCallBack_) {
        WaitRecordThread();
    }

    HLOGD("step: 4. exit");
    return true;
}

bool PerfEvents::StopTracking(void)
{
    if (g_trackRunning) {
        printf("some one called StopTracking\n");
        g_trackRunning = false;
        if (trackedCommand_) {
            if (trackedCommand_->GetState() == TrackedCommand::State::COMMAND_STARTED) {
                trackedCommand_->Stop();
            }
        }
        if (!PerfEventsEnable(false)) {
            HLOGE("StopTracking : PerfEventsEnable(false) failed");
            return false;
        }
    }
    return true;
}

bool PerfEvents::PauseTracking(void)
{
    if (!startedTracking_) {
        return false;
    }
    return PerfEventsEnable(false);
}

bool PerfEvents::ResumeTracking(void)
{
    if (!startedTracking_) {
        return false;
    }
    return PerfEventsEnable(true);
}

bool PerfEvents::EnableTracking()
{
    if (startedTracking_) {
        return true;
    }
    if (!PerfEventsEnable(true)) {
        HLOGE("PerfEvents::PerfEventsEnable() failed");
        return false;
    }

    if (trackedCommand_) {
        // start tracked Command
        if (trackedCommand_->GetState() == TrackedCommand::State::COMMAND_WAITING) {
            if (!trackedCommand_->StartCommand()) {
                int wstatus;
                if (!trackedCommand_->WaitCommand(wstatus)) {
                    trackedCommand_->Stop();
                }
                std::string commandName = trackedCommand_->GetCommandName();
                printf("failed to execute command: %zu: %s\n", commandName.size(), commandName.c_str());
                return false;
            }
        } else if (trackedCommand_->GetState() != TrackedCommand::State::COMMAND_STARTED) {
            return false;
        }
    }
    startedTracking_ = true;
    return true;
}

bool PerfEvents::IsTrackRunning()
{
    return g_trackRunning;
}

void PerfEvents::SetSystemTarget(bool systemTarget)
{
    systemTarget_ = systemTarget;
}

void PerfEvents::SetCpu(std::vector<pid_t> cpus)
{
    cpus_ = cpus;
}

void PerfEvents::SetPid(std::vector<pid_t> pids)
{
    pids_ = pids;
}

void PerfEvents::SetTimeOut(float timeOut)
{
    if (timeOut > 0) {
        timeOut_ = milliseconds(static_cast<int>(timeOut * THOUSANDS));
    }
}

void PerfEvents::SetTimeReport(int timeReport)
{
    static constexpr int minMsReportInterval = 100;
    if (timeReport < minMsReportInterval && timeReport != 0) {
        timeReport = minMsReportInterval;
        printf("time report min value is %d.\n", timeReport);
    }

    timeReport_ = milliseconds(timeReport);
}

std::map<__u64, std::string> PerfEvents::GetSupportEvents(perf_type_id type)
{
    if (type == PERF_TYPE_TRACEPOINT) {
        LoadTracepointEventTypesFromSystem();
    }

    std::map<__u64, std::string> eventConfigs;
    auto configTable = TYPE_CONFIGS.find(type);
    if (configTable != TYPE_CONFIGS.end()) {
        auto configs = configTable->second;
        for (auto config : configs) {
            if (type == PERF_TYPE_TRACEPOINT || IsEventSupport(type, (__u64)config.first)) {
                eventConfigs.insert(config);
            } else {
                HLOGD("'%s' not support", config.second.c_str());
            }
        }
    }
    return eventConfigs;
}

void PerfEvents::LoadTracepointEventTypesFromSystem()
{
    if (traceConfigTable.empty()) {
        std::string basePath {"/sys/kernel/tracing/events"};
        if (access(basePath.c_str(), R_OK) != 0) {
            basePath = "/sys/kernel/debug/tracing/events";
        }
        for (const auto &eventName : GetSubDirs(basePath)) {
            std::string eventPath = basePath + "/" + eventName;
            for (const auto &concreteEvent : GetSubDirs(eventPath)) {
                std::string idPath = eventPath + "/" + concreteEvent + "/id";
                {
                    std::ifstream ifs {idPath};
                    // clang-format off
                    const std::string idStr = {
                        std::istream_iterator<char>(ifs),
                        std::istream_iterator<char>()
                    };
                    // clang-format on
                    __u64 id {0};
                    try {
                        id = std::stoul(idStr, nullptr);
                    } catch (...) {
                        continue;
                    }
                    auto typeConfigs = TYPE_CONFIGS.find(PERF_TYPE_TRACEPOINT);
                    HLOG_ASSERT(typeConfigs != TYPE_CONFIGS.end());
                    auto configPair = typeConfigs->second.insert(
                        std::make_pair(id, eventName + ":" + concreteEvent));
                    traceConfigTable.insert(std::make_pair(id, eventName + ":" + concreteEvent));
                    ConfigTable::iterator it = configPair.first;
                    HLOGV("TYPE_CONFIGS add %llu:%s in %zu", it->first, it->second.c_str(),
                          typeConfigs->second.size());
                }
            }
        }
    }
}

void PerfEvents::SetVerboseReport(bool verboseReport)
{
    verboseReport_ = verboseReport;
}

void PerfEvents::SetSampleFrequency(unsigned int frequency)
{
    if (frequency > 0) {
        sampleFreq_ = frequency;
    }
}

void PerfEvents::SetSamplePeriod(unsigned int period)
{
    if (period > 0) {
        samplePeriod_ = period;
    }
}

void PerfEvents::SetMmapPages(size_t mmapPages)
{
    mmapPages_ = mmapPages;
}

void PerfEvents::SetSampleStackType(SampleStackType type)
{
    sampleStackType_ = type;
}

void PerfEvents::SetDwarfSampleStackSize(uint32_t stackSize)
{
    HLOGD("request stack size is %u", stackSize);
    dwarfSampleStackSize_ = stackSize;
}

bool PerfEvents::PerfEventsEnable(bool enable)
{
    HLOGV("%s", std::to_string(enable).c_str());
    for (const auto &eventGroupItem : eventGroupItem_) {
        for (const auto &eventItem : eventGroupItem.eventItems) {
            for (const auto &fdItem : eventItem.fdItems) {
                int result =
                    ioctl(fdItem.fd, enable ? PERF_EVENT_IOC_ENABLE : PERF_EVENT_IOC_DISABLE, 0);
                if (result < 0) {
                    printf("Cannot '%s' perf fd! type config name: '%s:%s'\n",
                           enable ? "enable" : "disable", eventItem.typeName.c_str(),
                           eventItem.configName.c_str());
                    return false;
                }
            }
        }
    }
    return true;
}

void PerfEvents::SetStatCallBack(StatCallBack reportCallBack)
{
    reportCallBack_ = reportCallBack;
}
void PerfEvents::SetRecordCallBack(RecordCallBack recordCallBack)
{
    recordCallBack_ = recordCallBack;
}

inline void PerfEvents::PutAllCpus()
{
    int processorNum = GetProcessorNum();
    for (int i = 0; i < processorNum; i++) {
        cpus_.push_back(i); // put all cpu
    }
}

bool PerfEvents::PrepareFdEvents(void)
{
    HLOGV("enter");
    /*
    https://man7.org/linux/man-pages/man2/perf_event_open.2.html
    pid == 0 and cpu == -1
            This measures the calling process/thread on any CPU.

    pid == 0 and cpu >= 0
            This measures the calling process/thread only when running
            on the specified CPU.

    pid > 0 and cpu == -1
            This measures the specified process/thread on any CPU.

    pid > 0 and cpu >= 0
            This measures the specified process/thread only when
            running on the specified CPU.

    pid == -1 and cpu >= 0
            This measures all processes/threads on the specified CPU.
            This requires CAP_PERFMON (since Linux 5.8) or
            CAP_SYS_ADMIN capability or a
            /proc/sys/kernel/perf_event_paranoid value of less than 1.

    pid == -1 and cpu == -1
            This setting is invalid and will return an error.
    */
    if (systemTarget_) {
        pids_.clear();
        pids_.push_back(-1);
    } else {
        if (trackedCommand_) {
            pids_.push_back(trackedCommand_->GetChildPid());
        }
        if (pids_.empty()) {
            pids_.push_back(0); // no pid means use 0 as self pid
        }
    }

    if (cpus_.empty()) {
        PutAllCpus();
    }

    // print info tell user which cpu and process we will select.
    if (pids_.size() == 1 && pids_[0] == -1) {
        HLOGI("target process: system scope \n");
    } else {
        HLOGI("target process: %zu (%s)\n", pids_.size(),
              (pids_[0] == 0) ? std::to_string(gettid()).c_str() : VectorToString(pids_).c_str());
    }
    if (cpus_.size() == 1 && cpus_[0] == -1) {
        HLOGI("target cpus: %d \n", GetProcessorNum());
    } else {
        HLOGI("target cpus: %zu / %d (%s)\n", cpus_.size(), GetProcessorNum(), VectorToString(cpus_).c_str());
    }

    return true;
}

bool PerfEvents::CreateFdEvents(void)
{
    HLOGV("enter");

    // must be some events , or will failed
    if (eventGroupItem_.empty()) {
        printf("no event select.\n");
        return false;
    }

    // create each fd by cpu and process user select
    /*
        https://man7.org/linux/man-pages/man2/perf_event_open.2.html

        (A single event on its own is created with group_fd = -1 and is
        considered to be a group with only 1 member.)
    */
    // Even if there is only one event, it is counted as a group.

    uint fdNumber = 0;
    uint eventNumber = 0;
    uint groupNumber = 0;
    for (auto &eventGroupItem : eventGroupItem_) {
        /*
            Explain what is the configuration of the group:
            Suppose we have 2 Event, 2 PID, and 3 CPU settings
            According to verification,
            Group's fd requires the pid to be the same as the cpu, the only difference is event
            In other words, if you want to bind E1 and E2 to the same group
            That can only be like this:

            event E1 pid P1 cpu C1 [Group 1]
            event E1 pid P1 cpu C2 [Group 2]
            event E1 pid P1 cpu C3 [Group 3]

            event E1 pid P2 cpu C1 [Group 4]
            event E1 pid P2 cpu C2 [Group 5]
            event E1 pid P2 cpu C3 [Group 6]

            event E2 pid P1 cpu C1 [Group 1]
            event E2 pid P1 cpu C2 [Group 2]
            event E2 pid P1 cpu C3 [Group 3]

            event E2 pid P2 cpu C1 [Group 4]
            event E2 pid P2 cpu C2 [Group 5]
            event E2 pid P2 cpu C3 [Group 6]
        */
        HLOGV("group %2u. eventGroupItem leader: '%s':", groupNumber++,
              eventGroupItem.eventItems[0].configName.c_str());

        int groupFdCache[cpus_.size()][pids_.size()];
        for (size_t i = 0; i < cpus_.size(); i++) {     // each cpu
            for (size_t j = 0; j < pids_.size(); j++) { // each pid
                // The leader is created first, with group_fd = -1.
                groupFdCache[i][j] = -1;
            }
        }

        uint eventIndex = 0;
        for (auto &eventItem : eventGroupItem.eventItems) {
            HLOGV(" - event %2u. eventName: '%s:%s'", eventIndex++, eventItem.typeName.c_str(),
                  eventItem.configName.c_str());

            for (size_t icpu = 0; icpu < cpus_.size(); icpu++) {     // each cpu
                for (size_t ipid = 0; ipid < pids_.size(); ipid++) { // each pid
                    // one fd event group must match same cpu and same pid config (event can be
                    // different)
                    // clang-format off
                    UniqueFd fd = Open(eventItem.attr, pids_[ipid], cpus_[icpu],
                                       groupFdCache[icpu][ipid], 0);
                    // clang-format on
                    if (fd < 0) {
                        if (errno == ESRCH) {
                            if (verboseReport_) {
                                printf("pid %d does not exist.\n", pids_[ipid]);
                            }
                            HLOGE("pid %d does not exist.\n", pids_[ipid]);
                            continue;
                        } else {
                            // clang-format off
                            if (verboseReport_) {
                                char errInfo[ERRINFOLEN] = { 0 };
                                strerror_r(errno, errInfo, ERRINFOLEN);
                                printf("%s event is not supported by the kernel on cpu %d. reason: %d:%s\n",
                                    eventItem.configName.c_str(), cpus_[icpu], errno, errInfo);
                            }
                            char errInfo[ERRINFOLEN] = { 0 };
                            strerror_r(errno, errInfo, ERRINFOLEN);
                            HLOGE("%s event is not supported by the kernel on cpu %d. reason: %d:%s\n",
                                eventItem.configName.c_str(), cpus_[icpu], errno, errInfo);
                            // clang-format on
                            break; // jump to next cpu
                        }
                    }
                    // after open successed , fill the result
                    // make a new FdItem
                    FdItem &fdItem = eventItem.fdItems.emplace_back();
                    fdItem.fd = move(fd);
                    fdItem.cpu = cpus_[icpu];
                    fdItem.pid = pids_[ipid];
                    fdNumber++;

                    // if sampling, mmap ring buffer
                    if (recordCallBack_) {
                        CreateMmap(fdItem, eventItem.attr);
                    }
                    // update group leader
                    if (groupFdCache[icpu][ipid] == -1) {
                        groupFdCache[icpu][ipid] = fdItem.fd.Get();
                    }
                }
            }
            eventNumber++;
        }
    }

    if (fdNumber == 0) {
        HLOGE("open %d fd for %d events", fdNumber, eventNumber);
        return false;
    }

    HLOGD("will try read %u events from %u fd (%zu groups):", eventNumber, fdNumber,
          eventGroupItem_.size());

    return true;
}

bool PerfEvents::StatReport(const __u64 &durationInSec)
{
    read_format_no_group readNoGroupValue;

    // only need read when need report
    HLOGM("eventGroupItem_:%zu", eventGroupItem_.size());
    __u64 groupId = 0;
    // clear countEvents data
    countEvents_.clear();
    for (const auto &eventGroupItem : eventGroupItem_) {
        HLOGM("eventItems:%zu", eventGroupItem.eventItems.size());
        groupId++;
        for (const auto &eventItem : eventGroupItem.eventItems) {
            // count event info together (every cpu , every pid)
            std::string configName = "";
            if (eventItem.attr.exclude_kernel) {
                configName = eventItem.configName + ":u";
            } else if (eventItem.attr.exclude_user) {
                configName = eventItem.configName + ":k";
            } else {
                configName = eventItem.configName;
            }
            if (countEvents_.count(configName) == 0) {
                auto countEvent = make_unique<CountEvent>(CountEvent {});
                countEvents_[configName] = std::move(countEvent);
                countEvents_[configName]->userOnly = eventItem.attr.exclude_kernel;
                countEvents_[configName]->kernelOnly = eventItem.attr.exclude_user;
            }
            std::unique_ptr<CountEvent> &countEvent = countEvents_[configName];
            HLOGM("eventItem.fdItems:%zu", eventItem.fdItems.size());
            for (const auto &fditem : eventItem.fdItems) {
                if (read(fditem.fd, &readNoGroupValue, sizeof(readNoGroupValue)) > 0) {
                    countEvent->eventCount += readNoGroupValue.value;
                    countEvent->time_enabled += readNoGroupValue.time_enabled;
                    countEvent->time_running += readNoGroupValue.time_running;
                    countEvent->id = groupId;
                    if (durationInSec != 0) {
                        countEvent->used_cpus =
                            (countEvent->eventCount / 1e9) / (durationInSec / THOUSANDS);
                    }
                    if (verboseReport_) {
                        printf("%s id:%llu(c%d:p%d) time_enabled:%llu time_running:%llu "
                               "value:%llu\n",
                               eventItem.configName.c_str(), readNoGroupValue.id, fditem.cpu,
                               fditem.pid, readNoGroupValue.time_enabled,
                               readNoGroupValue.time_running, readNoGroupValue.value);
                    }
                } else {
                    printf("read failed from event '%s'\n", eventItem.configName.c_str());
                }
            }
        }
    }

    reportCallBack_(countEvents_);

    return true;
}

bool PerfEvents::CreateMmap(const FdItem &item, const perf_event_attr &attr)
{
    auto it = cpuMmap_.find(item.cpu);
    if (it == cpuMmap_.end()) {
        void *rbuf = mmap(nullptr, (1 + mmapPages_) * pageSize_, PROT_READ | PROT_WRITE, MAP_SHARED,
                          item.fd.Get(), 0);
        if (rbuf == MMAP_FAILED) {
            char errInfo[ERRINFOLEN] = {0};
            strerror_r(errno, errInfo, ERRINFOLEN);
            perror("errno:%d, errstr:%s", errno, errInfo);
            perror("Fail to call mmap \n");
            return false;
        }
        MmapFd mmapItem;
        mmapItem.fd = item.fd.Get();
        mmapItem.mmapPage = reinterpret_cast<perf_event_mmap_page *>(rbuf);
        mmapItem.buf = reinterpret_cast<uint8_t *>(rbuf) + pageSize_;
        mmapItem.bufSize = mmapPages_ * pageSize_;
        mmapItem.attr = &attr;
        mmapItem.posCallChain = GetCallChainPosInSampleRecord(attr);

        cpuMmap_[item.cpu] = mmapItem;
        pollFds_.emplace_back(pollfd {mmapItem.fd, POLLIN, 0});
        HLOGD("CreateMmap success cpu %d fd %d", item.cpu, mmapItem.fd);
    } else {
        const MmapFd &mmapItem = it->second;
        int rc = ioctl(item.fd.Get(), PERF_EVENT_IOC_SET_OUTPUT, mmapItem.fd);
        if (rc != 0) {
            HLOGEP("ioctl PERF_EVENT_IOC_SET_OUTPUT (%d -> %d) ", item.fd.Get(), mmapItem.fd);
            perror("failed to share mapped buffer\n");
            return false;
        }
    }
    return true;
}

std::vector<AttrWithId> PerfEvents::GetAttrWithId() const
{
    std::vector<AttrWithId> result;
    HLOGV("eventGroupItem_ %zu :", eventGroupItem_.size());

    for (const auto &eventGroupItem : eventGroupItem_) {
        HLOGV(" eventItems %zu eventItems:", eventGroupItem.eventItems.size());
        for (const auto &eventItem : eventGroupItem.eventItems) {
            AttrWithId attrId;
            attrId.attr = eventItem.attr;
            attrId.name = eventItem.configName;
            HLOGV("  fdItems %zu fdItems:", eventItem.fdItems.size());
            for (const auto &fdItem : eventItem.fdItems) {
                auto &id = attrId.ids.emplace_back(fdItem.GetPrefId());
                HLOGV("    eventItem.fdItems GetPrefId %" PRIu64 "", id);
            }
            result.emplace_back(attrId);
        }
    }
    return result;
}

size_t PerfEvents::CalcBufferSize()
{
    size_t bufferSize = MAX_BUFFER_SIZE;
    if (!systemTarget_) {
        // suppose ring buffer is 4 times as much as mmap
        static constexpr int TIMES = 4;
        bufferSize = cpuMmap_.size() * mmapPages_ * pageSize_ * TIMES;
        if (bufferSize < MIN_BUFFER_SIZE) {
            bufferSize = MIN_BUFFER_SIZE;
        } else if (bufferSize > MAX_BUFFER_SIZE) {
            bufferSize = MAX_BUFFER_SIZE;
        }
    }
    HLOGD("CalcBufferSize return %zu", bufferSize);
    return bufferSize;
}

inline bool PerfEvents::IsRecordInMmap()
{
    if (pollFds_.size() > 0) {
        if (poll((struct pollfd *)pollFds_.data(), pollFds_.size(), pollTimeOut_) <= 0) {
            // time out try again
            return false;
        }
    }
    return true;
}

static bool CompareRecordTime(const PerfEvents::MmapFd *left, const PerfEvents::MmapFd *right)
{
    return left->timestamp > right->timestamp;
}

void PerfEvents::ReadRecordsFromMmaps()
{
#ifdef HIPERF_DEBUG_TIME
    const auto readKenelStartTime = steady_clock::now();
#endif
    // get readable mmap at this time
    for (auto &it : cpuMmap_) {
        ssize_t dataSize = it.second.mmapPage->data_head - it.second.mmapPage->data_tail;
        __sync_synchronize(); // this same as rmb in gcc, after reading mmapPage->data_head
        if (dataSize <= 0) {
            continue;
        }
        it.second.dataSize = dataSize;
        MmapRecordHeap_.push_back(&(it.second));
    }
    if (MmapRecordHeap_.empty()) {
        return;
    }

    if (MmapRecordHeap_.size() > 1) {
        for (auto &it : MmapRecordHeap_) {
            GetRecordFromMmap(*it);
        }
        std::make_heap(MmapRecordHeap_.begin(), MmapRecordHeap_.end(), CompareRecordTime);

        size_t heapSize = MmapRecordHeap_.size();
        while (heapSize > 1) {
            std::pop_heap(MmapRecordHeap_.begin(), MmapRecordHeap_.begin() + heapSize,
                          CompareRecordTime);
            MoveRecordToBuf(*MmapRecordHeap_[heapSize - 1]);
            if (GetRecordFromMmap(*MmapRecordHeap_[heapSize - 1])) {
                std::push_heap(MmapRecordHeap_.begin(), MmapRecordHeap_.begin() + heapSize,
                               CompareRecordTime);
            } else {
                heapSize--;
            }
        }
    }

    while (GetRecordFromMmap(*MmapRecordHeap_.front())) {
        MoveRecordToBuf(*MmapRecordHeap_.front());
    }
    MmapRecordHeap_.clear();
    {
        std::lock_guard<std::mutex> lk(mtxRrecordBuf_);
        recordBufReady_ = true;
    }
    cvRecordBuf_.notify_one();
#ifdef HIPERF_DEBUG_TIME
    recordKernelReadTime_ += duration_cast<milliseconds>(steady_clock::now() - readKenelStartTime);
#endif
}

bool PerfEvents::GetRecordFromMmap(MmapFd &mmap)
{
    if (mmap.dataSize <= 0) {
        return false;
    }

    GetRecordFieldFromMmap(mmap, &(mmap.header), mmap.mmapPage->data_tail, sizeof(mmap.header));
    if (mmap.header.type != PERF_RECORD_SAMPLE) {
        mmap.timestamp = 0;
        return true;
    }
    // in PERF_RECORD_SAMPLE : header + u64 sample_id + u64 ip + u32 pid + u32 tid + u64 time
    constexpr size_t timePos = sizeof(perf_event_header) + sizeof(uint64_t) + sizeof(uint64_t) +
                               sizeof(uint32_t) + sizeof(uint32_t);
    GetRecordFieldFromMmap(mmap, &(mmap.timestamp), mmap.mmapPage->data_tail + timePos,
                           sizeof(mmap.timestamp));
    return true;
}

void PerfEvents::GetRecordFieldFromMmap(MmapFd &mmap, void *dest, size_t pos, size_t size)
{
    pos = pos % mmap.bufSize;
    size_t tailSize = mmap.bufSize - pos;
    size_t copySize = std::min(size, tailSize);
    if (memcpy_s(dest, copySize, mmap.buf + pos, copySize) != 0) {
        HLOGEP("memcpy_s %p to %p failed. size %zd", mmap.buf + pos, dest, copySize);
    }
    if (copySize < size) {
        size -= copySize;
        if (memcpy_s(static_cast<uint8_t *>(dest) + copySize, size, mmap.buf, size) != 0) {
            HLOGEP("memcpy_s %p to %p failed. size %zd", mmap.buf,
                   static_cast<uint8_t *>(dest) + copySize, size);
        }
    }
}

size_t PerfEvents::GetCallChainPosInSampleRecord(const perf_event_attr &attr)
{
    // reference struct PerfRecordSampleData
    int fixedFieldNumber = __builtin_popcountll(
        attr.sample_type & (PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_IP | PERF_SAMPLE_TID |
                            PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR | PERF_SAMPLE_ID |
                            PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD));
    size_t pos = sizeof(perf_event_header) + sizeof(uint64_t) * fixedFieldNumber;
    if (attr.sample_type & PERF_SAMPLE_READ) {
        pos += sizeof(read_format);
    }
    return pos;
}

size_t PerfEvents::GetStackSizePosInSampleRecord(MmapFd &mmap)
{
    size_t pos = mmap.posCallChain;
    if (mmap.attr->sample_type & PERF_SAMPLE_CALLCHAIN) {
        uint64_t nr = 0;
        GetRecordFieldFromMmap(mmap, &nr, mmap.mmapPage->data_tail + pos, sizeof(nr));
        pos += (sizeof(nr) + nr * sizeof(uint64_t));
    }
    if (mmap.attr->sample_type & PERF_SAMPLE_RAW) {
        uint32_t raw_size = 0;
        GetRecordFieldFromMmap(mmap, &raw_size, mmap.mmapPage->data_tail + pos, sizeof(raw_size));
        pos += (sizeof(raw_size) + raw_size);
    }
    if (mmap.attr->sample_type & PERF_SAMPLE_BRANCH_STACK) {
        uint64_t bnr = 0;
        GetRecordFieldFromMmap(mmap, &bnr, mmap.mmapPage->data_tail + pos, sizeof(bnr));
        pos += (sizeof(bnr) + bnr * sizeof(perf_branch_entry));
    }
    if (mmap.attr->sample_type & PERF_SAMPLE_REGS_USER) {
        uint64_t user_abi = 0;
        GetRecordFieldFromMmap(mmap, &user_abi, mmap.mmapPage->data_tail + pos, sizeof(user_abi));
        pos += sizeof(user_abi);
        if (user_abi > 0) {
            uint64_t reg_nr = __builtin_popcountll(mmap.attr->sample_regs_user);
            pos += reg_nr * sizeof(uint64_t);
        }
    }
    return pos;
}

bool PerfEvents::CutStackAndMove(MmapFd &mmap)
{
    constexpr uint32_t alignSize = 64;
    if (!(mmap.attr->sample_type & PERF_SAMPLE_STACK_USER)) {
        return false;
    }
    size_t stackSizePos = GetStackSizePosInSampleRecord(mmap);
    uint64_t stackSize = 0;
    GetRecordFieldFromMmap(mmap, &stackSize, mmap.mmapPage->data_tail + stackSizePos,
                           sizeof(stackSize));
    if (stackSize == 0) {
        return false;
    }
    size_t dynSizePos = stackSizePos + sizeof(uint64_t) + stackSize;
    uint64_t dynSize = 0;
    GetRecordFieldFromMmap(mmap, &dynSize, mmap.mmapPage->data_tail + dynSizePos, sizeof(dynSize));
    uint64_t newStackSize = std::min(ALIGN(dynSize, alignSize), stackSize);
    if (newStackSize >= stackSize) {
        return false;
    }
    HLOGM("stackSize %" PRIx64 " dynSize %" PRIx64 " newStackSize %" PRIx64 "\n", stackSize, dynSize, newStackSize);
    // move and cut stack_data
    // mmap: |<+++copy1+++>|<++++++copy2++++++>|<---------------cut--------------->|<+++copy3+++>|
    //             ^                    ^                        ^                 ^
    //         new_header          stackSizePos         <stackSize-dynSize>     dynSizePos
    uint16_t recordSize = mmap.header.size;
    mmap.header.size -= stackSize - newStackSize; // reduce the stack size
    uint8_t *buf = recordBuf_->AllocForWrite(mmap.header.size);
    // copy1: new_header
    if (memcpy_s(buf, sizeof(perf_event_header), &(mmap.header), sizeof(perf_event_header)) != 0) {
        HLOGEP("memcpy_s %p to %p failed. size %zd", &(mmap.header), buf,
               sizeof(perf_event_header));
    }
    size_t copyPos = sizeof(perf_event_header);
    size_t copySize = stackSizePos - sizeof(perf_event_header) + sizeof(stackSize) + newStackSize;
    // copy2: copy stack_size, data[stack_size],
    GetRecordFieldFromMmap(mmap, buf + copyPos, mmap.mmapPage->data_tail + copyPos, copySize);
    copyPos += copySize;
    // copy3: copy dyn_size
    GetRecordFieldFromMmap(mmap, buf + copyPos, mmap.mmapPage->data_tail + dynSizePos,
                           recordSize - dynSizePos);
    // update stack_size
    if (memcpy_s(buf + stackSizePos, sizeof(stackSize), &(newStackSize), sizeof(newStackSize)) != 0) {
        HLOGEP("memcpy_s %p to %p failed. size %zd", &(newStackSize), buf + stackSizePos, sizeof(newStackSize));
    }
    recordBuf_->EndWrite();
    __sync_synchronize();
    mmap.mmapPage->data_tail += recordSize;
    mmap.dataSize -= recordSize;
    return true;
}

void PerfEvents::MoveRecordToBuf(MmapFd &mmap)
{
    uint8_t *buf = nullptr;
    if (mmap.header.type == PERF_RECORD_SAMPLE) {
        if (recordBuf_->GetFreeSize() <= BUFFER_CRITICAL_LEVEL) {
            lostSamples_++;
            HLOGD("BUFFER_CRITICAL_LEVEL: lost sample record");
            goto RETURN;
        }
        if (CutStackAndMove(mmap)) {
            return;
        }
    } else if (mmap.header.type == PERF_RECORD_LOST) {
        // in PERF_RECORD_LOST : header + u64 id + u64 lost
        constexpr size_t lostPos = sizeof(perf_event_header) + sizeof(uint64_t);
        uint64_t lost = 0;
        GetRecordFieldFromMmap(mmap, &lost, mmap.mmapPage->data_tail + lostPos, sizeof(lost));
        lostSamples_ += lost;
        HLOGD("PERF_RECORD_LOST: lost sample record");
        goto RETURN;
    }

    if ((buf = recordBuf_->AllocForWrite(mmap.header.size)) == nullptr) {
        // this record type must be Non-Sample
        lostNonSamples_++;
        HLOGD("alloc buffer failed: lost non-sample record");
        goto RETURN;
    }

    GetRecordFieldFromMmap(mmap, buf, mmap.mmapPage->data_tail, mmap.header.size);
    recordBuf_->EndWrite();
RETURN:
    __sync_synchronize();
    mmap.mmapPage->data_tail += mmap.header.size;
    mmap.dataSize -= mmap.header.size;
}

void PerfEvents::ReadRecordFromBuf()
{
    HLOGV("enter");

    const perf_event_attr *attr = GetDefaultAttr();
    uint8_t *p = nullptr;

    while (readRecordThreadRunning_) {
        {
            std::unique_lock<std::mutex> lk(mtxRrecordBuf_);
            cvRecordBuf_.wait(lk, [this] {
                if (recordBufReady_) {
                    recordBufReady_ = false;
                    return true;
                }
                return !readRecordThreadRunning_;
            });
        }
        while ((p = recordBuf_->GetReadData()) != nullptr) {
            uint32_t *type = reinterpret_cast<uint32_t *>(p);
#ifdef HIPERF_DEBUG_TIME
            const auto readingStartTime_ = steady_clock::now();
#endif
#if !HIDEBUG_SKIP_CALLBACK
            recordCallBack_(GetPerfEventRecord(*type, p, *attr));
#endif
            recordEventCount_++;
#ifdef HIPERF_DEBUG_TIME
            recordCallBackTime_ +=
                duration_cast<milliseconds>(steady_clock::now() - readingStartTime_);
#endif
            recordBuf_->EndRead();
        }
    }
    HLOGD("exit because trackStoped");

    // read the data left over in buffer
    while ((p = recordBuf_->GetReadData()) != nullptr) {
        uint32_t *type = reinterpret_cast<uint32_t *>(p);
#ifdef HIPERF_DEBUG_TIME
        const auto readingStartTime_ = steady_clock::now();
#endif
#if !HIDEBUG_SKIP_CALLBACK
        recordCallBack_(GetPerfEventRecord(*type, p, *attr));
#endif
        recordEventCount_++;
#ifdef HIPERF_DEBUG_TIME
        recordCallBackTime_ += duration_cast<milliseconds>(steady_clock::now() - readingStartTime_);
#endif
        recordBuf_->EndRead();
    }
    HLOGD("read all records from buffer");
}

bool PerfEvents::HaveTargetsExit(const std::chrono::steady_clock::time_point &startTime)
{
    if (systemTarget_) {
        return false;
    }
    if (trackedCommand_) {
        if (trackedCommand_->GetState() < TrackedCommand::State::COMMAND_STARTED) {
            return false; // not start yet
        }
        int wstatus;
        if (trackedCommand_->WaitCommand(wstatus)) {
            milliseconds usedMsTick = duration_cast<milliseconds>(steady_clock::now() - startTime);
            printf("tracked command(%s) has exited (total %" PRId64 " ms)\n",
                   trackedCommand_->GetCommandName().c_str(), (uint64_t)usedMsTick.count());
            return true;
        }
        return false;
    }

    for (auto it = pids_.begin(); it != pids_.end();) {
        if (IsDir("/proc/" + std::to_string(*it))) {
            it++;
        } else {
            it = pids_.erase(it);
        }
    }
    if (pids_.empty()) {
        milliseconds usedMsTick = duration_cast<milliseconds>(steady_clock::now() - startTime);
        printf("tracked processes have exited (total %" PRId64 " ms)\n", (uint64_t)usedMsTick.count());
        return true;
    }
    return false;
}

void PerfEvents::RecordLoop()
{
    HLOGV("enter");

    // calc the time
    const auto startTime = steady_clock::now();
    const auto endTime = startTime + timeOut_;
    milliseconds usedTimeMsTick {};

    while (g_trackRunning) {
        // time check point
        const auto thisTime = steady_clock::now();

        if (IsRecordInMmap()) {
            ReadRecordsFromMmaps();
        }

        if (HaveTargetsExit(startTime)) {
            break;
        }

        if (thisTime >= endTime) {
            usedTimeMsTick = duration_cast<milliseconds>(thisTime - startTime);
            printf("Timeout exit (total %" PRId64 " ms)\n", (uint64_t)usedTimeMsTick.count());
            if (trackedCommand_) {
                trackedCommand_->Stop();
            }
            break;
        }
    }
    ReadRecordsFromMmaps();

    if (!g_trackRunning) {
        // for user interrupt situation, print time statistic
        usedTimeMsTick = duration_cast<milliseconds>(steady_clock::now() - startTime);
        printf("User interrupt exit (total %" PRId64 " ms)\n", (uint64_t)usedTimeMsTick.count());
    }
}

void PerfEvents::StatLoop()
{
    HLOGV("enter");

    // calc the time
    const auto startTime = steady_clock::now();
    const auto endTime = startTime + timeOut_;
    auto nextReportTime = startTime + timeReport_;
    milliseconds usedTimeMsTick {};
    __u64 durationInSec = 0;
    int64_t thesholdTimeInMs = 2 * HUNDREDS;

    while (g_trackRunning) {
        // time check point
        const auto thisTime = steady_clock::now();
        if (timeReport_ != milliseconds::zero()) {
            // stat cmd
            if (thisTime >= nextReportTime) {
                // only for log or debug?
                usedTimeMsTick = duration_cast<milliseconds>(thisTime - startTime);
                durationInSec = usedTimeMsTick.count();
                auto lefTimeMsTick = duration_cast<milliseconds>(endTime - thisTime);
                printf("\nReport at %" PRId64 " ms (%" PRId64 " ms left):\n",
                       (uint64_t)usedTimeMsTick.count(), (uint64_t)lefTimeMsTick.count());
                // end of comments
                nextReportTime += timeReport_;
                StatReport(durationInSec);
            }
        }

        if (HaveTargetsExit(startTime)) {
            break;
        }

        if (thisTime >= endTime) {
            usedTimeMsTick = duration_cast<milliseconds>(thisTime - startTime);
            durationInSec = usedTimeMsTick.count();
            printf("Timeout exit (total %" PRId64 " ms)\n", (uint64_t)usedTimeMsTick.count());
            if (trackedCommand_) {
                trackedCommand_->Stop();
            }
            break;
        }

        // lefttime > 200ms sleep 100ms, else sleep 200us
        uint64_t defaultSleepUs = 2 * HUNDREDS; // 200us
        if (timeReport_ == milliseconds::zero()
            && (timeOut_.count() * THOUSANDS) > thesholdTimeInMs) {
            milliseconds leftTimeMsTmp = duration_cast<milliseconds>(endTime - thisTime);
            if (leftTimeMsTmp.count() > thesholdTimeInMs) {
                defaultSleepUs = HUNDREDS * THOUSANDS; // 100ms
            }
        }
        std::this_thread::sleep_for(microseconds(defaultSleepUs));
    }

    if (!g_trackRunning) {
        // for user interrupt situation, print time statistic
        usedTimeMsTick = duration_cast<milliseconds>(steady_clock::now() - startTime);
        printf("User interrupt exit (total %" PRId64 " ms)\n", (uint64_t)usedTimeMsTick.count());
    }

    if (timeReport_ == milliseconds::zero()) {
        StatReport(durationInSec);
    }
}

const std::string PerfEvents::GetTypeName(perf_type_id type_id)
{
    auto it = PERF_TYPES.find(type_id);
    if (it != PERF_TYPES.end()) {
        return it->second;
    } else {
        return "<not found>";
    }
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
