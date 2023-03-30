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
#ifndef HIPERF_PERF_EVENTS_H
#define HIPERF_PERF_EVENTS_H

#include <atomic>
#include <cassert>
#include <chrono>
#include <cinttypes>
#include <condition_variable>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <variant>
#include <vector>
#if !is_mingw
#include <poll.h>
#endif

#include <sys/types.h>
#include <unique_fd.h>
#include <linux/perf_event.h>

#include "debug_logger.h"
#include "perf_event_record.h"
#include "ring_buffer.h"
#include "tracked_command.h"
#include "utilities.h"
#include "virtual_runtime.h"

// this for some performance debug
#define HIDEBUG_SKIP_CALLBACK 0

namespace OHOS {
namespace Developtools {
namespace HiPerf {
using ConfigTable = std::map<__u64, const std::string>;
using SharedConfigTable = std::unique_ptr<ConfigTable>;

static const std::string PERF_EVENT_PARANOID = "/proc/sys/kernel/perf_event_paranoid";
static const std::string PERF_DISABLE_PARAM = "security.perf_harden";

// define convert from linux/perf_event.h
// description from https://man7.org/linux/man-pages/man2/perf_event_open.2.html

static const ConfigTable PERF_HW_CONFIGS = {
    {PERF_COUNT_HW_CPU_CYCLES, "hw-cpu-cycles"},
    {PERF_COUNT_HW_INSTRUCTIONS, "hw-instructions"},
    {PERF_COUNT_HW_CACHE_REFERENCES, "hw-cache-references"},
    {PERF_COUNT_HW_CACHE_MISSES, "hw-cache-misses"},
    {PERF_COUNT_HW_BRANCH_INSTRUCTIONS, "hw-branch-instructions"},
    {PERF_COUNT_HW_BRANCH_MISSES, "hw-branch-misses"},
    {PERF_COUNT_HW_BUS_CYCLES, "hw-bus-cycles"},
    {PERF_COUNT_HW_STALLED_CYCLES_FRONTEND, "hw-stalled-cycles-frontend"},
    {PERF_COUNT_HW_STALLED_CYCLES_BACKEND, "hw-stalled-cycles-backend"},
    {PERF_COUNT_HW_REF_CPU_CYCLES, "hw-ref-cpu-cycles"},
};
static const ConfigTable PERF_HW_CACHE_CONFIGS = {
    {PERF_COUNT_HW_CACHE_L1D, "hw-cache-l1d"},   {PERF_COUNT_HW_CACHE_L1I, "hw-cache-l1i"},
    {PERF_COUNT_HW_CACHE_LL, "hw-cache-ll"},     {PERF_COUNT_HW_CACHE_DTLB, "hw-cache-dtlb"},
    {PERF_COUNT_HW_CACHE_ITLB, "hw-cache-itlb"}, {PERF_COUNT_HW_CACHE_BPU, "hw-cache-bpu"},
    {PERF_COUNT_HW_CACHE_NODE, "hw-cache-node"},
};
static const ConfigTable PERF_HW_CACHE_OP_CONFIGS = {
    {PERF_COUNT_HW_CACHE_OP_READ, "hw-cache-op-read"},
    {PERF_COUNT_HW_CACHE_OP_WRITE, "hw-cache-op-write"},
    {PERF_COUNT_HW_CACHE_OP_PREFETCH, "hw-cache-op-prefetch"},
};
static const ConfigTable PERF_HW_CACHE_OP_RESULT_CONFIGS = {
    {PERF_COUNT_HW_CACHE_RESULT_ACCESS, "hw-cache-result-access"},
    {PERF_COUNT_HW_CACHE_RESULT_MISS, "hw-cache-result-miss"},
};
static const ConfigTable PERF_SW_CONFIGS = {
    {PERF_COUNT_SW_CPU_CLOCK, "sw-cpu-clock"},
    {PERF_COUNT_SW_TASK_CLOCK, "sw-task-clock"},
    {PERF_COUNT_SW_PAGE_FAULTS, "sw-page-faults"},
    {PERF_COUNT_SW_CONTEXT_SWITCHES, "sw-context-switches"},
    {PERF_COUNT_SW_CPU_MIGRATIONS, "sw-cpu-migrations"},
    {PERF_COUNT_SW_PAGE_FAULTS_MIN, "sw-page-faults-min"},
    {PERF_COUNT_SW_PAGE_FAULTS_MAJ, "sw-page-faults-maj"},
    {PERF_COUNT_SW_ALIGNMENT_FAULTS, "sw-alignment-faults"},
    {PERF_COUNT_SW_EMULATION_FAULTS, "sw-emulation-faults"},
    {PERF_COUNT_SW_DUMMY, "sw-dummy"},
    {PERF_COUNT_SW_BPF_OUTPUT, "sw-bpf-output"},
};
static const ConfigTable PERF_RAW_CONFIGS = {
    {0x0, "raw-sw-incr"},
    {0x1, "raw-l1-icache-refill"},
    {0x2, "raw-l1-itlb-refill"},
    {0x3, "raw-l1-dcache-refill"},
    {0x4, "raw-l1-dcache"},
    {0x5, "raw-l1-dtlb-refill"},
    {0x6, "raw-load-retired"},
    {0x7, "raw-store-retired"},
    {0x8, "raw-instruction-retired"},
    {0x9, "raw-exception-taken"},
    {0xa, "raw-exception-return"},
    {0xb, "raw-cid-write-retired"},
    {0xc, "raw-pc-write-retired"},
    {0xd, "raw-br-immed-retired"},
    {0xe, "raw-br-return-retired"},
    {0xf, "raw-unaligned-ldst-retired"},
    {0x10, "raw-br-mis-pred"},
    {0x11, "raw-cpu-cycles"},
    {0x12, "raw-br-pred"},
    {0x13, "raw-mem-access"},
    {0x14, "raw-l1-icache"},
    {0x15, "raw-l1-dcache-wb"},
    {0x16, "raw-l2-dcache"},
    {0x17, "raw-l2-dcache-refill"},
    {0x18, "raw-l2-dcache-wb"},
    {0x19, "raw-bus-access"},
    {0x1a, "raw-memory-error"},
    {0x1b, "raw-inst-spec"},
    {0x1c, "raw-ttbr-write-retired"},
    {0x1d, "raw-bus-cycles"},
    {0x1f, "raw-l1-dcache-allocate"},
    {0x20, "raw-l2-dcache-allocate"},
    {0x21, "raw-br-retired"},
    {0x22, "raw-br-mis-pred-retired"},
    {0x23, "raw-stall-frontend"},
    {0x24, "raw-stall-backend"},
    {0x25, "raw-l1-dtlb"},
    {0x26, "raw-l1-itlb"},
    {0x27, "raw-l2-icache"},
    {0x28, "raw-l2-icache-refill"},
    {0x29, "raw-l3-dcache-allocate"},
    {0x2a, "raw-l3-dcache-refill"},
    {0x2b, "raw-l3-dcache"},
    {0x2c, "raw-l3-dcache-wb"},
    {0x2d, "raw-l2-dtlb-refill"},
    {0x2e, "raw-l2-itlb-refill"},
    {0x2f, "raw-l2-dtlb"},
    {0x30, "raw-l2-itlb"},
};
static ConfigTable PERF_TRACEPOINT_CONFIGS = {

};

static const std::map<perf_type_id, std::string> PERF_TYPES = {
    {PERF_TYPE_HARDWARE, "hardware"},
    {PERF_TYPE_SOFTWARE, "software"},
    {PERF_TYPE_TRACEPOINT, "tracepoint"},
    {PERF_TYPE_HW_CACHE, "hardware cache"},
    {PERF_TYPE_RAW, "raw"},
};

static std::map<perf_type_id, ConfigTable> TYPE_CONFIGS = {
    {PERF_TYPE_HARDWARE, (PERF_HW_CONFIGS)},           {PERF_TYPE_SOFTWARE, (PERF_SW_CONFIGS)},
    {PERF_TYPE_HW_CACHE, (PERF_HW_CACHE_CONFIGS)},     {PERF_TYPE_RAW, (PERF_RAW_CONFIGS)},
    {PERF_TYPE_TRACEPOINT, (PERF_TRACEPOINT_CONFIGS)},
};

// default config
static const std::vector<__u64> DEFAULT_HW_CONFIGS = {
    PERF_COUNT_HW_CPU_CYCLES,
#if defined(__aarch64__)
    PERF_COUNT_HW_STALLED_CYCLES_FRONTEND,
    PERF_COUNT_HW_STALLED_CYCLES_BACKEND,
#endif
    PERF_COUNT_HW_INSTRUCTIONS,
    PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
    PERF_COUNT_HW_BRANCH_MISSES,
};
static const std::vector<__u64> DEFAULT_SW_CONFIGS = {
    PERF_COUNT_SW_TASK_CLOCK,
    PERF_COUNT_SW_CONTEXT_SWITCHES,
    PERF_COUNT_SW_PAGE_FAULTS,
};
static const std::map<perf_type_id, std::vector<__u64>> DEFAULT_TYPE_CONFIGS = {
    {PERF_TYPE_HARDWARE, DEFAULT_HW_CONFIGS},
    {PERF_TYPE_SOFTWARE, DEFAULT_SW_CONFIGS},
};

struct read_format_event {
    __u64 value; /* The value of the event */
    __u64 id;    /* if PERF_FORMAT_ID */
};

struct read_format_group {
    __u64 nr;           /* The number of events */
    __u64 time_enabled; /* if PERF_FORMAT_TOTAL_TIME_ENABLED */
    __u64 time_running; /* if PERF_FORMAT_TOTAL_TIME_RUNNING */
    read_format_event events[1];
};

struct read_format_no_group {
    __u64 value;        /* The value of the event */
    __u64 time_enabled; /* if PERF_FORMAT_TOTAL_TIME_ENABLED */
    __u64 time_running; /* if PERF_FORMAT_TOTAL_TIME_RUNNING */
    __u64 id;           /* if PERF_FORMAT_ID */
};

class PerfEvents {
public:
    static constexpr uint64_t DEFAULT_SAMPLE_FREQUNCY = 4000;
    static constexpr uint64_t DEFAULT_SAMPLE_PERIOD = 1;
    static constexpr uint64_t DEFAULT_TIMEOUT = 10 * 1000;
    static constexpr size_t MIN_BUFFER_SIZE = 64 * 1024 * 1024;
#ifdef LITTLE_MEMORY
    static constexpr size_t MAX_BUFFER_SIZE = 128 * 1024 * 1024;
#else
    static constexpr size_t MAX_BUFFER_SIZE = 256 * 1024 * 1024;
#endif
    static constexpr size_t BUFFER_LOW_LEVEL = 10 * 1024 * 1024;
    static constexpr size_t BUFFER_CRITICAL_LEVEL = 5 * 1024 * 1024;

    PerfEvents();
    ~PerfEvents();

    bool AddEvents(const std::vector<std::string> &eventStrings, bool group = false);
    bool PrepareTracking(void);
    bool StartTracking(bool immediately = true);
    bool StopTracking(void);
    bool PauseTracking(void);
    bool ResumeTracking(void);
    /* call sequence
       1. setXXX
       2. AddEvents()
       3. PrepareTracking
       4. StartTracking (blocking...)
    */
    bool EnableTracking();
    bool IsTrackRunning();

    void SetSystemTarget(bool);
    void SetCpu(const std::vector<pid_t> cpus); // cpu id must be [0~N]
    void SetPid(const std::vector<pid_t> pids); // tis is same as pid in kernel
    void SetTimeOut(float timeOut);
    void SetTimeReport(int);
    void SetVerboseReport(bool);
    bool AddOffCpuEvent();

    inline void SetTrackedCommand(const std::vector<std::string> &trackedCommand)
    {
        if (!trackedCommand.empty()) {
            trackedCommand_ = TrackedCommand::CreateInstance(trackedCommand);
        }
    }

    void SetSampleFrequency(unsigned int frequency);
    void SetSamplePeriod(unsigned int period);

    enum SampleStackType {
        NONE,
        FP,
        DWARF,
    };
    void SetSampleStackType(SampleStackType type);
    void SetDwarfSampleStackSize(uint32_t stackSize);
    void SetMmapPages(size_t mmapPages);
    std::vector<AttrWithId> GetAttrWithId() const;

    void SetInherit(bool inherit)
    {
        inherit_ = inherit;
    };
    void SetClockId(int clockId)
    {
        clockId_ = clockId;
    };
    bool SetBranchSampleType(uint64_t value);
    bool AddDefaultEvent(perf_type_id type);

    std::map<__u64, std::string> GetSupportEvents(perf_type_id type);

    struct CountEvent {
        bool userOnly = false;
        bool kernelOnly = false;
        __u64 eventCount = 0;
        __u64 time_enabled = 0;
        __u64 time_running = 0;
        __u64 id = 0;
        double used_cpus = 0;
    };
    using StatCallBack =
        std::function<void(const std::map<std::string, std::unique_ptr<PerfEvents::CountEvent>> &)>;
    using RecordCallBack = std::function<bool(std::unique_ptr<PerfEventRecord>)>;

    void SetStatCallBack(StatCallBack reportCallBack);
    void SetRecordCallBack(RecordCallBack recordCallBack);
    void GetLostSamples(size_t &lostSamples, size_t &lostNonSamples)
    {
        lostSamples = lostSamples_;
        lostNonSamples = lostNonSamples_;
    }

    // review: remove this function.
    static const std::string GetStaticConfigName(perf_type_id type_id, __u64 config_id)
    {
        auto typeConfigs = TYPE_CONFIGS.find(type_id);
        if (typeConfigs != TYPE_CONFIGS.end()) {
            auto configs = typeConfigs->second;
            auto config = configs.find(config_id);
            if (config != configs.end()) {
                return config->second;
            } else {
                HLOGW("config not found for %u:%lld in %zu:%zu", type_id, config_id,
                      TYPE_CONFIGS.size(), configs.size());
                // dump all config size
                for (auto types : TYPE_CONFIGS) {
                    HLOGV("type id %d %zu", types.first, types.second.size());
                }
            }
        } else {
            HLOGW("type not found for %d  in %zu", type_id, TYPE_CONFIGS.size());
        }
        return "<not found>";
    };

    const std::string GetTraceConfigName(__u64 config_id)
    {
        auto config = traceConfigTable.find(config_id);
        if (config != traceConfigTable.end()) {
            return config->second;
        } else {
            HLOGW("config not found for %lld in traceConfigTable.", config_id);
        }
        return "<not found>";
    };

    static const std::string GetTypeName(perf_type_id type_id);
    bool ParseEventName(const std::string &nameStr, std::string &name, bool &excludeUser,
                        bool &excludeKernel, bool &isTracePoint);

    // mmap one fd for each cpu
    struct MmapFd {
        int fd;
        perf_event_mmap_page *mmapPage = nullptr;
        uint8_t *buf = nullptr;
        size_t bufSize = 0;
        // for read and sort
        size_t dataSize = 0;
        perf_event_header header;
        uint64_t timestamp = 0;
        const perf_event_attr *attr = nullptr;
        size_t posCallChain = 0;
    };

private:
    size_t recordEventCount_ = 0; // only for debug time
#ifdef HIPERF_DEBUG_TIME
    std::chrono::microseconds recordCallBackTime_ = std::chrono::microseconds::zero();
    std::chrono::microseconds recordWaitDataTime_ = std::chrono::microseconds::zero();
    std::chrono::microseconds recordSleepTime_ = std::chrono::microseconds::zero();
    std::chrono::microseconds recordKernelReadTime_ = std::chrono::microseconds::zero();
#endif
    size_t lostSamples_ = 0;
    size_t lostNonSamples_ = 0;

    std::unique_ptr<RingBuffer> recordBuf_ {nullptr};
    bool recordBufReady_ = false;
    std::mutex mtxRrecordBuf_;
    std::condition_variable cvRecordBuf_;
    std::thread readRecordBufThread_;
    std::atomic_bool readRecordThreadRunning_ = false;
    bool startedTracking_ = false;
    bool isLowPriorityThread_ = false;
    void RecordLoop();
    void StatLoop();
    bool IsRecordInMmap();
    void ReadRecordsFromMmaps();
    bool GetRecordFromMmap(MmapFd &mmap);
    void GetRecordFieldFromMmap(MmapFd &mmap, void *dest, size_t pos, size_t size);
    void MoveRecordToBuf(MmapFd &mmap);
    size_t GetCallChainPosInSampleRecord(const perf_event_attr &attr);
    size_t GetStackSizePosInSampleRecord(MmapFd &mmap);
    bool CutStackAndMove(MmapFd &mmap);
    void ReadRecordFromBuf();
    size_t CalcBufferSize();
    bool PrepareRecordThread();
    void WaitRecordThread();
    bool HaveTargetsExit(const std::chrono::steady_clock::time_point &startTime);
    void ExitReadRecordBufThread();

    enum EventSpaceType {
        UNKNOW = 0,
        USER = 1,
        KERNEL = 2,
        USER_KERNEL = 3,
    };
    uint8_t eventSpaceType_ = EventSpaceType::UNKNOW;

    bool inherit_ = false;
    std::vector<pid_t> pids_;
    std::vector<pid_t> cpus_;
    std::vector<OHOS::UniqueFd> groups_;
    std::chrono::milliseconds timeOut_;    // milliseconds
    std::chrono::milliseconds timeReport_; // means same as timeOut
    bool verboseReport_ = false;
    bool prepared_ = false;
    ConfigTable traceConfigTable;

    unsigned int samplePeriod_ = 0;
    unsigned int sampleFreq_ = 0;

    struct FdItem {
        OHOS::UniqueFd fd;
        int cpu;
        pid_t pid;
        __u64 eventCount;
        mutable uint64_t perf_id_ = 0;
        uint64_t GetPrefId() const
        {
            if (perf_id_ == 0) {
                read_format_no_group readNoGroupValue;
                if (read(fd, &readNoGroupValue, sizeof(readNoGroupValue)) > 0) {
                    perf_id_ = readNoGroupValue.id;
                } else {
                    HLOGW("read failed with fd %d", fd.Get());
                }
            }
            return perf_id_;
        }
    };
    struct EventItem {
        std::string typeName;
        std::string configName;
        perf_event_attr attr = {};
        std::vector<FdItem> fdItems;
    };
    struct EventGroupItem {
        std::vector<EventItem> eventItems;
    };
    std::vector<EventGroupItem> eventGroupItem_;

    std::map<int, MmapFd> cpuMmap_;
    std::vector<MmapFd *> MmapRecordHeap_;

#if !is_mingw
    std::vector<struct pollfd> pollFds_;
#endif
    const int pollTimeOut_ = 500; // ms
    size_t pageSize_ = 4096;
    bool systemTarget_ = false;
    bool excludeHiperf_ = false;
    pid_t selfPid_ = -1;
    unsigned int mmapPages_ = 0;
    int clockId_ = -1;
    uint64_t branchSampleType_ = 0;

    SampleStackType sampleStackType_ = SampleStackType::NONE;
    uint32_t dwarfSampleStackSize_ = MAX_SAMPLE_STACK_SIZE;

    // read records from the ring buffer singleton
    void ReadRecordFromBuffer();
    void ReadRecordFromBufferThread();

    std::unique_ptr<TrackedCommand> trackedCommand_ = {};

    StatCallBack reportCallBack_;
    RecordCallBack recordCallBack_;

    void LoadTracepointEventTypesFromSystem();
    bool PerfEventsEnable(bool);
    bool AddEvent(perf_type_id type, __u64 config, bool excludeUser = false,
                  bool excludeKernel = false, bool followGroup = false);
    bool AddEvent(const std::string &eventString, bool followGroup = false);
    bool IsEventSupport(perf_type_id type, __u64 config);
    bool IsEventAttrSupport(perf_event_attr &attr);

    std::chrono::time_point<std::chrono::steady_clock> trackingStartTime_;
    std::chrono::time_point<std::chrono::steady_clock> trackingEndTime_;
    std::chrono::time_point<std::chrono::steady_clock> readingStartTime_;

    std::map<std::string, std::unique_ptr<CountEvent>> countEvents_;

    void PutAllCpus();
    bool PrepareFdEvents();
    bool CreateFdEvents();
    bool StatReport(const __u64 &durationInSec);
    bool CreateMmap(const FdItem &item, const perf_event_attr &attr);

    const perf_event_attr *GetDefaultAttr()
    {
        HLOG_ASSERT(eventGroupItem_.size() > 0);
        HLOG_ASSERT(eventGroupItem_[0].eventItems.size() > 0);
        return &(eventGroupItem_.at(0).eventItems.at(0).attr);
    };

    OHOS::UniqueFd Open(perf_event_attr &attr, pid_t pid = 0, int cpu = -1, int group_fd = -1,
                        unsigned long flags = 0);
    std::unique_ptr<perf_event_attr> CreateDefaultAttr(perf_type_id type, __u64 config);
};
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_PERF_EVENTS_H
