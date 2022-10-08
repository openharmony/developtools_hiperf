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
#ifndef HIPERF_PERF_EVENT_RECORD_H
#define HIPERF_PERF_EVENT_RECORD_H

#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <stdint.h>
#include <string>
#include <sys/types.h>
#include <unique_fd.h>
#include <variant>
#include <vector>
#include <linux/perf_event.h>
#include <linux/types.h>

#include "debug_logger.h"
#include "mem_map_item.h"
#include "perf_record_format.h"
#include "utilities.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
static constexpr uint32_t RECORD_SIZE_LIMIT = 65535;

enum perf_event_hiperf_ext_type {
    PERF_RECORD_HIPERF_CALLSTACK = UINT32_MAX / 2,
};

struct CallFrame {
    uint64_t ip_ = 0;
    uint64_t sp_ = 0;
    int32_t symbolFileIndex_ = -1; // symbols file index, used to report protobuf file
    uint64_t vaddrInFile_ = 0; // vaddr of symbol in file
    uint64_t offsetToVaddr_ = 0; // offset of ip to vaddr
    int32_t symbolIndex_ = -1; // symbols index , should update after sort
    std::string_view symbolName_;
    std::string_view filePath_; // lib path , elf path

    CallFrame(uint64_t ip, uint64_t sp = 0) : ip_(ip), sp_(sp) {}

    // this is for ut test
    CallFrame(uint64_t ip, uint64_t vaddrInFile, const char *name, const char *filePath)
        : ip_(ip), vaddrInFile_(vaddrInFile), symbolName_(name), filePath_(filePath)
    {
    }
    bool operator==(const CallFrame &b) const
    {
        return (ip_ == b.ip_) && (sp_ == b.sp_);
    }
    bool operator!=(const CallFrame &b) const
    {
        return (ip_ != b.ip_) || (sp_ != b.sp_);
    }
    std::string ToString() const
    {
        return StringPrintf("ip: 0x%016llx sp: 0x%016llx", ip_, sp_);
    }
    std::string ToSymbolString() const
    {
        std::string output = StringPrintf(" 0x%016llx : ", ip_);
        output.append(symbolName_);
        if (vaddrInFile_ != 0) {
            output += StringPrintf("[0x%016llx:0x%016llx][+0x%llx]", ip_ - offsetToVaddr_,
                vaddrInFile_, offsetToVaddr_);
        }

        output.append("@");
        output.append(filePath_);
        if (symbolIndex_ != -1) {
            output.append(":");
            output.append(std::to_string(symbolIndex_));
        }
        return output;
    }
};

struct AttrWithId {
    perf_event_attr attr;
    std::vector<uint64_t> ids;
    std::string name; // will be empty in GetAttrSection
};

class PerfEventRecord {
public:
    PerfEventRecord(const PerfEventRecord &) = delete;
    PerfEventRecord &operator=(const PerfEventRecord &) = delete;

    struct perf_event_header header;
    const std::string name_ {};

    PerfEventRecord(perf_event_type type, bool in_kernel, const std::string &name);
    PerfEventRecord(perf_event_hiperf_ext_type type, const std::string &name);

    PerfEventRecord(uint8_t *p, const std::string &name);

    virtual ~PerfEventRecord() {}

    virtual size_t GetSize() const
    {
        return header.size;
    };
    size_t GetHeaderSize() const
    {
        return sizeof(header);
    };
    void GetHeaderBinary(std::vector<uint8_t> &buf) const;

    uint32_t GetType() const
    {
        return header.type;
    };
    uint16_t GetMisc() const
    {
        return header.misc;
    };
    bool inKernel()
    {
        return header.misc & PERF_RECORD_MISC_KERNEL;
    }
    bool inUser()
    {
        return header.misc & PERF_RECORD_MISC_USER;
    }
    const std::string &GetName() const
    {
        return name_;
    };

    // to support --exclude-hiperf, return sample_id.pid to filter record,
    virtual pid_t GetPid() const
    {
        return 0;
    };

    virtual bool GetBinary(std::vector<uint8_t> &buf) const = 0;
    void Dump(int indent = 0) const;
    virtual void DumpData(int indent) const = 0;
    virtual void DumpLog(const std::string &prefix) const;
};

// define convert from linux/perf_event.h
// description from https://man7.org/linux/man-pages/man2/perf_event_open.2.html

constexpr __u64 SAMPLE_ID = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ID |
                            PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_IDENTIFIER;

constexpr __u64 SAMPLE_TYPE = PERF_SAMPLE_IP | SAMPLE_ID | PERF_SAMPLE_PERIOD;

constexpr __u32 MIN_SAMPLE_STACK_SIZE = 8;
constexpr __u32 MAX_SAMPLE_STACK_SIZE = 65528;

class PerfRecordMmap : public PerfEventRecord {
public:
    PerfRecordMmapData data_;

    explicit PerfRecordMmap(uint8_t *p);

    PerfRecordMmap(bool inKernel, u32 pid, u32 tid, u64 addr, u64 len, u64 pgoff,
                   const std::string &filename);

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
    void DumpLog(const std::string &prefix) const override;
};

class PerfRecordMmap2 : public PerfEventRecord {
public:
    PerfRecordMmap2Data data_;

    explicit PerfRecordMmap2(uint8_t *p);

    PerfRecordMmap2(bool inKernel, u32 pid, u32 tid, u64 addr, u64 len, u64 pgoff, u32 maj, u32 min,
                    u64 ino, u32 prot, u32 flags, const std::string &filename);

    PerfRecordMmap2(bool inKernel, u32 pid, u32 tid, const MemMapItem &item);

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
    void DumpLog(const std::string &prefix) const override;
};

class PerfRecordLost : public PerfEventRecord {
public:
    PerfRecordLostData data_;

    explicit PerfRecordLost(uint8_t *p);

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;

    // only for UT
    PerfRecordLost(bool inKernel, u64 id, u64 lost)
        : PerfEventRecord(PERF_RECORD_LOST, inKernel, "lost")
    {
        data_.id = id;
        data_.lost = lost;
        header.size = sizeof(header) + sizeof(data_);
    }
};

class PerfRecordComm : public PerfEventRecord {
public:
    PerfRecordCommData data_;

    explicit PerfRecordComm(uint8_t *p);

    PerfRecordComm(bool inKernel, u32 pid, u32 tid, const std::string &comm);

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
    void DumpLog(const std::string &prefix) const override;
};

class PerfRecordSample : public PerfEventRecord {
public:
    PerfRecordSampleData data_ = {};
    uint64_t sampleType_ = SAMPLE_TYPE;

    // extend
    // hold the new ips memory (after unwind)
    // used for data_.ips replace (ReplaceWithCallStack)
    std::vector<u64> ips_;
    std::vector<CallFrame> callFrames_;

    // referenced input(p) in PerfRecordSample, require caller keep input(p) together
    PerfRecordSample(uint8_t *p, const perf_event_attr &attr);
    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent = 0) const override;
    void DumpLog(const std::string &prefix) const override;

    // originalSize is use for expand callstack
    void ReplaceWithCallStack(size_t originalSize = 0);
    pid_t GetPid() const override;

    // only for UT
    PerfRecordSample(bool inKernel, u32 pid, u32 tid, u64 period = 0, u64 time = 0, u64 id = 0)
        : PerfEventRecord(PERF_RECORD_SAMPLE, inKernel, "sample")
    {
        data_.pid = pid;
        data_.tid = tid;
        data_.period = period;
        data_.time = time;
        data_.id = 0;
        header.size = sizeof(header) + sizeof(data_);
    };
};

class PerfRecordExit : public PerfEventRecord {
public:
    PerfRecordExitData data_;

    explicit PerfRecordExit(uint8_t *p);

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
};

class PerfRecordThrottle : public PerfEventRecord {
public:
    PerfRecordThrottleData data_;

    PerfRecordThrottle(uint8_t *p);

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
};

class PerfRecordUnthrottle : public PerfEventRecord {
public:
    PerfRecordThrottleData data_;

    explicit PerfRecordUnthrottle(uint8_t *p);

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
};

class PerfRecordFork : public PerfEventRecord {
public:
    PerfRecordForkData data_;

    explicit PerfRecordFork(uint8_t *p);

    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
};

/*
    This record indicates a read event.
*/
class PerfRecordRead : public PerfEventRecord {
public:
    PerfRecordReadData data_;

    explicit PerfRecordRead(uint8_t *p);
    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
};

/*
    This record reports that new data is available in the
    separate AUX buffer region.

    aux_offset
            offset in the AUX mmap region where the new
            data begins.
    aux_size
            size of the data made available.
    flags  describes the AUX update.
            PERF_AUX_FLAG_TRUNCATED
                if set, then the data returned was
                truncated to fit the available buffer
                size.

            PERF_AUX_FLAG_OVERWRITE
                if set, then the data returned has
                overwritten previous data.
*/
class PerfRecordAux : public PerfEventRecord {
public:
    PerfRecordAuxData data_;

    explicit PerfRecordAux(uint8_t *p);
    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
};

/*
    This record indicates which process has initiated an
    instruction trace event, allowing tools to properly
    correlate the instruction addresses in the AUX buffer
    with the proper executable.

    pid    process ID of the thread starting an
            instruction trace.
    tid    thread ID of the thread starting an instruction
            trace.
*/
class PerfRecordItraceStart : public PerfEventRecord {
public:
    PerfRecordItraceStartData data_;

    explicit PerfRecordItraceStart(uint8_t *p);
    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
};

/*
    When using hardware sampling (such as Intel PEBS) this
    record indicates some number of samples that may have
    been lost.
*/
class PerfRecordLostSamples : public PerfEventRecord {
public:
    PerfRecordLostSamplesData data_;

    explicit PerfRecordLostSamples(uint8_t *p);
    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
};

/*
    This record indicates a context switch has happened.
    The PERF_RECORD_MISC_SWITCH_OUT bit in the misc field
    indicates whether it was a context switch into or away
    from the current process.
*/
class PerfRecordSwitch : public PerfEventRecord {
public:
    PerfRecordSwitchData data_;
    explicit PerfRecordSwitch(uint8_t *p);
    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData([[maybe_unused]] int indent) const override {};
};

/*
    As with PERF_RECORD_SWITCH this record indicates a
    context switch has happened, but it only occurs when
    sampling in CPU-wide mode and provides additional
    information on the process being switched to/from.
    The PERF_RECORD_MISC_SWITCH_OUT bit in the misc field
    indicates whether it was a context switch into or away
    from the current process.

    next_prev_pid
            The process ID of the previous (if switching
            in) or next (if switching out) process on the
            CPU.

    next_prev_tid
            The thread ID of the previous (if switching in)
            or next (if switching out) thread on the CPU.
*/
class PerfRecordSwitchCpuWide : public PerfEventRecord {
public:
    PerfRecordSwitchCpuWideData data_;
    explicit PerfRecordSwitchCpuWide(uint8_t *p);
    bool GetBinary(std::vector<uint8_t> &buf) const override;
    void DumpData(int indent) const override;
};

std::unique_ptr<PerfEventRecord> GetPerfEventRecord(const int type, uint8_t *data,
                                                    const perf_event_attr &attr);

template<typename T>
void PushToBinary(bool condition, uint8_t *&p, const T &v);

template<typename T1, typename T2>
void PushToBinary2(bool condition, uint8_t *&p, const T1 &v1, const T2 &v2);

template<typename T>
void PopFromBinary(bool condition, uint8_t *&p, T &v);

template<typename T1, typename T2>
void PopFromBinary2(bool condition, uint8_t *&p, T1 &v1, T2 &v2);
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_PERF_EVENT_RECORD_H
