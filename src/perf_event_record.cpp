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
#define HILOG_TAG "PerfRecord"

#include "perf_event_record.h"
#include <cinttypes>
#include "utilities.h"


using namespace std;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
std::unique_ptr<PerfEventRecord> GetPerfEventRecord(const int type, uint8_t *p,
                                                    const perf_event_attr &attr)
{
    HLOG_ASSERT(p);
    uint8_t *data = p;

    // check kernel
    switch (type) {
        case PERF_RECORD_SAMPLE:
            return std::make_unique<PerfRecordSample>(data, attr);
        case PERF_RECORD_MMAP:
            return std::make_unique<PerfRecordMmap>(data);
        case PERF_RECORD_MMAP2:
            return std::make_unique<PerfRecordMmap2>(data);
        case PERF_RECORD_LOST:
            return std::make_unique<PerfRecordLost>(data);
        case PERF_RECORD_COMM:
            return std::make_unique<PerfRecordComm>(data);
        case PERF_RECORD_EXIT:
            return std::make_unique<PerfRecordExit>(data);
        case PERF_RECORD_THROTTLE:
            return std::make_unique<PerfRecordThrottle>(data);
        case PERF_RECORD_UNTHROTTLE:
            return std::make_unique<PerfRecordUnthrottle>(data);
        case PERF_RECORD_FORK:
            return std::make_unique<PerfRecordFork>(data);
        case PERF_RECORD_READ:
            return std::make_unique<PerfRecordRead>(data);
        case PERF_RECORD_AUX:
            return std::make_unique<PerfRecordAux>(data);
        case PERF_RECORD_ITRACE_START:
            return std::make_unique<PerfRecordItraceStart>(data);
        case PERF_RECORD_LOST_SAMPLES:
            return std::make_unique<PerfRecordLostSamples>(data);
        case PERF_RECORD_SWITCH:
            return std::make_unique<PerfRecordSwitch>(data);
        case PERF_RECORD_SWITCH_CPU_WIDE:
            return std::make_unique<PerfRecordSwitchCpuWide>(data);
        default:
            HLOGE("unknown record type %d\n", type);
            return nullptr;
    }
}

template<typename T>
inline void PushToBinary(bool condition, uint8_t *&p, const T &v)
{
    if (condition) {
        *(reinterpret_cast<T *>(p)) = v;
        p += sizeof(T);
    }
}

template<typename T1, typename T2>
inline void PushToBinary2(bool condition, uint8_t *&p, const T1 &v1, const T2 &v2)
{
    if (condition) {
        *(reinterpret_cast<T1 *>(p)) = v1;
        p += sizeof(T1);
        *(reinterpret_cast<T2 *>(p)) = v2;
        p += sizeof(T2);
    }
}

template<typename T>
inline void PopFromBinary(bool condition, uint8_t *&p, T &v)
{
    if (condition) {
        v = *(reinterpret_cast<const T *>(p));
        p += sizeof(T);
    }
}

template<typename T1, typename T2>
inline void PopFromBinary2(bool condition, uint8_t *&p, T1 &v1, T2 &v2)
{
    if (condition) {
        v1 = *(reinterpret_cast<const T1 *>(p));
        p += sizeof(T1);
        v2 = *(reinterpret_cast<const T2 *>(p));
        p += sizeof(T2);
    }
}

// PerfEventRecord
PerfEventRecord::PerfEventRecord(perf_event_type type, bool in_kernel, const std::string &name)
    : name_(name)
{
    header.type = type;
    header.misc = in_kernel ? PERF_RECORD_MISC_KERNEL : PERF_RECORD_MISC_USER;
    header.size = sizeof(header);
}

PerfEventRecord::PerfEventRecord(perf_event_hiperf_ext_type type, const std::string &name)
    : name_(name)
{
    header.type = type;
    header.misc = PERF_RECORD_MISC_USER;
    header.size = sizeof(header);
}

PerfEventRecord::PerfEventRecord(uint8_t *p, const std::string &name) : name_(name)
{
    header = *(reinterpret_cast<perf_event_header *>(p));
}

void PerfEventRecord::GetHeaderBinary(std::vector<uint8_t> &buf) const
{
    if (buf.size() < GetHeaderSize()) {
        buf.resize(GetHeaderSize());
    }
    uint8_t *p = buf.data();
    *(reinterpret_cast<perf_event_header *>(p)) = header;
}

void PerfEventRecord::Dump(int indent) const
{
    PrintIndent(indent, "\n");
    PrintIndent(indent, "record %s: type %u, misc %u, size %zu\n", GetName().c_str(), GetType(),
                GetMisc(), GetSize());
    DumpData(indent + 1);
}

void PerfEventRecord::DumpLog(const std::string &prefix) const
{
    HLOGV("%s: record %s: type %u, misc %u, size %zu\n", prefix.c_str(), GetName().c_str(),
          GetType(), GetMisc(), GetSize());
}

void PerfRecordSample::DumpLog(const std::string &prefix) const
{
    HLOGV("%s: SAMPLE: id= %llu size %d pid %u tid %u ips %llu regs %llu, stacks %llu time %llu",
          prefix.c_str(), data_.sample_id, header.size, data_.pid, data_.tid, data_.nr,
          data_.reg_nr, data_.dyn_size, data_.time);
}

void PerfRecordSample::ReplaceWithCallStack(size_t originalSize)
{
    // first we check if we have some user unwind stack need to merge ?
    if (callFrames_.size() != 0) {
        // when we have some kernel ips , we cp it first
        // new size is user call frames + kernel call frames
        // + PERF_CONTEXT_USER(last + 1) + expand mark(also PERF_CONTEXT_USER)
        const unsigned int perfContextSize = 2;
        ips_.reserve(data_.nr + callFrames_.size() + perfContextSize);
        if (data_.nr > 0) {
            ips_.assign(data_.ips, data_.ips + data_.nr);
        }
        // add user context mark
        ips_.emplace_back(PERF_CONTEXT_USER);
        // we also need make a expand mark just for debug only
        const size_t beginIpsSize = ips_.size();
        bool ret = std::all_of(callFrames_.begin(), callFrames_.end(), [&](const CallFrame &frame) {
            ips_.emplace_back(frame.ip_);
            if (originalSize != 0 and (originalSize != callFrames_.size()) and
                ips_.size() == (originalSize + beginIpsSize)) {
                // just for debug
                // so we can see which frame begin is expand call frames
                ips_.emplace_back(PERF_CONTEXT_USER);
            }
            return true;
        });
        if (ret) {
            HLOGV("combed %zu", callFrames_.size());
        } else {
            HLOGV("failed to combed %zu", callFrames_.size());
        }

        if (sampleType_ & PERF_SAMPLE_REGS_USER) {
            data_.reg_nr = 0;
            header.size -= data_.reg_nr * sizeof(u64);
        }

        if (sampleType_ & PERF_SAMPLE_STACK_USER) {
            // 1. remove the user stack
            header.size -= data_.stack_size;

            // 2. clean the size
            data_.user_abi = 0;
            data_.stack_size = 0;
            data_.dyn_size = 0;
        }

        if (sampleType_ & PERF_SAMPLE_CALLCHAIN) {
            HLOGV("ips change from %llu -> %zu", data_.nr, ips_.size());

            // 3. remove the nr size
            header.size -= data_.nr * sizeof(u64);

            // 4. add new nr size
            data_.nr = ips_.size();
            header.size += data_.nr * sizeof(u64);

            // 5. change ips potin to our ips array and hold it.
            data_.ips = ips_.data();
        }
    } else {
        // nothing need change
        return;
    }
}

PerfRecordSample::PerfRecordSample(uint8_t *p, const perf_event_attr &attr)
    : PerfEventRecord(p, "sample")
{
    if (p == nullptr) {
        HLOG_ASSERT(p);
        return;
    }
    sampleType_ = attr.sample_type;

    p += sizeof(header);

    // parse record according SAMPLE_TYPE
    PopFromBinary(sampleType_ & PERF_SAMPLE_IDENTIFIER, p, data_.sample_id);
    PopFromBinary(sampleType_ & PERF_SAMPLE_IP, p, data_.ip);
    PopFromBinary2(sampleType_ & PERF_SAMPLE_TID, p, data_.pid, data_.tid);
    PopFromBinary(sampleType_ & PERF_SAMPLE_TIME, p, data_.time);
    PopFromBinary(sampleType_ & PERF_SAMPLE_ADDR, p, data_.addr);
    PopFromBinary(sampleType_ & PERF_SAMPLE_ID, p, data_.id);
    PopFromBinary(sampleType_ & PERF_SAMPLE_STREAM_ID, p, data_.stream_id);
    PopFromBinary2(sampleType_ & PERF_SAMPLE_CPU, p, data_.cpu, data_.res);
    PopFromBinary(sampleType_ & PERF_SAMPLE_PERIOD, p, data_.period);
    PopFromBinary(sampleType_ & PERF_SAMPLE_CALLCHAIN, p, data_.nr);
    if (data_.nr > 0) {
        // the pointer is from input(p), require caller keep input(p) with *this together
        // think it in next time
        data_.ips = reinterpret_cast<u64 *>(p);
        p += data_.nr * sizeof(u64);
    }
    PopFromBinary(sampleType_ & PERF_SAMPLE_RAW, p, data_.raw_size);
    if (data_.raw_size > 0) {
        data_.raw_data = p;
        p += data_.raw_size * sizeof(u8);
    }
    PopFromBinary(sampleType_ & PERF_SAMPLE_BRANCH_STACK, p, data_.bnr);
    if (data_.bnr > 0) {
        data_.lbr = reinterpret_cast<perf_branch_entry *>(p);
        p += data_.bnr * sizeof(perf_branch_entry);
    }
    PopFromBinary(sampleType_ & PERF_SAMPLE_REGS_USER, p, data_.user_abi);
    if (data_.user_abi > 0) {
        data_.reg_mask = attr.sample_regs_user;
        data_.reg_nr = __builtin_popcountll(data_.reg_mask);
        data_.user_regs = reinterpret_cast<u64 *>(p);
        p += data_.reg_nr * sizeof(u64);
    }
    PopFromBinary(sampleType_ & PERF_SAMPLE_STACK_USER, p, data_.stack_size);
    if (data_.stack_size > 0) {
        data_.stack_data = p;
        p += data_.stack_size;
        PopFromBinary(true, p, data_.dyn_size);
    }
}

bool PerfRecordSample::GetBinary(std::vector<uint8_t> &buf) const
{
    if (buf.size() < GetSize()) {
        buf.resize(GetSize());
    }

    GetHeaderBinary(buf);
    uint8_t *p = buf.data() + GetHeaderSize();

    PushToBinary(sampleType_ & PERF_SAMPLE_IDENTIFIER, p, data_.sample_id);
    PushToBinary(sampleType_ & PERF_SAMPLE_IP, p, data_.ip);
    PushToBinary2(sampleType_ & PERF_SAMPLE_TID, p, data_.pid, data_.tid);
    PushToBinary(sampleType_ & PERF_SAMPLE_TIME, p, data_.time);
    PushToBinary(sampleType_ & PERF_SAMPLE_ADDR, p, data_.addr);
    PushToBinary(sampleType_ & PERF_SAMPLE_ID, p, data_.id);
    PushToBinary(sampleType_ & PERF_SAMPLE_STREAM_ID, p, data_.stream_id);
    PushToBinary2(sampleType_ & PERF_SAMPLE_CPU, p, data_.cpu, data_.res);
    PushToBinary(sampleType_ & PERF_SAMPLE_PERIOD, p, data_.period);
    PushToBinary(sampleType_ & PERF_SAMPLE_CALLCHAIN, p, data_.nr);
    if (data_.nr > 0) {
        std::copy(data_.ips, data_.ips + data_.nr, reinterpret_cast<u64 *>(p));
        p += data_.nr * sizeof(u64);
    }
    PushToBinary(sampleType_ & PERF_SAMPLE_RAW, p, data_.raw_size);
    if (data_.raw_size > 0) {
        std::copy(data_.raw_data, data_.raw_data + data_.raw_size, p);
        p += data_.raw_size * sizeof(u8);
    }
    PushToBinary(sampleType_ & PERF_SAMPLE_BRANCH_STACK, p, data_.bnr);
    if (data_.bnr > 0) {
        std::copy(data_.lbr, data_.lbr + data_.bnr, reinterpret_cast<perf_branch_entry *>(p));
        p += data_.bnr * sizeof(perf_branch_entry);
    }
    PushToBinary(sampleType_ & PERF_SAMPLE_REGS_USER, p, data_.user_abi);
    if (data_.user_abi > 0 && data_.reg_nr > 0) {
        std::copy(data_.user_regs, data_.user_regs + data_.reg_nr, reinterpret_cast<u64 *>(p));
        p += data_.reg_nr * sizeof(u64);
    }
    PushToBinary(sampleType_ & PERF_SAMPLE_STACK_USER, p, data_.stack_size);
    if (data_.stack_size > 0) {
        std::copy(data_.stack_data, data_.stack_data + data_.stack_size, p);
        p += data_.stack_size * sizeof(u8);
        PushToBinary(true, p, data_.dyn_size);
    }

    return true;
}

void PerfRecordSample::DumpData(int indent) const
{
    PrintIndent(indent, "sample_type: 0x%" PRIx64 "\n", sampleType_);

    // dump record according sampleType
    if (sampleType_ & (PERF_SAMPLE_ID | PERF_SAMPLE_IDENTIFIER)) {
        PrintIndent(indent, "ID %" PRIu64 "\n", static_cast<uint64_t>(data_.sample_id));
    }
    if (sampleType_ & PERF_SAMPLE_IP) {
        PrintIndent(indent, "ip %llx\n", data_.ip);
    }
    if (sampleType_ & PERF_SAMPLE_TID) {
        PrintIndent(indent, "pid %u, tid %u\n", data_.pid, data_.tid);
    }
    if (sampleType_ & PERF_SAMPLE_TIME) {
        PrintIndent(indent, "time %llu\n", data_.time);
    }
    if (sampleType_ & PERF_SAMPLE_ADDR) {
        PrintIndent(indent, "addr %p\n", reinterpret_cast<void *>(data_.addr));
    }
    if (sampleType_ & PERF_SAMPLE_STREAM_ID) {
        PrintIndent(indent, "stream_id %" PRIu64 "\n", static_cast<uint64_t>(data_.stream_id));
    }
    if (sampleType_ & PERF_SAMPLE_CPU) {
        PrintIndent(indent, "cpu %u, res %u\n", data_.cpu, data_.res);
    }
    if (sampleType_ & PERF_SAMPLE_PERIOD) {
        PrintIndent(indent, "period %" PRIu64 "\n", static_cast<uint64_t>(data_.period));
    }
    if (sampleType_ & PERF_SAMPLE_CALLCHAIN) {
        bool userContext = false;
        PrintIndent(indent, "callchain nr=%lld\n", data_.nr);
        for (uint64_t i = 0; i < data_.nr; ++i) {
            std::string_view supplement = "";
            if ((sampleType_ & PERF_SAMPLE_STACK_USER) == 0 || data_.ips[i] != PERF_CONTEXT_USER) {
                PrintIndent(indent + 1, "0x%llx%s\n", data_.ips[i], supplement.data());
                continue;
            }
            // is PERF_SAMPLE_STACK_USER type and is PERF_CONTEXT_USER
            if (!userContext) {
                userContext = true;
                supplement = " <unwind callstack>";
            } else {
                supplement = " <expand callstack>";
            }
            PrintIndent(indent + 1, "0x%llx%s\n", data_.ips[i], supplement.data());
        }
    }
    if (sampleType_ & PERF_SAMPLE_RAW) {
        PrintIndent(indent, "raw size=%u\n", data_.raw_size);
        const uint32_t *data = reinterpret_cast<const uint32_t *>(data_.raw_data);
        size_t size = data_.raw_size / sizeof(uint32_t);
        for (size_t i = 0; i < size; ++i) {
            PrintIndent(indent + 1, "0x%08x (%x)\n", data[i], data[i]);
        }
    }
    if (sampleType_ & PERF_SAMPLE_BRANCH_STACK) {
        PrintIndent(indent, "branch_stack nr=%lld\n", data_.bnr);
        for (uint64_t i = 0; i < data_.bnr; ++i) {
            auto &item = data_.lbr[i];
            PrintIndent(indent + 1, "from 0x%llx, to 0x%llx %s%s\n", item.from, item.to,
                        item.mispred ? "mispred" : "", item.predicted ? "predicted" : "");
        }
    }
    if (sampleType_ & PERF_SAMPLE_REGS_USER) {
        PrintIndent(indent, "user regs: abi=%lld, reg_nr=%lld\n", data_.user_abi, data_.reg_nr);
        for (uint64_t i = 0; i < data_.reg_nr; ++i) {
            PrintIndent(indent + 1, "0x%llx\n", data_.user_regs[i]);
        }
    }
    if (sampleType_ & PERF_SAMPLE_STACK_USER) {
        PrintIndent(indent, "user stack: size %llu dyn_size %lld\n", data_.stack_size,
                    data_.dyn_size);
    }
}

inline pid_t PerfRecordSample::GetPid() const
{
    return data_.pid;
}

PerfRecordMmap::PerfRecordMmap(uint8_t *p) : PerfEventRecord(p, "mmap")
{
    size_t copySize = GetSize() - sizeof(header);
    if (memcpy_s((uint8_t *)&data_, sizeof(data_), p + sizeof(header), copySize) != 0) {
        HLOGE("memcpy_s retren failed !!!");
    }
}

PerfRecordMmap::PerfRecordMmap(bool inKernel, u32 pid, u32 tid, u64 addr, u64 len, u64 pgoff,
                               const std::string &filename)
    : PerfEventRecord(PERF_RECORD_MMAP, inKernel, "mmap")
{
    data_.pid = pid;
    data_.tid = tid;
    data_.addr = addr;
    data_.len = len;
    data_.pgoff = pgoff;
    if (strncpy_s(data_.filename, KILO, filename.c_str(), filename.size()) != 0) {
        HLOGE("strncpy_s failed");
    }

    header.size = sizeof(header) + sizeof(data_) - KILO + filename.size() + 1;
}

bool PerfRecordMmap::GetBinary(std::vector<uint8_t> &buf) const
{
    if (buf.size() < GetSize()) {
        buf.resize(GetSize());
    }

    GetHeaderBinary(buf);
    uint8_t *p = buf.data() + GetHeaderSize();

    // data_.filename[] is variable-length
    std::copy((uint8_t *)&data_, (uint8_t *)&data_ + GetSize() - GetHeaderSize(), p);
    return true;
}

void PerfRecordMmap::DumpData(int indent) const
{
    PrintIndent(indent, "pid %u, tid %u, addr 0x%llx, len 0x%llx\n", data_.pid, data_.tid,
                data_.addr, data_.len);
    PrintIndent(indent, "pgoff 0x%llx, filename %s\n", data_.pgoff, data_.filename);
}

void PerfRecordMmap::DumpLog(const std::string &prefix) const
{
    HLOGV("%s:  MMAP: size %d pid %u tid %u dso '%s' (0x%llx-0x%llx)@0x%llx", prefix.c_str(),
          header.size, data_.pid, data_.tid, data_.filename, data_.addr, data_.addr + data_.len,
          data_.pgoff);
}

PerfRecordMmap2::PerfRecordMmap2(uint8_t *p) : PerfEventRecord(p, "mmap2")
{
    size_t copySize = GetSize() - sizeof(header);
    if (memcpy_s((uint8_t *)&data_, sizeof(data_), p + sizeof(header), copySize) != 0) {
        HLOGE("memcpy_s retren failed !!!");
    }
}

PerfRecordMmap2::PerfRecordMmap2(bool inKernel, u32 pid, u32 tid, u64 addr, u64 len, u64 pgoff,
                                 u32 maj, u32 min, u64 ino, u32 prot, u32 flags,
                                 const std::string &filename)
    : PerfEventRecord(PERF_RECORD_MMAP2, inKernel, "mmap2")
{
    data_.pid = pid;
    data_.tid = tid;
    data_.addr = addr;
    data_.len = len;
    data_.pgoff = pgoff;
    data_.maj = maj;
    data_.min = min;
    data_.ino = ino;
    data_.ino_generation = 0;
    data_.prot = prot;
    data_.flags = flags;
    if (strncpy_s(data_.filename, KILO, filename.c_str(), filename.size()) != 0) {
        HLOGE("strncpy_s failed");
    }

    header.size = sizeof(header) + sizeof(data_) - KILO + filename.size() + 1;
}

PerfRecordMmap2::PerfRecordMmap2(bool inKernel, u32 pid, u32 tid, const MemMapItem &item)
    : PerfEventRecord(PERF_RECORD_MMAP2, inKernel, "mmap2")
{
    data_.pid = pid;
    data_.tid = tid;
    data_.addr = item.begin_;
    data_.len = item.end_ - item.begin_;
    data_.pgoff = item.pageoffset_;
    data_.maj = item.major_;
    data_.min = item.minor_;
    data_.ino = item.inode;
    data_.ino_generation = 0;
    data_.prot = item.type_;
    data_.flags = item.flags;
    if (strncpy_s(data_.filename, KILO, item.name_.c_str(), item.name_.size()) != 0) {
        HLOGE("strncpy_s failed");
    }

    header.size = sizeof(header) + sizeof(data_) - KILO + item.name_.size() + 1;
}

bool PerfRecordMmap2::GetBinary(std::vector<uint8_t> &buf) const
{
    if (buf.size() < GetSize()) {
        buf.resize(GetSize());
    }

    GetHeaderBinary(buf);
    uint8_t *p = buf.data() + GetHeaderSize();

    // data_.filename[] is variable-length
    std::copy((uint8_t *)&data_, (uint8_t *)&data_ + GetSize() - GetHeaderSize(), p);
    return true;
}

void PerfRecordMmap2::DumpData(int indent) const
{
    PrintIndent(indent, "pid %u, tid %u, addr 0x%llx, len 0x%llx\n", data_.pid, data_.tid,
                data_.addr, data_.len);
    PrintIndent(indent, "pgoff 0x%llx, maj %u, min %u, ino %llu, ino_generation %llu\n",
                data_.pgoff, data_.maj, data_.min, data_.ino, data_.ino_generation);
    PrintIndent(indent, "prot %u, flags %u, filename %s\n", data_.prot, data_.flags,
                data_.filename);
}
void PerfRecordMmap2::DumpLog(const std::string &prefix) const
{
    HLOGV("%s:  MMAP2: size %d pid %u tid %u dso '%s' (0x%llx-0x%llx)@0x%llx", prefix.c_str(),
          header.size, data_.pid, data_.tid, data_.filename, data_.addr, data_.addr + data_.len,
          data_.pgoff);
}

PerfRecordLost::PerfRecordLost(uint8_t *p) : PerfEventRecord(p, "lost")
{
    size_t copySize = GetSize() - sizeof(header);
    if (memcpy_s((uint8_t *)&data_, sizeof(data_), p + sizeof(header), copySize) != 0) {
        HLOGE("memcpy_s retren failed !!!");
    }
}

bool PerfRecordLost::GetBinary(std::vector<uint8_t> &buf) const
{
    if (buf.size() < GetSize()) {
        buf.resize(GetSize());
    }

    GetHeaderBinary(buf);
    uint8_t *p = buf.data() + GetHeaderSize();

    auto pDest = reinterpret_cast<PerfRecordLostData *>(p);
    *pDest = data_;

    return true;
}

void PerfRecordLost::DumpData(int indent) const
{
    PrintIndent(indent, "id %llu, lost %llu\n", data_.id, data_.lost);
}

PerfRecordComm::PerfRecordComm(uint8_t *p) : PerfEventRecord(p, "comm")
{
    size_t copySize = GetSize() - sizeof(header);
    if (memcpy_s((uint8_t *)&data_, sizeof(data_), p + sizeof(header), copySize) != 0) {
        HLOGE("memcpy_s retren failed !!!");
    }
}

PerfRecordComm::PerfRecordComm(bool inKernel, u32 pid, u32 tid, const std::string &comm)
    : PerfEventRecord(PERF_RECORD_COMM, inKernel, "comm")
{
    data_.pid = pid;
    data_.tid = tid;
    if (strncpy_s(data_.comm, KILO, comm.c_str(), comm.size()) != 0) {
        HLOGE("strncpy_s failed !!!");
    }

    header.size = sizeof(header) + sizeof(data_) - KILO + comm.size() + 1;
}

bool PerfRecordComm::GetBinary(std::vector<uint8_t> &buf) const
{
    if (buf.size() < GetSize()) {
        buf.resize(GetSize());
    }

    GetHeaderBinary(buf);
    uint8_t *p = buf.data() + GetHeaderSize();

    // data_.comm[] is variable-length
    std::copy((uint8_t *)&data_, (uint8_t *)&data_ + GetSize() - GetHeaderSize(), p);

    return true;
}

void PerfRecordComm::DumpData(int indent) const
{
    PrintIndent(indent, "pid %u, tid %u, comm %s\n", data_.pid, data_.tid, data_.comm);
}

void PerfRecordComm::DumpLog(const std::string &prefix) const
{
    HLOGV("pid %u, tid %u, comm %s\n", data_.pid, data_.tid, data_.comm);
}

PerfRecordExit::PerfRecordExit(uint8_t *p) : PerfEventRecord(p, "exit")
{
    size_t copySize = GetSize() - sizeof(header);
    if (memcpy_s((uint8_t *)&data_, sizeof(data_), p + sizeof(header), copySize) != 0) {
        HLOGE("memcpy_s retren failed !!!");
    }
}

bool PerfRecordExit::GetBinary(std::vector<uint8_t> &buf) const
{
    if (buf.size() < GetSize()) {
        buf.resize(GetSize());
    }

    GetHeaderBinary(buf);
    uint8_t *p = buf.data() + GetHeaderSize();

    auto pDest = reinterpret_cast<PerfRecordExitData *>(p);
    *pDest = data_;
    return true;
}

void PerfRecordExit::DumpData(int indent) const
{
    PrintIndent(indent, "pid %u, ppid %u, tid %u, ptid %u time 0x%llx\n", data_.pid, data_.ppid,
                data_.tid, data_.ptid, data_.time);
}

PerfRecordThrottle::PerfRecordThrottle(uint8_t *p) : PerfEventRecord(p, "throttle")
{
    size_t copySize = GetSize() - sizeof(header);
    if (memcpy_s((uint8_t *)&data_, sizeof(data_), p + sizeof(header), copySize) != 0) {
        HLOGE("memcpy_s retren failed !!!");
    }
}

bool PerfRecordThrottle::GetBinary(std::vector<uint8_t> &buf) const
{
    if (buf.size() < GetSize()) {
        buf.resize(GetSize());
    }

    GetHeaderBinary(buf);
    uint8_t *p = buf.data() + GetHeaderSize();

    auto pDest = reinterpret_cast<PerfRecordThrottleData *>(p);
    *pDest = data_;
    return true;
}

void PerfRecordThrottle::DumpData(int indent) const
{
    PrintIndent(indent, "time 0x%llx, id %llx, stream_id %llx\n", data_.time, data_.id,
                data_.stream_id);
}

PerfRecordUnthrottle::PerfRecordUnthrottle(uint8_t *p) : PerfEventRecord(p, "unthrottle")
{
    size_t copySize = GetSize() - sizeof(header);
    if (memcpy_s((uint8_t *)&data_, sizeof(data_), p + sizeof(header), copySize) != 0) {
        HLOGE("memcpy_s retren failed !!!");
    }
}

bool PerfRecordUnthrottle::GetBinary(std::vector<uint8_t> &buf) const
{
    if (buf.size() < GetSize()) {
        buf.resize(GetSize());
    }

    GetHeaderBinary(buf);
    uint8_t *p = buf.data() + GetHeaderSize();

    auto pDest = reinterpret_cast<PerfRecordThrottleData *>(p);
    *pDest = data_;
    return true;
}
void PerfRecordUnthrottle::DumpData(int indent) const
{
    PrintIndent(indent, "time 0x%llx, id %llx, stream_id %llx\n", data_.time, data_.id,
                data_.stream_id);
}

PerfRecordFork::PerfRecordFork(uint8_t *p) : PerfEventRecord(p, "fork")
{
    size_t copySize = GetSize() - sizeof(header);
    if (memcpy_s((uint8_t *)&data_, sizeof(data_), p + sizeof(header), copySize) != 0) {
        HLOGE("memcpy_s retren failed !!!");
    }
}

bool PerfRecordFork::GetBinary(std::vector<uint8_t> &buf) const
{
    if (buf.size() < GetSize()) {
        buf.resize(GetSize());
    }

    GetHeaderBinary(buf);
    uint8_t *p = buf.data() + GetHeaderSize();

    auto pDest = reinterpret_cast<PerfRecordForkData *>(p);
    *pDest = data_;
    return true;
}

void PerfRecordFork::DumpData(int indent) const
{
    PrintIndent(indent, "pid %u, ppid %u, tid %u, ptid %u\n", data_.pid, data_.ppid, data_.tid,
                data_.ptid);
}

PerfRecordRead::PerfRecordRead(uint8_t *p) : PerfEventRecord(p, "read")
{
    size_t copySize = GetSize() - sizeof(header);
    if (memcpy_s((uint8_t *)&data_, sizeof(data_), p + sizeof(header), copySize) != 0) {
        HLOGE("memcpy_s retren failed !!!");
    }
}

bool PerfRecordRead::GetBinary(std::vector<uint8_t> &buf) const
{
    if (buf.size() < GetSize()) {
        buf.resize(GetSize());
    }

    GetHeaderBinary(buf);
    uint8_t *p = buf.data() + GetHeaderSize();

    auto pDest = reinterpret_cast<PerfRecordReadData *>(p);
    *pDest = data_;
    return true;
}

void PerfRecordRead::DumpData(int indent) const
{
    PrintIndent(indent, "pid %u, tid %u\n", data_.pid, data_.tid);
    PrintIndent(indent, "values: value %llx, time_enabled %llx, time_running %llx, id %llx\n",
                data_.values.value, data_.values.time_enabled, data_.values.time_running,
                data_.values.id);
}

PerfRecordAux::PerfRecordAux(uint8_t *p) : PerfEventRecord(p, "aux")
{
    size_t copySize = GetSize() - sizeof(header);
    if (memcpy_s((uint8_t *)&data_, sizeof(data_), p + sizeof(header), copySize) != 0) {
        HLOGE("memcpy_s retren failed !!!");
    }
}

bool PerfRecordAux::GetBinary(std::vector<uint8_t> &buf) const
{
    if (buf.size() < GetSize()) {
        buf.resize(GetSize());
    }

    GetHeaderBinary(buf);
    uint8_t *p = buf.data() + GetHeaderSize();

    auto pDest = reinterpret_cast<PerfRecordAuxData *>(p);
    *pDest = data_;
    return true;
}

void PerfRecordAux::DumpData(int indent) const
{
    PrintIndent(indent, "aux_offset %llx, aux_size %llx, flags %llx\n", data_.aux_offset,
                data_.aux_size, data_.flags);
}

PerfRecordItraceStart::PerfRecordItraceStart(uint8_t *p) : PerfEventRecord(p, "itraceStart")
{
    size_t copySize = GetSize() - sizeof(header);
    if (memcpy_s((uint8_t *)&data_, sizeof(data_), p + sizeof(header), copySize) != 0) {
        HLOGE("memcpy_s retren failed !!!");
    }
}

bool PerfRecordItraceStart::GetBinary(std::vector<uint8_t> &buf) const
{
    if (buf.size() < GetSize()) {
        buf.resize(GetSize());
    }

    GetHeaderBinary(buf);
    uint8_t *p = buf.data() + GetHeaderSize();

    auto pDest = reinterpret_cast<PerfRecordItraceStartData *>(p);
    *pDest = data_;
    return true;
}

void PerfRecordItraceStart::DumpData(int indent) const
{
    PrintIndent(indent, "pid %u, tid %u\n", data_.pid, data_.tid);
}

PerfRecordLostSamples::PerfRecordLostSamples(uint8_t *p) : PerfEventRecord(p, "lostSamples")
{
    size_t copySize = GetSize() - sizeof(header);
    if (memcpy_s((uint8_t *)&data_, sizeof(data_), p + sizeof(header), copySize) != 0) {
        HLOGE("memcpy_s retren failed !!!");
    }
}

bool PerfRecordLostSamples::GetBinary(std::vector<uint8_t> &buf) const
{
    if (buf.size() < GetSize()) {
        buf.resize(GetSize());
    }

    GetHeaderBinary(buf);
    uint8_t *p = buf.data() + GetHeaderSize();

    auto pDest = reinterpret_cast<PerfRecordLostSamplesData *>(p);
    *pDest = data_;
    return true;
}

void PerfRecordLostSamples::DumpData(int indent) const
{
    PrintIndent(indent, "lost %llu\n", data_.lost);
}

PerfRecordSwitch::PerfRecordSwitch(uint8_t *p) : PerfEventRecord(p, "switch")
{
    size_t copySize = GetSize() - sizeof(header);
    if (memcpy_s((uint8_t *)&data_, sizeof(data_), p + sizeof(header), copySize) != 0) {
        HLOGE("memcpy_s retren failed !!!");
    }
}

bool PerfRecordSwitch::GetBinary(std::vector<uint8_t> &buf) const
{
    if (buf.size() < GetSize()) {
        buf.resize(GetSize());
    }

    GetHeaderBinary(buf);
    uint8_t *p = buf.data() + GetHeaderSize();

    auto pDest = reinterpret_cast<PerfRecordSwitchData *>(p);
    *pDest = data_;
    return true;
}

PerfRecordSwitchCpuWide::PerfRecordSwitchCpuWide(uint8_t *p) : PerfEventRecord(p, "switchCpuWide")
{
    size_t copySize = GetSize() - sizeof(header);
    if (memcpy_s((uint8_t *)&data_, sizeof(data_), p + sizeof(header), copySize) != 0) {
        HLOGE("memcpy_s retren failed !!!");
    }
}

bool PerfRecordSwitchCpuWide::GetBinary(std::vector<uint8_t> &buf) const
{
    if (buf.size() < GetSize()) {
        buf.resize(GetSize());
    }

    GetHeaderBinary(buf);
    uint8_t *p = buf.data() + GetHeaderSize();

    auto pDest = reinterpret_cast<PerfRecordSwitchCpuWideData *>(p);
    *pDest = data_;
    return true;
}

void PerfRecordSwitchCpuWide::DumpData(int indent) const
{
    PrintIndent(indent, "next_prev_pid %u, next_prev_tid %u\n", data_.next_prev_pid,
                data_.next_prev_tid);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
