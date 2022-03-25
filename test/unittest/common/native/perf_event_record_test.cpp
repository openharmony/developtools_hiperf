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

#include "perf_event_record_test.h"

#include <cstring>

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;

namespace OHOS {
namespace Developtools {
namespace HiPerf {
class PerfEventRecordTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static constexpr size_t HEADER_SIZE = sizeof(perf_event_header);
};

void PerfEventRecordTest::SetUpTestCase() {}

void PerfEventRecordTest::TearDownTestCase() {}

void PerfEventRecordTest::SetUp() {}

void PerfEventRecordTest::TearDown() {}

static int CompareByteStream(const uint8_t *a, const uint8_t *b, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        if (a[i] > b[i]) {
            return (a[i] - b[i]);
        } else if (a[i] < b[i]) {
            return (int(a[i]) - int(b[i]));
        }
    }
    return 0;
}

/**
 * @tc.name: Test
 * @tc.desc:
 * @tc.type: FUNC
 */
const std::string RECORDNAME_MMAP = "mmap";
HWTEST_F(PerfEventRecordTest, Mmap, TestSize.Level1)
{
    PerfRecordMmapData data {1, 2, 3, 4, 5, "testdatammap"};
    PerfRecordMmap recordIn {true,     data.pid,   data.tid,     data.addr,
                             data.len, data.pgoff, data.filename};

    ASSERT_EQ(recordIn.GetType(), PERF_RECORD_MMAP);
    ASSERT_EQ(recordIn.GetName(), RECORDNAME_MMAP);
    ASSERT_EQ(recordIn.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(recordIn.GetHeaderSize(), HEADER_SIZE);

    std::vector<uint8_t> header;
    recordIn.GetHeaderBinary(header);
    std::vector<uint8_t> buff;
    ASSERT_TRUE(recordIn.GetBinary(buff));
    ASSERT_EQ(CompareByteStream(header.data(), buff.data(), HEADER_SIZE), 0);

    size_t buffSize = HEADER_SIZE + sizeof(PerfRecordMmapData) - KILO + strlen(data.filename) + 1;
    ASSERT_EQ(recordIn.GetSize(), buffSize);

    PerfRecordMmap recordOut(buff.data());
    ASSERT_EQ(recordOut.GetType(), PERF_RECORD_MMAP);
    ASSERT_EQ(recordOut.GetName(), RECORDNAME_MMAP);
    ASSERT_EQ(recordOut.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(recordOut.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(recordOut.GetSize(), buffSize);
    ASSERT_EQ(recordOut.data_.pid, data.pid);
    ASSERT_EQ(recordOut.data_.tid, data.tid);
    ASSERT_EQ(recordOut.data_.addr, data.addr);
    ASSERT_EQ(recordOut.data_.len, data.len);
    ASSERT_EQ(recordOut.data_.pgoff, data.pgoff);
    ASSERT_EQ(strcmp(recordOut.data_.filename, data.filename), 0);
}

const std::string RECORDNAME_MMAP2 = "mmap2";
HWTEST_F(PerfEventRecordTest, Mmap2, TestSize.Level1)
{
    PerfRecordMmap2Data data {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, "testdatammap2"};
    PerfRecordMmap2 recordIn {true,     data.pid, data.tid, data.addr, data.len,   data.pgoff,
                              data.maj, data.min, data.ino, data.prot, data.flags, data.filename};

    ASSERT_EQ(recordIn.GetType(), PERF_RECORD_MMAP2);
    ASSERT_EQ(recordIn.GetName(), RECORDNAME_MMAP2);
    ASSERT_EQ(recordIn.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(recordIn.GetHeaderSize(), HEADER_SIZE);

    std::vector<uint8_t> header;
    recordIn.GetHeaderBinary(header);
    std::vector<uint8_t> buff;
    ASSERT_TRUE(recordIn.GetBinary(buff));
    ASSERT_EQ(CompareByteStream(header.data(), buff.data(), HEADER_SIZE), 0);

    size_t buffSize = HEADER_SIZE + sizeof(PerfRecordMmap2Data) - KILO + strlen(data.filename) + 1;
    ASSERT_EQ(recordIn.GetSize(), buffSize);

    PerfRecordMmap2 recordOut(buff.data());
    ASSERT_EQ(recordOut.GetType(), PERF_RECORD_MMAP2);
    ASSERT_EQ(recordOut.GetName(), RECORDNAME_MMAP2);
    ASSERT_EQ(recordOut.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(recordOut.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(recordOut.GetSize(), buffSize);
    ASSERT_EQ(recordOut.data_.pid, data.pid);
    ASSERT_EQ(recordOut.data_.tid, data.tid);
    ASSERT_EQ(recordOut.data_.addr, data.addr);
    ASSERT_EQ(recordOut.data_.len, data.len);
    ASSERT_EQ(recordOut.data_.pgoff, data.pgoff);
    ASSERT_EQ(recordOut.data_.maj, data.maj);
    ASSERT_EQ(recordOut.data_.min, data.min);
    ASSERT_EQ(recordOut.data_.ino, data.ino);
    ASSERT_EQ(recordOut.data_.prot, data.prot);
    ASSERT_EQ(recordOut.data_.flags, data.flags);
    ASSERT_EQ(strcmp(recordOut.data_.filename, data.filename), 0);
}

const std::string RECORDNAME_COMM = "comm";
HWTEST_F(PerfEventRecordTest, Comm, TestSize.Level1)
{
    PerfRecordCommData data {1, 2, "testdatcomm"};
    PerfRecordComm recordIn {true, data.pid, data.tid, data.comm};

    ASSERT_EQ(recordIn.GetType(), PERF_RECORD_COMM);
    ASSERT_EQ(recordIn.GetName(), RECORDNAME_COMM);
    ASSERT_EQ(recordIn.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(recordIn.GetHeaderSize(), HEADER_SIZE);

    std::vector<uint8_t> header;
    recordIn.GetHeaderBinary(header);
    std::vector<uint8_t> buff;
    ASSERT_TRUE(recordIn.GetBinary(buff));
    ASSERT_EQ(CompareByteStream(header.data(), buff.data(), HEADER_SIZE), 0);

    size_t buffSize = HEADER_SIZE + sizeof(PerfRecordCommData) - KILO + strlen(data.comm) + 1;
    ASSERT_EQ(recordIn.GetSize(), buffSize);
    PerfRecordComm recordOut(buff.data());
    ASSERT_EQ(recordOut.GetType(), PERF_RECORD_COMM);
    ASSERT_EQ(recordOut.GetName(), RECORDNAME_COMM);
    ASSERT_EQ(recordOut.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(recordOut.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(recordOut.GetSize(), buffSize);
    ASSERT_EQ(recordOut.data_.pid, data.pid);
    ASSERT_EQ(recordOut.data_.tid, data.tid);
    ASSERT_EQ(strcmp(recordOut.data_.comm, data.comm), 0);
}

const std::string RECORDNAME_LOST = "lost";
HWTEST_F(PerfEventRecordTest, Lost, TestSize.Level1)
{
    struct TestRecordLostst {
        perf_event_header h;
        PerfRecordLostData d;
    };
    TestRecordLostst data = {
        {PERF_RECORD_LOST_SAMPLES, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordLostst)},
        {1, 2}};

    PerfRecordLost record((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_LOST_SAMPLES);
    ASSERT_EQ(record.GetName(), RECORDNAME_LOST);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

const std::string RECORDNAME_EXIT = "exit";
HWTEST_F(PerfEventRecordTest, Exit, TestSize.Level1)
{
    struct TestRecordExitst {
        perf_event_header h;
        PerfRecordExitData d;
    };
    TestRecordExitst data = {{PERF_RECORD_EXIT, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordExitst)},
                             {1, 2, 3, 4, 5}};

    PerfRecordExit record((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_EXIT);
    ASSERT_EQ(record.GetName(), RECORDNAME_EXIT);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

const std::string RECORDNAME_THROTTLE = "throttle";
HWTEST_F(PerfEventRecordTest, Throttle, TestSize.Level1)
{
    struct TestRecordThrottlest {
        perf_event_header h;
        PerfRecordThrottleData d;
    };
    TestRecordThrottlest data = {
        {PERF_RECORD_THROTTLE, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordThrottlest)},
        {1, 2, 3}};

    PerfRecordThrottle record((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_THROTTLE);
    ASSERT_EQ(record.GetName(), RECORDNAME_THROTTLE);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

const std::string RECORDNAME_UNTHROTTLE = "unthrottle";
HWTEST_F(PerfEventRecordTest, Unthrottle, TestSize.Level1)
{
    struct TestRecordUNThrottlest {
        perf_event_header h;
        PerfRecordThrottleData d;
    };
    TestRecordUNThrottlest data = {
        {PERF_RECORD_UNTHROTTLE, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordUNThrottlest)},
        {1, 2, 3}};

    PerfRecordUnthrottle record((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_UNTHROTTLE);
    ASSERT_EQ(record.GetName(), RECORDNAME_UNTHROTTLE);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

const std::string RECORDNAME_FORK = "fork";
HWTEST_F(PerfEventRecordTest, Fork, TestSize.Level1)
{
    struct TestRecordForkst {
        perf_event_header h;
        PerfRecordForkData d;
    };
    TestRecordForkst data = {{PERF_RECORD_FORK, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordForkst)},
                             {1, 2, 3, 4, 5}};

    PerfRecordFork record((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_FORK);
    ASSERT_EQ(record.GetName(), RECORDNAME_FORK);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

struct TestRecordSamplest {
    perf_event_header header_;
    PerfRecordSampleData data_;
};

static void InitTestRecordSample(TestRecordSamplest &record)
{
    record.header_.size = sizeof(perf_event_header);
    record.header_.size +=
        sizeof(record.data_.sample_id) + sizeof(record.data_.sample_id) + sizeof(record.data_.ip) +
        sizeof(record.data_.pid) + sizeof(record.data_.tid) + sizeof(record.data_.time) +
        sizeof(record.data_.addr) + sizeof(record.data_.id) + sizeof(record.data_.stream_id) +
        sizeof(record.data_.cpu) + sizeof(record.data_.res) + sizeof(record.data_.period);

    // v??

    record.data_.nr = 0;
    record.data_.ips = nullptr;
    record.header_.size += sizeof(record.data_.nr);
    record.data_.raw_size = 0;
    record.data_.raw_data = nullptr;
    record.header_.size += sizeof(record.data_.raw_size);
    record.data_.bnr = 0;
    record.data_.lbr = nullptr;
    record.header_.size += sizeof(record.data_.bnr);
    record.data_.user_abi = 0;
    record.data_.reg_mask = 0;
    record.header_.size += sizeof(record.data_.user_abi);
    record.data_.stack_size = 0;
    record.header_.size += sizeof(record.data_.stack_size);
    // others
}

static bool CompareRecordSample50(const TestRecordSamplest &record, const std::vector<u8> &buf,
                                  size_t offset)
{
    const uint8_t *p = buf.data() + offset;

    if (record.data_.nr != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    if (record.data_.raw_size != *(reinterpret_cast<const u32 *>(p))) {
        return false;
    }
    p += sizeof(u32);

    if (record.data_.bnr != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    if (record.data_.user_abi != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    if (record.data_.stack_size != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    return true;
}

static bool CompareRecordSample(const TestRecordSamplest &record, const std::vector<u8> &buf)
{
    if (buf.size() < record.header_.size) {
        return false;
    }
    const uint8_t *p = buf.data();
    p += sizeof(perf_event_header);

    if (record.data_.sample_id != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    if (record.data_.ip != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    if (record.data_.pid != *(reinterpret_cast<const u32 *>(p))) {
        return false;
    }
    p += sizeof(u32);

    if (record.data_.tid != *(reinterpret_cast<const u32 *>(p))) {
        return false;
    }
    p += sizeof(u32);

    if (record.data_.time != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    if (record.data_.addr != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    if (record.data_.id != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    if (record.data_.stream_id != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    if (record.data_.cpu != *(reinterpret_cast<const u32 *>(p))) {
        return false;
    }
    p += sizeof(u32);

    if (record.data_.res != *(reinterpret_cast<const u32 *>(p))) {
        return false;
    }
    p += sizeof(u32);

    if (record.data_.period != *(reinterpret_cast<const u64 *>(p))) {
        return false;
    }
    p += sizeof(u64);

    return CompareRecordSample50(record, buf, p - buf.data());
}

const std::string RECORDNAME_SAMPLE = "sample";
HWTEST_F(PerfEventRecordTest, Sample, TestSize.Level1)
{
    perf_event_attr attr {};
    attr.sample_type = UINT64_MAX;
    TestRecordSamplest data = {
        {PERF_RECORD_SAMPLE, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordSamplest)},
        {}};
    InitTestRecordSample(data);

    PerfRecordSample record((uint8_t *)&data, attr);
    ASSERT_EQ(record.GetType(), PERF_RECORD_SAMPLE);
    ASSERT_EQ(record.GetName(), RECORDNAME_SAMPLE);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_TRUE(CompareRecordSample(data, buff));
}

HWTEST_F(PerfEventRecordTest, SampleReplaceWithCallStack1, TestSize.Level1)
{
    perf_event_attr attr {};
    attr.sample_type = UINT64_MAX;
    TestRecordSamplest data = {
        {PERF_RECORD_SAMPLE, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordSamplest)},
        {}};
    InitTestRecordSample(data);

    PerfRecordSample record((uint8_t *)&data, attr);
    record.sampleType_ |= PERF_SAMPLE_REGS_USER;
    record.sampleType_ |= PERF_SAMPLE_STACK_USER;
    record.sampleType_ |= PERF_SAMPLE_CALLCHAIN;

    std::vector<u64> ips = {};
    record.data_.ips = ips.data();
    record.data_.nr = ips.size();
    record.callFrames_ = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    record.ReplaceWithCallStack();
    ASSERT_EQ(record.data_.reg_nr, 0u);
    ASSERT_EQ(record.data_.user_abi, 0u);
    ASSERT_EQ(record.data_.stack_size, 0u);
    ASSERT_EQ(record.data_.dyn_size, 0u);

    // include PERF_CONTEXT_USER
    ASSERT_EQ(record.callFrames_.size() + 1, record.data_.nr);
    ASSERT_EQ(record.data_.ips[0], PERF_CONTEXT_USER);
    for (size_t i = 1; i < record.data_.nr; i++) {
        ASSERT_EQ(record.data_.ips[i], record.callFrames_.at(i - 1).ip_);
    }
    // result is 1 - 9
}

HWTEST_F(PerfEventRecordTest, SampleReplaceWithCallStack2, TestSize.Level1)
{
    perf_event_attr attr {};
    attr.sample_type = UINT64_MAX;
    TestRecordSamplest data = {
        {PERF_RECORD_SAMPLE, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordSamplest)},
        {}};
    InitTestRecordSample(data);

    PerfRecordSample record((uint8_t *)&data, attr);
    record.sampleType_ |= PERF_SAMPLE_CALLCHAIN;

    std::vector<u64> ips = {};
    record.data_.ips = ips.data();
    record.data_.nr = ips.size();
    record.callFrames_ = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    record.ReplaceWithCallStack();
    // include PERF_CONTEXT_USER
    ASSERT_EQ(record.callFrames_.size() + 1, record.data_.nr);
    ASSERT_EQ(record.data_.ips[0], PERF_CONTEXT_USER);
    for (size_t i = 1; i < record.data_.nr; i++) {
        ASSERT_EQ(record.data_.ips[i], record.callFrames_.at(i - 1).ip_);
    }
    // result is 1 - 9
}

HWTEST_F(PerfEventRecordTest, SampleReplaceWithCallStack3, TestSize.Level1)
{
    perf_event_attr attr {};
    attr.sample_type = UINT64_MAX;
    TestRecordSamplest data = {
        {PERF_RECORD_SAMPLE, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordSamplest)},
        {}};
    InitTestRecordSample(data);

    PerfRecordSample record((uint8_t *)&data, attr);
    record.sampleType_ |= PERF_SAMPLE_CALLCHAIN;

    record.callFrames_ = {4, 5, 6, 7, 8, 9};
    std::vector<u64> ips = {0, 1, 2, 3};
    record.data_.ips = ips.data();
    record.data_.nr = ips.size();
    record.ReplaceWithCallStack();
    // include PERF_CONTEXT_USER
    ASSERT_EQ(record.callFrames_.size() + ips.size() + 1, record.data_.nr);
    for (size_t i = 0; i < ips.size(); i++) {
        ASSERT_EQ(record.data_.ips[i], ips[i]);
    }
    ASSERT_EQ(record.data_.ips[ips.size()], PERF_CONTEXT_USER);
    for (size_t i = 0; i < record.callFrames_.size(); i++) {
        ASSERT_EQ(record.data_.ips[i + ips.size() + 1], record.callFrames_.at(i).ip_);
    }
    // result is 0 - 3 , PERF_CONTEXT_USER , 4 - 9
}

HWTEST_F(PerfEventRecordTest, SampleReplaceWithCallStack4, TestSize.Level1)
{
    perf_event_attr attr {};
    attr.sample_type = UINT64_MAX;
    TestRecordSamplest data = {
        {PERF_RECORD_SAMPLE, PERF_RECORD_MISC_KERNEL, sizeof(TestRecordSamplest)},
        {}};
    InitTestRecordSample(data);

    PerfRecordSample record((uint8_t *)&data, attr);
    record.sampleType_ |= PERF_SAMPLE_CALLCHAIN;

    record.callFrames_ = {};
    std::vector<u64> ips = {0, 1, 2, 3};
    record.data_.ips = ips.data();
    record.data_.nr = ips.size();
    record.ReplaceWithCallStack();
    // not PERF_CONTEXT_USER will add
    ASSERT_EQ(ips.size(), record.data_.nr);
    for (size_t i = 0; i < record.data_.nr; i++) {
        ASSERT_EQ(record.data_.ips[i], ips[i]);
    }
    // result is 0 - 3
}

const std::string RECORDNAME_READ = "read";
HWTEST_F(PerfEventRecordTest, Read, TestSize.Level1)
{
    struct PerfRecordReadst {
        perf_event_header h;
        PerfRecordReadData d;
    };
    PerfRecordReadst data = {{PERF_RECORD_READ, PERF_RECORD_MISC_KERNEL, sizeof(PerfRecordReadst)},
                             {1, 2, {11, 12, 13, 14}}};

    PerfRecordRead record((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_READ);
    ASSERT_EQ(record.GetName(), RECORDNAME_READ);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

const std::string RECORDNAME_AUX = "aux";
HWTEST_F(PerfEventRecordTest, Aux, TestSize.Level1)
{
    struct PerfRecordAuxst {
        perf_event_header h;
        PerfRecordAuxData d;
    };
    PerfRecordAuxst data = {{PERF_RECORD_AUX, PERF_RECORD_MISC_KERNEL, sizeof(PerfRecordAuxst)},
                            {1, 2, 3}};

    PerfRecordAux record((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_AUX);
    ASSERT_EQ(record.GetName(), RECORDNAME_AUX);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

const std::string RECORDNAME_ITRACE_START = "itraceStart";
HWTEST_F(PerfEventRecordTest, ItraceStart, TestSize.Level1)
{
    struct PerfRecordItraceStartst {
        perf_event_header h;
        PerfRecordItraceStartData d;
    };
    PerfRecordItraceStartst data = {
        {PERF_RECORD_ITRACE_START, PERF_RECORD_MISC_KERNEL, sizeof(PerfRecordItraceStartst)},
        {1, 2}};

    PerfRecordItraceStart record((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_ITRACE_START);
    ASSERT_EQ(record.GetName(), RECORDNAME_ITRACE_START);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

const std::string RECORDNAME_LOST_SAMPLES = "lostSamples";
HWTEST_F(PerfEventRecordTest, LostSamples, TestSize.Level1)
{
    struct PerfRecordLostSamplesst {
        perf_event_header h;
        PerfRecordLostSamplesData d;
    };
    PerfRecordLostSamplesst data = {
        {PERF_RECORD_LOST_SAMPLES, PERF_RECORD_MISC_KERNEL, sizeof(PerfRecordLostSamplesst)},
        {1}};

    PerfRecordLostSamples record((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_LOST_SAMPLES);
    ASSERT_EQ(record.GetName(), RECORDNAME_LOST_SAMPLES);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}

const std::string RECORDNAME_SWITCH = "switch";
HWTEST_F(PerfEventRecordTest, Switch, TestSize.Level1)
{
    struct PerfRecordSwitchst {
        perf_event_header h;
        PerfRecordSwitchData d;
    };
    PerfRecordSwitchst data = {
        {PERF_RECORD_SWITCH, PERF_RECORD_MISC_KERNEL, sizeof(perf_event_header)},
        {}};

    PerfRecordSwitch record((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_SWITCH);
    ASSERT_EQ(record.GetName(), RECORDNAME_SWITCH);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), HEADER_SIZE);

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), HEADER_SIZE), 0);
}

const std::string RECORDNAME_SWITCH_CPU_WIDE = "switchCpuWide";
HWTEST_F(PerfEventRecordTest, SwitchCpuWide, TestSize.Level1)
{
    struct PerfRecordSwitchCpuWidest {
        perf_event_header h;
        PerfRecordSwitchCpuWideData d;
    };
    PerfRecordSwitchCpuWidest data = {
        {PERF_RECORD_SWITCH_CPU_WIDE, PERF_RECORD_MISC_KERNEL, sizeof(PerfRecordSwitchCpuWidest)},
        {}};

    PerfRecordSwitchCpuWide record((uint8_t *)&data);
    ASSERT_EQ(record.GetType(), PERF_RECORD_SWITCH_CPU_WIDE);
    ASSERT_EQ(record.GetName(), RECORDNAME_SWITCH_CPU_WIDE);
    ASSERT_EQ(record.GetMisc(), PERF_RECORD_MISC_KERNEL);
    ASSERT_EQ(record.GetHeaderSize(), HEADER_SIZE);
    ASSERT_EQ(record.GetSize(), sizeof(data));

    std::vector<uint8_t> buff;
    ASSERT_TRUE(record.GetBinary(buff));
    ASSERT_EQ(CompareByteStream((uint8_t *)&data, buff.data(), sizeof(data)), 0);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
