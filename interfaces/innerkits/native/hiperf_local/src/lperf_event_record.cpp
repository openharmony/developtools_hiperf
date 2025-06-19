/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "lperf_event_record.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
namespace HiPerfLocal {
LperfRecordSample LperfRecordFactory::record_ = {};

void LperfRecordSample::InitHeader(uint8_t* p)
{
    if (p == nullptr) {
        header_.type = PERF_RECORD_MMAP;
        header_.misc = PERF_RECORD_MISC_USER;
        header_.size = 0;
        return;
    }
    header_ = *(reinterpret_cast<perf_event_header *>(p));
}

bool LperfRecordSample::Init(uint8_t* p)
{
    InitHeader(p);
    CHECK_TRUE_AND_RET(p != nullptr, false, "LperfRecordSample Init error");
    data_ = {};
    uint64_t dataSize = static_cast<uint64_t>(RECORD_SIZE_LIMIT);
    CHECK_TRUE_AND_RET(SetPointerOffset(p, sizeof(header_), dataSize), false, "set header_ offset error");

    // parse record according SAMPLE_TYPE
    bool popId = PopFromBinary2<uint32_t, uint32_t>(sampleType_ & PERF_SAMPLE_TID, p, data_.pid, data_.tid, dataSize);
    CHECK_TRUE_AND_RET(popId, false, "Init PERF_SAMPLE_TID error");
    CHECK_TRUE_AND_RET(PopFromBinary<uint64_t>(sampleType_ & PERF_SAMPLE_TIME, p, data_.time, dataSize),
                       false, "Init PERF_SAMPLE_TIME error");
    CHECK_TRUE_AND_RET(PopFromBinary<uint64_t>(sampleType_ & PERF_SAMPLE_CALLCHAIN, p, data_.nr, dataSize),
                       false, "Init PERF_SAMPLE_CALLCHAIN error");
    if (data_.nr > 0) {
        // the pointer is from input(p), require caller keep input(p) with *this together
        // think it in next time
        data_.ips = reinterpret_cast<uint64_t *>(p);
        CHECK_TRUE_AND_RET(SetPointerOffset(p, data_.nr * sizeof(uint64_t), dataSize), false, "set ips offset error");
    }
    return true;
}

void LperfRecordSample::Clear()
{
    data_.pid = 0;
    data_.tid = 0;
    data_.time = 0;
    data_.nr = 0;
    data_.ips = nullptr;
}

LperfRecordSample& LperfRecordFactory::GetLperfRecord(uint32_t type, uint8_t* data)
{
    if (type != PERF_RECORD_SAMPLE || !record_.Init(data)) {
        record_.Clear();
        HIPERF_HILOGE(MODULE_DEFAULT, "Init LperfRecordSample data error");
    }
    return record_;
}

void LperfRecordFactory::ClearData()
{
    record_.Clear();
}

template<typename T>
inline bool PopFromBinary(bool condition, uint8_t*& p, T& v, uint64_t& size)
{
    CHECK_TRUE_AND_RET(sizeof(T) <= size, false, "PopFromBinary error");
    if (condition) {
        v = *(reinterpret_cast<const T *>(p));
        p += sizeof(T);
        size -= sizeof(T);
    }
    return true;
}

template<typename T1, typename T2>
inline bool PopFromBinary2(bool condition, uint8_t*& p, T1& v1, T2& v2, uint64_t& size)
{
    CHECK_TRUE_AND_RET(sizeof(T1) + sizeof(T2) <= size, false, "PopFromBinary2 error");
    if (condition) {
        v1 = *(reinterpret_cast<const T1 *>(p));
        p += sizeof(T1);
        v2 = *(reinterpret_cast<const T2 *>(p));
        p += sizeof(T2);
        size -= (sizeof(T1) + sizeof(T2));
    }
    return true;
}

inline bool SetPointerOffset(uint8_t*& p, uint64_t offset, uint64_t& size)
{
    CHECK_TRUE_AND_RET(offset <= size && offset <= RECORD_SIZE_LIMIT, false, "SetPointerOffset error");
    size -= offset;
    p += offset;
    return true;
}
} // namespace HiPerfLocal
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS