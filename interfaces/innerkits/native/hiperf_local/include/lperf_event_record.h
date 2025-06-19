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
#ifndef LPERF_EVENT_RECORD_H
#define LPERF_EVENT_RECORD_H

#include <cstdint>
#include <linux/perf_event.h>
#include <securec.h>
#include <string>
#include "hiperf_hilog.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
namespace HiPerfLocal {
static constexpr char PERF_RECORD_TYPE_SAMPLE[] = "sample";
static constexpr uint32_t RECORD_SIZE_LIMIT = 65535;
static constexpr ssize_t ERRINFOLEN = 512;

struct LperfRecordSampleData {
    uint32_t pid = 0;
    uint32_t tid = 0;                       /* if PERF_SAMPLE_TID */
    uint64_t time = 0;                      /* if PERF_SAMPLE_TIME */
    uint64_t nr = 0;                        /* if PERF_SAMPLE_CALLCHAIN */
    uint64_t* ips = nullptr;                /* if PERF_SAMPLE_CALLCHAIN */
};

class LperfRecordSample {
public:
    LperfRecordSampleData data_ = {};

    LperfRecordSample() = default;

    const char* GetName()
    {
        return PERF_RECORD_TYPE_SAMPLE;
    }

    uint32_t GetType() const
    {
        return header_.type;
    }

    bool Init(uint8_t* data);

    void Clear();

protected:
    void InitHeader(uint8_t* p);

private:
    struct perf_event_header header_ = {};
    uint64_t sampleType_ = PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_TIME;
};

class LperfRecordFactory {
public:
    static LperfRecordSample& GetLperfRecord(uint32_t type, uint8_t* data);
    static void ClearData();

private:
    static LperfRecordSample record_;
};

template<typename T>
bool PopFromBinary(bool condition, uint8_t*& p, T& v, uint64_t& size);

template<typename T1, typename T2>
bool PopFromBinary2(bool condition, uint8_t*& p, T1& v1, T2& v2, uint64_t& size);

bool SetPointerOffset(uint8_t*& p, uint64_t offset, uint64_t& size);

#define NO_RETVAL /* retval */
#ifndef CHECK_TRUE_AND_RET
#define CHECK_TRUE_AND_RET(condition, retval, fmt, ...)                                            \
    do {                                                                                           \
        if (!(condition)) [[unlikely]] {                                                           \
            std::string str = StringFormat(fmt, ##__VA_ARGS__);                                    \
            HIPERF_HILOGE(MODULE_DEFAULT, "%{public}s", str.c_str());                              \
            return retval;                                                                         \
        }                                                                                          \
    } while (0)
#endif

#ifndef CHECK_ERR
#define CHECK_ERR(err, fmt, ...)                                                                   \
    do {                                                                                           \
        if (err < 0) [[unlikely]] {                                                                \
            char errInfo[ERRINFOLEN] = { 0 };                                                      \
            strerror_r(errno, errInfo, ERRINFOLEN);                                                \
            HIPERF_HILOGE(MODULE_DEFAULT, "%{public}s, error: %{public}d, errInfo: %{public}s",    \
                          StringFormat(fmt, ##__VA_ARGS__).c_str(), errno, errInfo);               \
            return false;                                                                          \
        }                                                                                          \
    } while (0)
#endif
} // namespace HiPerfLocal
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // LPERF_EVENT_RECORD_H