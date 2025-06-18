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
#ifndef LPERF_RECORD_H
#define LPERF_RECORD_H

#include <map>
#include <string>
#include "unwinder.h"
#include "stack_printer.h"

#include "lperf_events.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
namespace HiPerfLocal {
using namespace OHOS::HiviewDFX;

class LperfRecord {
public:
    static constexpr int MIN_SAMPLE_COUNT = 1;
    static constexpr int MAX_SAMPLE_COUNT = 10;
    static constexpr int MIN_SAMPLE_FREQUENCY = 1;
    static constexpr int MAX_SAMPLE_FREQUENCY = 100;
    static constexpr int MIN_STOP_SECONDS = 1;
    static constexpr int MAX_STOP_SECONDS = 10000;
    static constexpr uint32_t UNIQUE_STABLE_SIZE = 1024 * 1024;

    LperfRecord();
    ~LperfRecord();

    int StartProcessSampling(std::vector<int> tids, int freq, int duration, bool parseMiniDebugInfo);
    int CollectSampleStack(int tid, std::string &stack);
    int CollectHeaviestStack(int tid, std::string &stack);
    int FinishProcessSampling();

private:
    std::map<unsigned int, std::unique_ptr<StackPrinter>> tidStackMaps_;

    LperfEvents lperfEvents_;
    unsigned int timeStopSec_ = 5;
    unsigned int frequency_ = 0;

    std::shared_ptr<Unwinder> unwinder_;
    std::shared_ptr<DfxMaps> maps_;

    std::vector<int> tids_ = {};
    bool defaultEnableDebugInfo_ = false;
    bool enableDebugInfoSymbolic_ = false;

    int OnSubCommand();
    void PrepareLperfEvent();
    void SymbolicRecord(LperfRecordSample& record);
};

template<typename T>
inline bool CheckOutOfRange(const T& value, const T& min, const T& max)
{
    return value < min || value > max;
}
} // namespace HiPerfLocal
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // LPERF_RECORD_H