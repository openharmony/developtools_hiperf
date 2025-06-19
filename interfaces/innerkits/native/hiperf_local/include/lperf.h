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
#ifndef LPERF_H
#define LPERF_H

#include "lperf_record.h"

#include <atomic>
#include <string>
#include <vector>

namespace OHOS {
namespace Developtools {
namespace HiPerf {
namespace HiPerfLocal {
class Lperf {
public:
    Lperf() = default;
    ~Lperf() = default;

    static Lperf& GetInstance();
    int StartProcessStackSampling(const std::vector<int>& tids, int freq, int milliseconds, bool parseMiniDebugInfo);
    int CollectSampleStackByTid(int tid, std::string& stack);
    int CollectHeaviestStackByTid(int tid, std::string& stack);
    int FinishProcessStackSampling();

private:
    LperfRecord lperfRecord_;
    std::atomic<bool> isRunning_{false};
};
} // namespace HiPerfLocal
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // LPERF_H