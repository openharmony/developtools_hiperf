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

#include "lperf.h"
#include "hiperf_hilog.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
namespace HiPerfLocal {

Lperf& Lperf::GetInstance()
{
    static Lperf lperfInstance;
    return lperfInstance;
}

int Lperf::StartProcessStackSampling(const std::vector<int>& tids, int freq, int milliseconds, bool parseMiniDebugInfo)
{
    bool expected = false;
    if (!isRunning_.compare_exchange_strong(expected, true)) {
        HIPERF_HILOGE(MODULE_DEFAULT, "Process is being sampled.");
        return -1;
    }

    int res = lperfRecord_.StartProcessSampling(tids, freq, milliseconds, parseMiniDebugInfo);
    isRunning_.store(false);
    return res;
}

int Lperf::CollectSampleStackByTid(int tid, std::string& stack)
{
    return lperfRecord_.CollectSampleStack(tid, stack);
}

int Lperf::CollectHeaviestStackByTid(int tid, std::string& stack)
{
    return lperfRecord_.CollectHeaviestStack(tid, stack);
}

int Lperf::FinishProcessStackSampling()
{
    return lperfRecord_.FinishProcessSampling();
}
} // namespace HiPerfLocal
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS