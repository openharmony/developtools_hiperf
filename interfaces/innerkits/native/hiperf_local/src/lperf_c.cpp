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

#include "lperf_c.h"

#include <string>
#include <vector>

#include "hiperf_hilog.h"
#include "lperf.h"

using namespace OHOS::Developtools::HiPerf::HiPerfLocal;

#ifdef __cplusplus
extern "C" {
#endif
    int LperfStartProcessStackSampling(int* tids, int tidsSize, int freq, int milliseconds, bool parseMiniDebugInfo)
    {
        std::vector<int> tidList(tids, tids + tidsSize);
        return Lperf::GetInstance().StartProcessStackSampling(tidList, freq, milliseconds, parseMiniDebugInfo);
    }

    int LperfCollectSampleStackByTid(int tid, char* stackBuf, int bufSize)
    {
        std::string stackStr;
        int ret = Lperf::GetInstance().CollectSampleStackByTid(tid, stackStr);
        if (ret < 0) {
            return ret;
        }
        if (strncpy_s(stackBuf, bufSize, stackStr.c_str(), stackStr.length()) != 0) {
            HIPERF_HILOGE(MODULE_DEFAULT, "Error: strncpy_s stackStr: %{public}s failed", stackStr.c_str());
            return -1;
        }
        return 0;
    }

    int LperfCollectHeaviestStackByTid(int tid, char* stackBuf, int bufSize)
    {
        std::string stackStr;
        int ret = Lperf::GetInstance().CollectHeaviestStackByTid(tid, stackStr);
        if (ret < 0) {
            return ret;
        }
        if (strncpy_s(stackBuf, bufSize, stackStr.c_str(), stackStr.length()) != 0) {
            HIPERF_HILOGE(MODULE_DEFAULT, "Error: strncpy_s stackStr: %{public}s failed", stackStr.c_str());
            return -1;
        }
        return 0;
    }

    int LperfFinishProcessStackSampling()
    {
        return Lperf::GetInstance().FinishProcessStackSampling();
    }
#ifdef __cplusplus
}
#endif
