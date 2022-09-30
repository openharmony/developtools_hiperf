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

#include "LibReport_fuzzer.h"

namespace OHOS {
bool FuzzLibReport(const uint8_t *data, size_t size)
{
    char buf[DATA_MAX_SIZE] = { 0 };
    if (memcpy_s(buf, sizeof(buf) - 1, data, size) != 0) { // 1 ：  make sure end of '\0'
        return false;
    }
    const char *dataPtr = reinterpret_cast<const char *>(buf);

    EchoLoopBack(dataPtr);
    Report(dataPtr, dataPtr, dataPtr);
    ReportJson(dataPtr, dataPtr);
    ReportUnwindJson(dataPtr, dataPtr, dataPtr);
    Dump(dataPtr);
    ReportGetSymbolFiles(dataPtr);
    ReportGetBuildId(dataPtr);
    ReportGetElfArch(dataPtr);

    return 0;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#ifdef DEBUG_HIPERF_FUZZ
    ScopeDebugLevel mix(LEVEL_VERBOSE, true);
    DebugLogger::GetInstance()->Disable(false);
#else
    OHOS::Developtools::HiPerf::StdoutRecord noStdOut("/dev/null", "w");
#endif
    /* Run your code on data */
    OHOS::FuzzLibReport(data, size);
    return 0;
}
