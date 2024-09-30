/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "PerfFileFormat_fuzzer.h"
#include "perf_file_format.h"

using namespace OHOS::Developtools::HiPerf;

namespace OHOS {
bool FuzzPerfFileFormat(const uint8_t *data, size_t size)
{
    char buf[DATA_MAX_SIZE] = { 0 };
    if (memcpy_s(buf, sizeof(buf) - 1, data, size) != 0) { // 1 ：  make sure end of '\0'
        return false;
    }
    std::unique_ptr<PerfFileSectionString> perfFileSectionString =
        std::make_unique<PerfFileSectionString>(FEATURE::HIPERF_FILES_SYMBOL, buf, size);
    perfFileSectionString->GetBinary(buf, size);
    std::unique_ptr<PerfFileSectionNrCpus> perfFileSectionNrCpus =
        std::make_unique<PerfFileSectionNrCpus>(FEATURE::HIPERF_FILES_SYMBOL, buf, size);
    perfFileSectionNrCpus->GetBinary(buf, size);
    std::unique_ptr<PerfFileSectionU64> perfFileSectionU64 =
        std::make_unique<PerfFileSectionU64>(FEATURE::HIPERF_FILES_SYMBOL, buf, size);
    perfFileSectionU64->GetBinary(buf, size);
    return 0;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
/* Run your code on data */
#ifdef DEBUG_HIPERF_FUZZ
    ScopeDebugLevel mix(LEVEL_DEBUG, true);
    DebugLogger::GetInstance()->Disable(false);
#else
    OHOS::Developtools::HiPerf::StdoutRecord noStdOut("/dev/null", "w");
#endif

    OHOS::FuzzPerfFileFormat(data, size);
    return 0;
}
