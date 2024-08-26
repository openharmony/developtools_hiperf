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

#include "SpeDecoder_fuzzer.h"
#include "spe_decoder.h"

using namespace OHOS::Developtools::HiPerf;

namespace OHOS {
bool FuzzSpeDecoder(const uint8_t *data, size_t size)
{
    SpeDecoder *decoder = SpeDecoderDataNew(data, size);
    std::vector<SpeRecord> records;
    int ret = SpeDecode(decoder);
    if (ret <= 0) {
        printf("SpeDecode failed.\n");
    }
    struct SpeRecord record = SpeRecord(decoder->record);
    records.emplace_back(record);
    SpeDecoderFree(decoder);
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

    OHOS::FuzzSpeDecoder(data, size);
    return 0;
}
