/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "PerfFile_fuzzer.h"
#include "utilities.h"

namespace OHOS {
using namespace OHOS::Developtools::HiPerf;
class PerfFileReaderFuzzer : public PerfFileReader {
public:
    explicit PerfFileReaderFuzzer(const std::string &fileName, FILE *fp)
        : PerfFileReader(fileName, fp) {}

    static std::unique_ptr<PerfFileReaderFuzzer> Instance(const std::string &fileName,
                                                          const uint8_t *data, size_t size)
    {
        std::string resolvedPath = CanonicalizeSpecPath(fileName.c_str());
        FILE *fpApp = fopen(resolvedPath.c_str(), "ab");
        if (fpApp == nullptr) {
            printf("fail to append file %s\n", fileName.c_str());
            return nullptr;
        } else {
            (void)fwrite(data, sizeof(uint8_t), size, fpApp);
            (void)fclose(fpApp);
            fpApp = nullptr;
        }
        FILE *fp = fopen(resolvedPath.c_str(), "rb");
        if (fp == nullptr) {
            printf("fail to open file %s\n", fileName.c_str());
            return nullptr;
        }

        std::unique_ptr<PerfFileReaderFuzzer> reader =
            std::make_unique<PerfFileReaderFuzzer>(resolvedPath, fp);

        if (!reader->ReadFileHeader()) {
            printf("head read error\n");
            return nullptr;
        }
        if (!reader->ReadAttrSection()) {
            printf("attr read error\n");
            return nullptr;
        }
        return reader;
    };
};

bool FuzzPerfFileReader(const uint8_t *data, size_t size)
{
    const std::string testData = "/data/test/resource/testdata/report_test.data";
    HLOGV("test data size %zu\n", size);
    if (size == 0) {
        return false;
    }
    auto reader = PerfFileReaderFuzzer::Instance(testData, data, size);
    if (reader == nullptr) {
        printf("test open failed %s\n", testData.c_str());
        return false;
    }

    reader->ReadFeatureSection();
    auto recordCallback = [&](const std::unique_ptr<PerfEventRecord> &record) {
        // nothing to do
        return true;
    };
    reader->ReadDataSection(recordCallback);
    return false;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#ifdef DEBUG_HIPERF_FUZZ
    OHOS::ScopeDebugLevel mix(OHOS::LEVEL_VERBOSE, true);
    OHOS::DebugLogger::GetInstance()->Disable(false);
#else
    OHOS::Developtools::HiPerf::StdoutRecord noStdOut("/dev/null", "w");
#endif

    /* Run your code on data */
    OHOS::FuzzPerfFileReader(data, size);
    return 0;
}
