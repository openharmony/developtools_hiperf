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

#include "PerfFile_fuzzer.h"

namespace OHOS {
using namespace OHOS::Developtools::HiPerf;
class PerfFileReaderFuzzer : public PerfFileReader {
public:
    const char *dataPtr_ = nullptr;
    size_t dataSize_ = 0;
    size_t FuzzerTime_ = 0; // when we make a fuzzer read

    bool Read(void *buf, size_t len) override
    {
        if (FuzzerTime_ != 0 or dataSize_ == 0) {
            FuzzerTime_--;
            return PerfFileReader::Read(buf, len);
        } else {
            HLOGD("fuzz read %zu/%zu\n", dataSize_, len);
            if (PerfFileReader::Read(buf, len)) {
                std::copy(dataPtr_, dataPtr_ + std::min(len, dataSize_),
                          reinterpret_cast<char *>(buf));
                return true;
            } else {
                return false;
            }
        }
    }

    bool Read(char *buf, [[maybe_unused]] uint64_t offset, size_t len) override
    {
        if (FuzzerTime_ != 0 or dataSize_ == 0) {
            FuzzerTime_--;
            return PerfFileReader::Read(buf, offset, len);
        } else {
            HLOGD("fuzz read %zu/%zu\n", dataSize_, len);
            if (PerfFileReader::Read(buf, offset, len)) {
                std::copy(dataPtr_, dataPtr_ + std::min(len, dataSize_),
                          reinterpret_cast<char *>(buf));
                return true;
            } else {
                return false;
            }
        }
    }

    explicit PerfFileReaderFuzzer(const std::string &fileName, FILE *fp)
        : PerfFileReader(fileName, fp) {};

    static std::unique_ptr<PerfFileReaderFuzzer> Instance(const std::string &fileName,
                                                          const uint8_t *data, size_t size)
    {
        FILE *fp = fopen(fileName.c_str(), "rb");
        if (fp == nullptr) {
            HLOGE("fail to open file %s", fileName.c_str());
            return nullptr;
        }

        std::unique_ptr<PerfFileReaderFuzzer> reader =
            std::make_unique<PerfFileReaderFuzzer>(fileName, fp);

        reader->dataPtr_ = reinterpret_cast<const char *>(data);
        reader->dataSize_ = size;
        reader->FuzzerTime_ = size;
        if (!reader->ReadFileHeader()) {
            printf("head read error");
            return nullptr;
        }
        if (!reader->ReadAttrSection()) {
            printf("attr read error");
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
        return 0;
    }
    auto reader = PerfFileReaderFuzzer::Instance(testData, data, size);
    if (reader == nullptr) {
        printf("test open failed %s\n", testData.c_str());
        return 0;
    }

    reader->ReadFeatureSection();
    auto recordCallback = [&](const std::unique_ptr<PerfEventRecord> &record) {
        // nothing to do
        return true;
    };
    reader->ReadDataSection(recordCallback);
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
    OHOS::FuzzPerfFileReader(data, size);
    return 0;
}
