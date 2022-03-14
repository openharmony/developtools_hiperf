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

#include "ElfParser_fuzzer.h"

namespace OHOS {
using namespace OHOS::Developtools::HiPerf;
using namespace OHOS::Developtools::HiPerf::ELF;
class ElfFileFuzzer : public ElfFile {
public:
    const char *dataPtr_ = nullptr;
    size_t dataSize_ = 0;
    size_t FuzzerTime_ = 0; // when we make a fuzzer read

    ssize_t ReadFile(void *buf, size_t len) override
    {
        if (FuzzerTime_ != 0 or dataSize_ == 0) {
            FuzzerTime_--;
            return ElfFile::ReadFile(buf, len);
        } else {
            HLOGV("fuzz read %zu/%zu\n", dataSize_, len);
            if (ElfFile::ReadFile(buf, len) != 0) {
                std::copy(dataPtr_, dataPtr_ + std::min(len, dataSize_),
                          reinterpret_cast<char *>(buf));
            }
            return len;
        }
    }

    explicit ElfFileFuzzer(const std::string &filename) : ElfFile(filename) {}

    static std::unique_ptr<ElfFileFuzzer> MakeUnique(const std::string &filename,
                                                     const uint8_t *data, size_t size)
    {
        std::unique_ptr<ElfFileFuzzer> file = std::make_unique<ElfFileFuzzer>(filename);
        if (file == nullptr) {
            HLOGE("Error in ElfFile::MakeUnique(): ElfFile::ElfFile() failed");
            return nullptr;
        }
        file->dataPtr_ = reinterpret_cast<const char *>(data);
        file->dataSize_ = size;
        file->FuzzerTime_ = size;
        if (!file->IsOpened()) {
            HLOGE("Error in ElfFile::MakeUnique(): elf file not opended");
            return nullptr;
        }
        if (!file->ParseFile()) {
            HLOGE("parse elf file failed");
            return nullptr;
        }
        return file;
    }
};

bool FuzzElfFile(const uint8_t *data, size_t size)
{
    const std::string testData = "/data/test/resource/testdata/elf_test";
    HLOGV("test data size %zu\n", size);
    if (size == 0) {
        return 0;
    }
    ElfFileFuzzer::MakeUnique(testData, data, size);
    return 0;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#ifdef DEBUG_HIPERF_FUZZ
    ScopeDebugLevel mix(LEVEL_DEBUG, true);
    DebugLogger::GetInstance()->Disable(false);
#else
    OHOS::Developtools::HiPerf::StdoutRecord noStdOut("/dev/null", "w");
#endif
    /* Run your code on data */
    OHOS::FuzzElfFile(data, size);
    return 0;
}
