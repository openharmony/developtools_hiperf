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
    explicit ElfFileFuzzer(const std::string &filename) : ElfFile(filename) {}

    static std::unique_ptr<ElfFileFuzzer> MakeUnique(const std::string &filename,
                                                     const uint8_t *data, size_t size)
    {
        std::unique_ptr<ElfFileFuzzer> file = std::make_unique<ElfFileFuzzer>(filename);
        if (file == nullptr) {
            HLOGE("Error in ElfFile::MakeUnique(): ElfFile::ElfFile() failed");
            return nullptr;
        }
        if (!file->IsOpened()) {
            HLOGE("Error in ElfFile::MakeUnique(): elf file not opened");
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
        return true;
    }
    FILE *fp = fopen(testData.c_str(), "ab");
    if (fp == nullptr) {
        printf("fail to append file %s\n", testData.c_str());
        return false;
    } else {
        (void)fwrite(data, sizeof(uint8_t), size, fp);
        (void)fclose(fp);
    }
    ElfFileFuzzer::MakeUnique(testData, data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#ifdef DEBUG_HIPERF_FUZZ
    OHOS::ScopeDebugLevel mix(OHOS::LEVEL_DEBUG, true);
    OHOS::DebugLogger::GetInstance()->Disable(false);
#else
    OHOS::Developtools::HiPerf::StdoutRecord noStdOut("/dev/null", "w");
#endif
    /* Run your code on data */
    OHOS::FuzzElfFile(data, size);
    return 0;
}
