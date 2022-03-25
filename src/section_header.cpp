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

#include <elf_parser.h>

using namespace OHOS::Developtools::HiPerf::ELF;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
enum class NUMBER : int {
    ZERO = 0,
    ONE = 1,
    TWO = 2,
    THREE = 3,
    FOUR = 4,
    FIVE = 5,
    SIX = 6,
    SEVEN = 7,
    EIGHT = 8,
    NINE = 9,
    TEN = 10,
    ELEVEN = 11,
    TWELVE = 12,
};

std::unique_ptr<SectionHeader> SectionHeader::MakeUnique(char * const shdrBuf, const size_t bufSize,
                                                         const size_t index)
{
    std::unique_ptr<SectionHeader> shdr {new (std::nothrow) SectionHeader()};
    if (shdr == nullptr) {
        return nullptr;
    }
    if (!shdr->Init(shdrBuf, bufSize, index)) {
        HLOGE("SectionHeader::Init(shdrBuf, bufSize, index) failed");
        DumpShdrBuf(shdrBuf, bufSize);
        return nullptr;
    }
    return shdr;
}

bool SectionHeader::ParseSecHeader32(char * const shdrBuf)
{
    uint32_t *u4Buf = reinterpret_cast<uint32_t *>(shdrBuf);
    int index {0};
    nameIndex_ = u4Buf[index];
    index = static_cast<int>(NUMBER::ONE);
    secType_ = u4Buf[index];
    index = static_cast<int>(NUMBER::TWO);
    secFlags_ = u4Buf[index];
    index = static_cast<int>(NUMBER::SIX);
    link_ = u4Buf[index];
    index = static_cast<int>(NUMBER::SEVEN);
    info_ = u4Buf[index];
    index = static_cast<int>(NUMBER::THREE);
    secVaddr_ = u4Buf[index];
    index = static_cast<int>(NUMBER::FOUR);
    fileOffset_ = u4Buf[index];
    index = static_cast<int>(NUMBER::FIVE);
    secSize_ = u4Buf[index];
    index = static_cast<int>(NUMBER::EIGHT);
    secAddrAlign_ = u4Buf[index];
    index = static_cast<int>(NUMBER::NINE);
    secEntrySize_ = u4Buf[index];
    return true;
}

bool SectionHeader::ParseSecHeader64(char * const shdrBuf)
{
    uint64_t *u8Buf = reinterpret_cast<uint64_t *>(shdrBuf);
    uint32_t *u4Buf = reinterpret_cast<uint32_t *>(shdrBuf);
    size_t index {0};
    nameIndex_ = u4Buf[index];
    index = static_cast<size_t>(NUMBER::ONE);
    secType_ = u4Buf[index];
    secFlags_ = u8Buf[index];
    index = static_cast<size_t>(NUMBER::TEN);
    link_ = u4Buf[index];
    index = static_cast<size_t>(NUMBER::ELEVEN);
    info_ = u4Buf[index];
    index = static_cast<size_t>(NUMBER::TWO);
    secVaddr_ = u8Buf[index];
    index = static_cast<size_t>(NUMBER::THREE);
    fileOffset_ = u8Buf[index];
    index = static_cast<size_t>(NUMBER::FOUR);
    secSize_ = u8Buf[index];
    index = static_cast<size_t>(NUMBER::SIX);
    secAddrAlign_ = u8Buf[index];
    index = static_cast<size_t>(NUMBER::SEVEN);
    secEntrySize_ = u8Buf[index];
    return true;
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
