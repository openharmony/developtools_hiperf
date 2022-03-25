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
std::unique_ptr<ProgramHeader> ProgramHeader::MakeUnique(char * const phdrBuf, const size_t bufSize)
{
    std::unique_ptr<ProgramHeader> phdr {new (std::nothrow) ProgramHeader()};
    if (phdr == nullptr) {
        HLOGE("ProgramHeader() failed");
        return nullptr;
    }
    if (!phdr->Init(phdrBuf, bufSize)) {
        HLOGE("ProgramHeader::Init(phdrBuf, bufSize) failed");
        DumpPhdrBuf(phdrBuf, bufSize);
        return nullptr;
    }
    return phdr;
}

bool ProgramHeader::ParsePrgHeader32(char * const phdrBuf)
{
    uint32_t *u4Buf = reinterpret_cast<uint32_t *>(phdrBuf);
    size_t index {0};
    type_ = u4Buf[index];
    ++index;
    offset_ = u4Buf[index];
    ++index;
    vaddr_ = u4Buf[index];
    ++index;
    paddr_ = u4Buf[index];
    ++index;
    fileSize_ = u4Buf[index];
    ++index;
    memSize_ = u4Buf[index];
    ++index;
    flags_ = u4Buf[index];
    ++index;
    secAlign_ = u4Buf[index];
    return true;
}

bool ProgramHeader::ParsePrgHeader64(char * const phdrBuf)
{
    uint32_t *u4Buf = reinterpret_cast<uint32_t *>(phdrBuf);
    size_t index {0};
    type_ = u4Buf[index];
    ++index;
    flags_ = u4Buf[index];

    uint64_t *u8Buf = reinterpret_cast<uint64_t *>(phdrBuf);
    offset_ = u8Buf[index];
    ++index;
    vaddr_ = u8Buf[index];
    ++index;
    paddr_ = u8Buf[index];
    ++index;
    fileSize_ = u8Buf[index];
    ++index;
    memSize_ = u8Buf[index];
    ++index;
    secAlign_ = u8Buf[index];
    return true;
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
