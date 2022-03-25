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

#include <elf_parser.h>

namespace OHOS {
namespace Developtools {
namespace HiPerf {
namespace ELF {
std::unique_ptr<ElfHeader> ElfHeader::MakeUnique(unsigned char * const ehdrBuf,
                                                 const std::size_t bufSize)
{
    std::unique_ptr<ElfHeader> ehdr {new (std::nothrow) ElfHeader()};
    if (ehdr == nullptr) {
        HLOGV("ElfHeader() failed");
        return nullptr;
    }
    if (!ehdr->Init(ehdrBuf, bufSize)) {
        HLOGV("ElfHeader::Init(ehdrBuf, bufSize) failed\n");
        DumpEhdrBuf(reinterpret_cast<char *>(ehdrBuf), bufSize);
        return nullptr;
    }
    return ehdr;
}

bool ElfHeader::Init(unsigned char * const ehdrBuf, const std::size_t bufSize)
{
    std::string magicStr {ehdrBuf, ehdrBuf + SELFMAG};
    std::string elfMagic {ELFMAG};
    if (magicStr.compare(elfMagic) != 0) {
        HLOGE("elf magic not found");
        return false;
    }
    if (memcpy_s(ehdrIdent_, EI_NIDENT, ehdrBuf, EI_NIDENT) != 0) {
        HLOGE("init ehdrIdent_ failed");
        return false;
    }
    if (ehdrBuf[EI_CLASS] == ELFCLASS32 and ParseElf32Header(ehdrBuf, bufSize)) {
        return true;
    }
    if (ehdrBuf[EI_CLASS] == ELFCLASS64 and ParseElf64Header(ehdrBuf, bufSize)) {
        return true;
    }
    HLOGE("init elf header failed, elf header buffer dumped");
    return false;
}

bool ElfHeader::ParseElf32Header(unsigned char * const ehdrBuf, const std::size_t bufSize)
{
    if (bufSize < ehdr32Size) {
        HLOGE("bad elf32 header buffer");
        return false;
    }
    size_t curIndex {EI_NIDENT};
    uint16_t *u2Buf = reinterpret_cast<uint16_t *>(ehdrBuf + curIndex);
    type_ = u2Buf[0];
    curIndex += sizeof(uint16_t);

    u2Buf = reinterpret_cast<uint16_t *>(ehdrBuf + curIndex);
    machine_ = u2Buf[0];
    curIndex += sizeof(uint16_t);

    uint32_t *u4Buf = reinterpret_cast<uint32_t *>(ehdrBuf + curIndex);
    elfVersion_ = u4Buf[0];
    curIndex += sizeof(uint32_t);

    u4Buf = reinterpret_cast<uint32_t *>(ehdrBuf + curIndex);
    prgEntryVaddr_ = u4Buf[0];
    curIndex += sizeof(uint32_t);

    u4Buf = reinterpret_cast<uint32_t *>(ehdrBuf + curIndex);
    phdrOffset_ = u4Buf[0];
    curIndex += sizeof(uint32_t);

    u4Buf = reinterpret_cast<uint32_t *>(ehdrBuf + curIndex);
    shdrOffset_ = u4Buf[0];
    curIndex += sizeof(uint32_t);

    u4Buf = reinterpret_cast<uint32_t *>(ehdrBuf + curIndex);
    ehdrFlags_ = u4Buf[0];
    curIndex += sizeof(uint32_t);

    u2Buf = reinterpret_cast<uint16_t *>(ehdrBuf + curIndex);
    ehdrSize_ = u2Buf[0];
    curIndex += sizeof(uint16_t);

    u2Buf = reinterpret_cast<uint16_t *>(ehdrBuf + curIndex);
    phdrEntSize_ = u2Buf[0];
    curIndex += sizeof(uint16_t);

    u2Buf = reinterpret_cast<uint16_t *>(ehdrBuf + curIndex);
    phdrNumEnts_ = u2Buf[0];
    curIndex += sizeof(uint16_t);

    u2Buf = reinterpret_cast<uint16_t *>(ehdrBuf + curIndex);
    shdrEntSize_ = u2Buf[0];
    curIndex += sizeof(uint16_t);

    u2Buf = reinterpret_cast<uint16_t *>(ehdrBuf + curIndex);
    shdrNumEnts_ = u2Buf[0];
    curIndex += sizeof(uint16_t);

    u2Buf = reinterpret_cast<uint16_t *>(ehdrBuf + curIndex);
    shdrStrTabIdx_ = u2Buf[0];

#ifdef HIPERF_DEBUG_ASSERT
    curIndex += sizeof(uint16_t);
    HLOG_ASSERT(curIndex == ehdrSize_);
    HLOG_ASSERT(shdr32Size == ehdrSize_);
#endif
    return true;
}

bool ElfHeader::ParseElf64Header(unsigned char * const ehdrBuf, const std::size_t bufSize)
{
    if (bufSize < ehdr64Size) {
        HLOGE("bad elf64 header buffer");
        return false;
    }
    size_t curIndex {EI_NIDENT};
    uint16_t *u2Buf = reinterpret_cast<uint16_t *>(ehdrBuf + curIndex);
    type_ = u2Buf[0];
    curIndex += sizeof(uint16_t);

    u2Buf = reinterpret_cast<uint16_t *>(ehdrBuf + curIndex);
    machine_ = u2Buf[0];
    curIndex += sizeof(uint16_t);

    uint32_t *u4Buf = reinterpret_cast<uint32_t *>(ehdrBuf + curIndex);
    elfVersion_ = u4Buf[0];
    curIndex += sizeof(uint32_t);

    uint64_t *u8Buf = reinterpret_cast<uint64_t *>(ehdrBuf + curIndex);
    prgEntryVaddr_ = u8Buf[0];
    curIndex += sizeof(uint64_t);

    u8Buf = reinterpret_cast<uint64_t *>(ehdrBuf + curIndex);
    phdrOffset_ = u8Buf[0];
    curIndex += sizeof(uint64_t);

    u8Buf = reinterpret_cast<uint64_t *>(ehdrBuf + curIndex);
    shdrOffset_ = u8Buf[0];
    curIndex += sizeof(uint64_t);

    u4Buf = reinterpret_cast<uint32_t *>(ehdrBuf + curIndex);
    ehdrFlags_ = u4Buf[0];
    curIndex += sizeof(uint32_t);

    u2Buf = reinterpret_cast<uint16_t *>(ehdrBuf + curIndex);
    ehdrSize_ = u2Buf[0];
    curIndex += sizeof(uint16_t);

    u2Buf = reinterpret_cast<uint16_t *>(ehdrBuf + curIndex);
    phdrEntSize_ = u2Buf[0];
    curIndex += sizeof(uint16_t);

    u2Buf = reinterpret_cast<uint16_t *>(ehdrBuf + curIndex);
    phdrNumEnts_ = u2Buf[0];
    curIndex += sizeof(uint16_t);

    u2Buf = reinterpret_cast<uint16_t *>(ehdrBuf + curIndex);
    shdrEntSize_ = u2Buf[0];
    curIndex += sizeof(uint16_t);

    u2Buf = reinterpret_cast<uint16_t *>(ehdrBuf + curIndex);
    shdrNumEnts_ = static_cast<long long>(*u2Buf);
    curIndex += sizeof(uint16_t);

    u2Buf = reinterpret_cast<uint16_t *>(ehdrBuf + curIndex);
    shdrStrTabIdx_ = u2Buf[0];

#ifdef HIPERF_DEBUG_ASSERT
    curIndex += sizeof(uint16_t);
    HLOG_ASSERT(curIndex == ehdrSize_);
    HLOG_ASSERT(shdr64Size == ehdrSize_);
#endif
    return true;
}
} // namespace ELF
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
