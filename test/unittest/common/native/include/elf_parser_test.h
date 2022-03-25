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

#ifndef HIPERF_ELF_PARSER_TEST_H
#define HIPERF_ELF_PARSER_TEST_H

#if !is_ohos
// this is not good enough
#include <../musl/include/elf.h>
#else
#include <elf.h>
#endif
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <hilog/log.h>

#include "elf_parser.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
namespace UnitTest {
class EhdrFromReadelf {
public:
    static std::unique_ptr<EhdrFromReadelf> MakeUnique(FILE *fp);
    bool Init(FILE *fp);

    unsigned char ehdrIdent_[EI_NIDENT];
    uint16_t ehdrSize_;
    uint16_t phdrEntSize_;
    uint16_t phdrNumEnts_;
    uint16_t shdrEntSize_;
    uint16_t shdrNumEnts_;
    uint16_t shdrStrTabIdx_;
    uint32_t ehdrFlags_;
    uint64_t prgEntryVaddr_;
    uint64_t phdrOffset_;
    uint64_t shdrOffset_;

private:
    explicit EhdrFromReadelf() = default;
    bool GetMagic(FILE * const fp);
    bool GetEntryAddr(FILE * const fp);
    bool GetPrgOffset(FILE * const fp);
    bool GetSecOffset(FILE * const fp);
    bool GetFlag(FILE * const fp);
    bool GetEhdrSize(FILE * const fp);
    bool GetPhdrSize(FILE * const fp);
    bool GetNumPhdrs(FILE * const fp);
    bool GetShdrSize(FILE * const fp);
    bool GetNumShdrs(FILE * const fp);
    bool GetShdrStrTabIdx(FILE * const fp);
};

class PhdrFromReadelf {
public:
    static std::unique_ptr<PhdrFromReadelf> MakeUnique(const std::string &line);
    bool Init(const std::string &line);

    uint64_t offset_ {0};
    uint64_t vaddr_ {0};
    uint64_t paddr_ {0};
    uint64_t fileSize_ {0};
    uint64_t memSize_ {0};
    uint64_t secAlign_ {0};

private:
    explicit PhdrFromReadelf() = default;
    int64_t GetOffset(const std::string &line);
    int64_t GetVaddr(const std::string &line);
    int64_t GetPaddr(const std::string &line);
    int64_t GetFileSize(const std::string &line);
    int64_t GetMemSize(const std::string &line);
    int64_t GetAlign(const std::string &line);
};

class ShdrFromReadelf {
public:
    static std::unique_ptr<ShdrFromReadelf> MakeUnique(const std::string &line);
    bool Init(const std::string &line);

    inline const std::string GetSecName()
    {
        return secName_;
    }

    uint32_t link_ {0};
    uint32_t info_ {0};
    uint64_t secVaddr_ {0};
    uint64_t fileOffset_ {0};
    uint64_t secSize_ {0};
    uint64_t secAddrAlign_ {0};
    uint64_t secEntrySize_ {0};
    uint32_t secIndex_ {0};
    std::string secName_ {};

private:
    explicit ShdrFromReadelf() = default;
    int64_t GetSecIndex(const std::string &line);
    const std::string GetName(const std::string &line);
    int64_t GetAddress(const std::string &line);
    int64_t GetFileOffset(const std::string &line);
    int64_t GetSecSize(const std::string &line);
    int64_t GetEntrySize(const std::string &line);
    int64_t GetLink(const std::string &line);
    int64_t GetInfo(const std::string &line);
    int64_t GetAlign(const std::string &line);
};

class ElfSymbolFromReadelf {
public:
    static std::unique_ptr<ElfSymbolFromReadelf> MakeUnique(const std::string &line);
    bool Init(const std::string &line);

    uint32_t num_ {0};
    uint64_t value_ {0};
    uint64_t size_ {0};
    std::string name_ {};

private:
    explicit ElfSymbolFromReadelf() = default;
    int64_t GetNum(const std::string &line);
    int64_t GetValue(const std::string &line);
    int64_t GetSize(const std::string &line);
    const std::string GetName(const std::string &line);
};

class ElfFileFromReadelf {
public:
    enum class ElfFileType {
        ELF32,
        ELF64,
    };
    ~ElfFileFromReadelf();
    static std::unique_ptr<ElfFileFromReadelf> MakeUnique(ElfFileType fileType);
    bool Init();

    std::unique_ptr<EhdrFromReadelf> ehdr_ {nullptr};
    std::vector<std::unique_ptr<ShdrFromReadelf>> shdrs_;
    std::vector<std::unique_ptr<PhdrFromReadelf>> phdrs_;
    std::vector<std::unique_ptr<ElfSymbolFromReadelf>> syms_;
    std::vector<std::unique_ptr<ElfSymbolFromReadelf>> dynSyms_;

private:
    explicit ElfFileFromReadelf(ElfFileType fileType);
    bool ParseElfHeader();
    bool ParsePrgHeaders64();
    bool ParsePrgHeaders32();
    bool ParseSecHeaders64();
    bool ParseSecHeaders32();
    bool ParseSymTable();
    bool IsOpened();
    bool ParseSymsInSymTab();
    bool ParseSymsInDynSym();
    const std::string GetNextPhdrLine();
    const std::string GetNextShdrLine();
    const std::string GetNextSymLine();

    FILE *ehdrFP_ {nullptr};
    FILE *shdrsFP_ {nullptr};
    FILE *phdrsFP_ {nullptr};
    FILE *symTabFP_ {nullptr};
};
} // namespace UnitTest
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_ELF_PARSER_TEST_H
