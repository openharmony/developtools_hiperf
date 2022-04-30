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

#include <iostream>
#include <string>

#include <cstdio>

#include "elf_parser.h"
#include "elf_parser_test.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
using namespace OHOS::Developtools::HiPerf::ELF;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
namespace UnitTest {
namespace {
const std::string file32 {"resource/testdata/elf32_test"};
const std::string file64 {"resource/testdata/elf_test"};
const std::string ehdr32 {"resource/testdata/ehdr_from_readelf_32"};
const std::string ehdr64 {"resource/testdata/ehdr_from_readelf_64"};
const std::string shdrs32 {"resource/testdata/shdrs_from_readelf_32"};
const std::string shdrs64 {"resource/testdata/shdrs_from_readelf_64"};
const std::string phdrs32 {"resource/testdata/phdrs_from_readelf_32"};
const std::string phdrs64 {"resource/testdata/phdrs_from_readelf_64"};
const std::string syms32 {"resource/testdata/syms_from_readelf_32"};
const std::string syms64 {"resource/testdata/syms_from_readelf_64"};
} // namespace

static const std::string GetNextLine(FILE *fp, int *status)
{
    constexpr int bufSize {128};
    char buf[bufSize];
    if (memset_s(buf, sizeof(buf), '\0', sizeof(buf)) != EOK) {
        HLOGV("memset_s() failed");
        return "";
    }
    if (fgets(buf, bufSize, fp) == nullptr) {
        HLOGV("fgets() failed");
        *status = -1;
        return "";
    }
    *status = 0;
    std::string res {buf};
    if (res.back() == '\n') {
        res = res.substr(0, res.length() - 1);
    }
    return res;
}

static int MemCmp(void *p1, void *p2, std::size_t num)
{
    char *cstrp1 = static_cast<char *>(p1);
    char *cstrp2 = static_cast<char *>(p2);
    if (num == 0) {
        return 0;
    }
    for (std::size_t count = 0; count < num; ++count) {
        if (cstrp1[count] != cstrp2[count]) {
            return count;
        }
    }
    return num;
}

ElfFileFromReadelf::ElfFileFromReadelf(ElfFileType fileType)
{
    if (fileType == ElfFileType::ELF32) {
        ehdrFP_ = fopen(ehdr32.c_str(), "rb");
        if (ehdrFP_ == nullptr) {
            HLOGV("fopen(ehdr32, \"r\") failed");
        }
        shdrsFP_ = fopen(shdrs32.c_str(), "rb");
        if (shdrsFP_ == nullptr) {
            HLOGV("fopen(shdrs32, \"r\") failed");
        }
        phdrsFP_ = fopen(phdrs32.c_str(), "rb");
        if (phdrsFP_ == nullptr) {
            HLOGV("fopen(phdrs32, \"r\") failed");
        }
        symTabFP_ = fopen(syms32.c_str(), "rb");
        if (symTabFP_ == nullptr) {
            HLOGV("fopen(syms32, \"r\") failed");
        }
    }
    if (fileType == ElfFileType::ELF64) {
        ehdrFP_ = fopen(ehdr64.c_str(), "rb");
        if (ehdrFP_ == nullptr) {
            HLOGV("fopen(ehdr64, \"r\") failed");
        }
        shdrsFP_ = fopen(shdrs64.c_str(), "rb");
        if (shdrsFP_ == nullptr) {
            HLOGV("fopen(shdrs64, \"r\") failed");
        }
        phdrsFP_ = fopen(phdrs64.c_str(), "rb");
        if (phdrsFP_ == nullptr) {
            HLOGV("fopen(phdrs64, \"r\") failed");
        }
        symTabFP_ = fopen(syms64.c_str(), "rb");
        if (symTabFP_ == nullptr) {
            HLOGV("fopen(syms64, \"r\") failed");
        }
    }
}

ElfFileFromReadelf::~ElfFileFromReadelf()
{
    if (ehdrFP_ != nullptr) {
        fclose(ehdrFP_);
        ehdrFP_ = nullptr;
    }
    if (shdrsFP_ != nullptr) {
        fclose(shdrsFP_);
        shdrsFP_ = nullptr;
    }
    if (phdrsFP_ != nullptr) {
        fclose(phdrsFP_);
        phdrsFP_ = nullptr;
    }
    if (symTabFP_ != nullptr) {
        fclose(symTabFP_);
        symTabFP_ = nullptr;
    }
}

std::unique_ptr<ElfFileFromReadelf> ElfFileFromReadelf::MakeUnique(ElfFileType fileType)
{
    std::unique_ptr<ElfFileFromReadelf> elfFile {new (std::nothrow) ElfFileFromReadelf(fileType)};
    if (elfFile == nullptr) {
        HLOGV("ElfFileFromReadelf(fileType) failed:");
        return nullptr;
    }
    if (!elfFile->Init()) {
        HLOGV("ElfFileFromReadelf::Init() failed");
        return nullptr;
    }
    HLOGD("ElfFileFromReadelf::MakeUnique() done");
    return elfFile;
}

bool ElfFileFromReadelf::Init()
{
    if (!IsOpened()) {
        HLOGV("IsOpened() returns false");
        return false;
    }
    HLOGD("all commands done");
    if (!ParseElfHeader()) {
        HLOGV("ElfFileFromReadelf::ParseElfHeader() failed");
        return false;
    }
    HLOGD("ParseElfHeader() done");
    if (ehdr_->ehdrIdent_[EI_CLASS] == ELFCLASS32) {
        if (!ParsePrgHeaders32()) {
            HLOGV("ElfFileFromReadelf::ParsePrgHeader() failed");
            return false;
        }
        HLOGD("ParsePrgHeaders32() done");
        if (!ParseSecHeaders32()) {
            HLOGV("ElfFileFromReadelf::ParseSecHeader() failed");
            return false;
        }
        HLOGD("ParseSecHeaders32() done");
    } else if (ehdr_->ehdrIdent_[EI_CLASS] == ELFCLASS64) {
        if (!ParsePrgHeaders64()) {
            HLOGV("ElfFileFromReadelf::ParsePrgHeader() failed");
            return false;
        }
        HLOGD("ParsePrgHeaders64() done");
        if (!ParseSecHeaders64()) {
            HLOGV("ElfFileFromReadelf::ParseSecHeader() failed");
            return false;
        }
        HLOGD("ParseSecHeaders64() done");
    } else {
        HLOGV("not an elf file");
        return false;
    }
    if (!ParseSymTable()) {
        HLOGV("ElfFileFromReadelf::ParseSymTable() failed");
        return false;
    }
    HLOGD("ParseSymTable() done");
    HLOGD("ElfFileFromReadelf::Init() done");
    return true;
}

bool ElfFileFromReadelf::IsOpened()
{
    if (ehdrFP_ == nullptr) {
        HLOGV("ehdrFP_ = nullptr");
        return false;
    }
    if (shdrsFP_ == nullptr) {
        HLOGV("shdrsFP_ = nullptr");
        return false;
    }
    if (phdrsFP_ == nullptr) {
        HLOGV("phdrsFP_ = nullptr");
        return false;
    }
    if (symTabFP_ == nullptr) {
        HLOGV("symTabFP_ = nullptr");
        return false;
    }
    return true;
}

bool ElfFileFromReadelf::ParseElfHeader()
{
    ehdr_ = EhdrFromReadelf::MakeUnique(ehdrFP_);
    if (ehdr_ == nullptr) {
        HLOGV("EhdrFromReadelf::MakeUnique(ehdrFP_) failed");
        return false;
    }
    return true;
}

bool ElfFileFromReadelf::ParsePrgHeaders64()
{
    std::string line1 {};
    std::string line2 {};
    while (true) {
        line1 = GetNextPhdrLine();
        line2 = GetNextPhdrLine();
        if (line1 == "" or line2 == "") {
            HLOGV("no more program header lines");
            break;
        }
        auto phdr = PhdrFromReadelf::MakeUnique(line1 + line2);
        if (phdr == nullptr) {
            HLOGV("64 bit PhdrFromReadelf::MakeUnique(line) failed:");
            HLOGV("    line1 = %s", line1.c_str());
            HLOGV("    line2 = %s", line2.c_str());
            return false;
        }
        phdrs_.push_back(std::move(phdr));
    }
    return true;
}

bool ElfFileFromReadelf::ParsePrgHeaders32()
{
    std::string line {};
    while (true) {
        line = GetNextPhdrLine();
        if (line == "") {
            HLOGV("no more program header lines");
            break;
        }
        auto phdr = PhdrFromReadelf::MakeUnique(line);
        if (phdr == nullptr) {
            HLOGV("32 bit PhdrFromReadelf::MakeUnique(line) failed:");
            HLOGV("    line = %s", line.c_str());
            return false;
        }
        phdrs_.push_back(std::move(phdr));
    }
    return true;
}

bool ElfFileFromReadelf::ParseSecHeaders64()
{
    std::string line1 {};
    std::string line2 {};
    while (true) {
        int status {0};
        line1 = GetNextShdrLine();
        line2 = GetNextLine(shdrsFP_, &status);
        if (line1 == "" or line2 == "") {
            HLOGV("no more section header lines");
            break;
        }
        auto shdr = ShdrFromReadelf::MakeUnique(line1 + line2);
        if (shdr == nullptr) {
            HLOGV("ShdrFromReadelf::MakeUnique(line1, line2) returns nullptr:");
            HLOGV("    line1 = %s line2 = %s", line1.c_str(), line2.c_str());
            return false;
        }
        shdrs_.push_back(std::move(shdr));
    }
    return true;
}

bool ElfFileFromReadelf::ParseSecHeaders32()
{
    std::string line {};
    while (true) {
        int status {0};
        line = GetNextShdrLine();
        if (line == "") {
            HLOGV("no more section header lines");
            break;
        }
        auto shdr = ShdrFromReadelf::MakeUnique(line);
        if (shdr == nullptr) {
            HLOGV("ShdrFromReadelf::MakeUnique(line) returns nullptr:");
            HLOGV("    line = %s", line.c_str());
            return false;
        }
        shdrs_.push_back(std::move(shdr));
    }
    return true;
}

bool ElfFileFromReadelf::ParseSymTable()
{
    std::string line {};
    while (true) {
        line = GetNextSymLine();
        if (line == "") {
            HLOGV("no more symbol lines");
            break;
        }
        if (line.find(".dynsym") != std::string::npos) {
            if (!ParseSymsInDynSym()) {
                HLOGV("ParseSymsInDynSym() returns false");
                return false;
            }
        }
        if (!ParseSymsInSymTab()) {
            HLOGV("ParseSymsInSymTab() returns false");
            return false;
        }
    }
    HLOGD("ElfFileFromReadelf::ParseSymTable() done");
    return true;
}

bool ElfFileFromReadelf::ParseSymsInDynSym()
{
    std::string line {};
    while (true) {
        line = GetNextSymLine();
        if (line == "") {
            HLOGV("no more symbol lines");
            break;
        }
        if (line.find(".symtab") != std::string::npos) {
            HLOGV("no more dynsym lines");
            break;
        }
        auto dynSym = ElfSymbolFromReadelf::MakeUnique(line);
        if (dynSym == nullptr) {
            HLOGV("ElfSymbolFromReadelf::MakeUnique(line) failed:");
            HLOGV("    line = %s", line.c_str());
            return false;
        }
        if (dynSym->num_ != 0) {
            dynSyms_.push_back(std::move(dynSym));
        }
    }
    return true;
}

bool ElfFileFromReadelf::ParseSymsInSymTab()
{
    std::string line {};
    while (true) {
        line = GetNextSymLine();
        if (line == "") {
            HLOGV("no more symtab lines");
            break;
        }
        auto sym = ElfSymbolFromReadelf::MakeUnique(line);
        if (sym == nullptr) {
            HLOGV("ElfSymbolFromReadelf::MakeUnique(line) failed:");
            HLOGV("    line = %s", line.c_str());
            return false;
        }
        if (sym->num_ != 0) {
            syms_.push_back(std::move(sym));
        }
    }
    return true;
}

const std::string ElfFileFromReadelf::GetNextPhdrLine()
{
    const std::string effectFlag {"0x00"};
    std::string line {};
    int status {0};
    while (true) {
        line = GetNextLine(phdrsFP_, &status);
        if (status == -1) {
            HLOGV("GetNextLine(phdrsFP_, &status) error:");
            line = "";
            break;
        }
        if (line.find(effectFlag) != std::string::npos) {
            HLOGV("effective program header line: %s", line.c_str());
            break;
        }
    }
    return line;
}

const std::string ElfFileFromReadelf::GetNextShdrLine()
{
    const std::string effectFlag {"]"};
    std::string line {};
    int status {0};
    while (true) {
        line = GetNextLine(shdrsFP_, &status);
        if (status == -1) {
            HLOGV("GetNextLine(phdrsFP_, &status) error:");
            line = "";
            break;
        }
        auto pos = line.find(effectFlag);
        if ((pos != std::string::npos) and isdigit(line.at(pos - 1))) {
            HLOGV("effective section header line: %s", line.c_str());
            break;
        }
    }
    return line;
}

const std::string ElfFileFromReadelf::GetNextSymLine()
{
    const std::string effectFlag {":"};
    std::string line {};
    int status {0};
    while (true) {
        line = GetNextLine(symTabFP_, &status);
        if (status == -1) {
            HLOGV("GetNextLine(phdrsFP_, &status) error:");
            line = "";
            break;
        }
        if (line.find(".dynsym") != std::string::npos) {
            break;
        }
        if (line.find(".symtab") != std::string::npos) {
            break;
        }
        auto pos = line.find(effectFlag);
        if ((pos != std::string::npos) and isdigit(line.at(pos - 1))) {
            HLOGV("effective symbol line: %s", line.c_str());
            break;
        }
    }
    return line;
}

std::unique_ptr<ElfSymbolFromReadelf> ElfSymbolFromReadelf::MakeUnique(const std::string &line)
{
    std::unique_ptr<ElfSymbolFromReadelf> elfSym {new (std::nothrow) ElfSymbolFromReadelf()};
    if (elfSym == nullptr) {
        HLOGV("ElfSymbolFromReadelf() failed");
        return nullptr;
    }
    if (!elfSym->Init(line)) {
        HLOGV("ElfSymbolFromReadelf::Init(line) failed:");
        HLOGV("    line = %s", line.c_str());
        return nullptr;
    }
    HLOGD("ElfSymbolFromReadelf::MakeUnique() done");
    return elfSym;
}

bool ElfSymbolFromReadelf::Init(const std::string &line)
{
    auto num = GetNum(line);
    if (num == -1) {
        HLOGV("ElfSymbolFromReadelf::GetNum(line) failed:");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    num_ = static_cast<uint32_t>(num);
    auto value = GetValue(line);
    if (value == -1) {
        HLOGV("ElfSymbolFromReadelf::GetValue(line) failed");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    value_ = static_cast<uint64_t>(value);
    auto size = GetSize(line);
    if (size == -1) {
        HLOGV("ElfSymbolFromReadelf::GetSize(line) failed");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    size_ = static_cast<uint64_t>(size);
    name_ = GetName(line);
    return true;
}

int64_t ElfSymbolFromReadelf::GetNum(const std::string &line)
{
    int64_t res {-1};
    auto strVec = StringSplit(line, " ");
    constexpr int numIndex {0};
    if (strVec.size() <= numIndex) {
        return res;
    }
    std::string numStr = strVec[numIndex];
    numStr = numStr.substr(0, numStr.size() - 1);
    if (IsDigits(numStr)) {
        res = std::stoll(numStr);
    }
    return res;
}

int64_t ElfSymbolFromReadelf::GetValue(const std::string &line)
{
    int64_t res {-1};
    auto strVec = StringSplit(line, " ");
    constexpr int valIndex {1};
    if (strVec.size() <= valIndex) {
        return res;
    }
    std::string valStr = strVec[valIndex];
    if (IsHexDigits(valStr)) {
        constexpr int base {16};
        res = std::stoll(valStr, nullptr, base);
    }
    return res;
}

int64_t ElfSymbolFromReadelf::GetSize(const std::string &line)
{
    int64_t res {-1};
    auto strVec = StringSplit(line, " ");
    constexpr int sizeIndex {2};
    if (strVec.size() <= sizeIndex) {
        return res;
    }
    std::string sizeStr = strVec[sizeIndex];
    if (IsDigits(sizeStr)) {
        res = std::stoll(sizeStr);
    }
    return res;
}

const std::string ElfSymbolFromReadelf::GetName(const std::string &line)
{
    std::string res {};
    auto strVec = StringSplit(line, " ");
    constexpr int nameIndex {7};
    if (strVec.size() > nameIndex) {
        res = strVec.back();
    }
    return res;
}

std::unique_ptr<ShdrFromReadelf> ShdrFromReadelf::MakeUnique(const std::string &line)
{
    std::unique_ptr<ShdrFromReadelf> shdr {new (std::nothrow) ShdrFromReadelf()};
    if (shdr == nullptr) {
        HLOGV("ShdrFromReadelf() failed");
        return nullptr;
    }
    if (!shdr->Init(line)) {
        HLOGV("ShdrFromReadelf::Init(line) failed:");
        HLOGV("    line = %s", line.c_str());
        return nullptr;
    }
    HLOGD("ShdrFromReadelf::MakeUnique() done");
    return shdr;
}

bool ShdrFromReadelf::Init(const std::string &line)
{
    auto secIndex = GetSecIndex(line);
    if (secIndex == -1) {
        HLOGV("ShdrFromReadelf::GetSecIndex(line) failed");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    secIndex_ = static_cast<uint32_t>(secIndex);
    secName_ = GetName(line);
    auto secVaddr = GetAddress(line);
    if (secVaddr == -1) {
        HLOGV("ShdrFromReadelf::GetAddress(line) failed");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    secVaddr_ = static_cast<uint32_t>(secVaddr);
    auto fileOffset = GetFileOffset(line);
    if (fileOffset == -1) {
        HLOGV("ShdrFromReadelf::GetFileOffset(line) failed");
        HLOGV("   line = %s", line.c_str());
        return false;
    }
    fileOffset_ = static_cast<uint64_t>(fileOffset);
    auto secSize = GetSecSize(line);
    if (secSize == -1) {
        HLOGV("ShdrFromReadelf::GetSecSize(line) failed");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    secSize_ = static_cast<uint64_t>(secSize);
    auto secEntrySize = GetEntrySize(line);
    if (secEntrySize == -1) {
        HLOGV("ShdrFromReadelf::GetEntrySize(line) failed");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    secEntrySize_ = static_cast<uint64_t>(secEntrySize);
    auto link = GetLink(line);
    if (link == -1) {
        HLOGV("ShdrFromReadelf::GetLink(line) failed");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    link_ = static_cast<uint32_t>(link);
    auto info = GetInfo(line);
    if (info == -1) {
        HLOGV("ShdrFromReadelf::GetLink(line) failed");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    info_ = static_cast<uint32_t>(info);
    auto secAddrAlign = GetAlign(line);
    if (secAddrAlign == -1) {
        HLOGV("ShdrFromReadelf::GetAlign(line) failed");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    secAddrAlign_ = static_cast<uint64_t>(secAddrAlign);
    return true;
}

int64_t ShdrFromReadelf::GetSecIndex(const std::string &line)
{
    int64_t res {-1};
    auto pos = line.find("[");
    if (pos == std::string::npos) {
        HLOGV("no section index found: %s", line.c_str());
        return res;
    }
    constexpr int len {4};
    std::string str = line.substr(pos, len);
    if (str.length() != len) {
        HLOGV("section index form incorrect: %s", str.c_str());
        return res;
    }
    // section index is of the form "[xx]"
    constexpr int firstDigit {1};
    constexpr int numDigits {2};
    str = str.substr(firstDigit, numDigits);
    if (str[0] == ' ') {
        // str = [ x], transform it to [xx]
        str[0] = '0';
    }
    if (IsDigits(str)) {
        res = std::stoll(str);
    } else {
        HLOGV("not digits: %s", str.c_str());
    }
    return res;
}

const std::string ShdrFromReadelf::GetName(const std::string &line)
{
    auto pos = line.find("]");
    if (pos == std::string::npos) {
        HLOGV("incorrect section line: %s", line.c_str());
        return "";
    }
    ++pos;
    std::string tmpLine = line.substr(pos, line.length() - pos);
    auto strVec = StringSplit(tmpLine, " ");
    std::string res {};
    constexpr int index {1};
    if (strVec.size() <= index) {
        return res;
    }
    std::string str = strVec[index];
    if (str[0] == '.') {
        res = str;
    }
    return res;
}

int64_t ShdrFromReadelf::GetAddress(const std::string &line)
{
    int64_t res {-1};
    auto pos = line.find("]");
    if (pos == std::string::npos) {
        HLOGV("incorrect section line: %s", line.c_str());
        return res;
    }
    ++pos;
    std::string tmpLine = line.substr(pos, line.length() - pos);
    auto strVec = StringSplit(tmpLine, " ");
    std::size_t index {3};
    if (secName_ == "") {
        --index;
    }
    if (strVec.size() <= index) {
        return res;
    }
    std::string str = strVec[index];
    if (IsHexDigits(str)) {
        constexpr int base {16};
        res = std::stoll(str, nullptr, base);
    }
    return res;
}

int64_t ShdrFromReadelf::GetFileOffset(const std::string &line)
{
    int64_t res {-1};
    auto pos = line.find("]");
    if (pos == std::string::npos) {
        HLOGV("incorrect section line: %s", line.c_str());
        return res;
    }
    ++pos;
    std::string tmpLine = line.substr(pos, line.length() - pos);
    auto strVec = StringSplit(tmpLine, " ");
    std::size_t index {4};
    if (secName_ == "") {
        --index;
    }
    if (strVec.size() <= index) {
        return res;
    }
    std::string str = strVec[index];
    if (IsHexDigits(str)) {
        constexpr int base {16};
        res = std::stoll(str, nullptr, base);
    }
    return res;
}

int64_t ShdrFromReadelf::GetSecSize(const std::string &line)
{
    int64_t res {-1};
    auto pos = line.find("]");
    if (pos == std::string::npos) {
        HLOGV("incorrect section line: %s", line.c_str());
        return res;
    }
    ++pos;
    std::string tmpLine = line.substr(pos, line.length() - pos);
    auto strVec = StringSplit(tmpLine, " ");
    std::size_t index {5};
    if (secName_ == "") {
        --index;
    }
    if (strVec.size() <= index) {
        return res;
    }
    std::string str = strVec[index];
    if (IsHexDigits(str)) {
        constexpr int base {16};
        res = std::stoll(str, nullptr, base);
    }
    return res;
}

int64_t ShdrFromReadelf::GetEntrySize(const std::string &line)
{
    int64_t res {-1};
    auto pos = line.find("]");
    if (pos == std::string::npos) {
        HLOGV("incorrect section line: %s", line.c_str());
        return res;
    }
    ++pos;
    std::string tmpLine = line.substr(pos, line.length() - pos);
    auto strVec = StringSplit(tmpLine, " ");
    std::size_t index {6};
    if (secName_ == "") {
        --index;
    }
    if (strVec.size() <= index) {
        return res;
    }
    std::string str = strVec[index];
    if (IsHexDigits(str)) {
        constexpr int base {16};
        res = std::stoll(str, nullptr, base);
    }
    return res;
}

int64_t ShdrFromReadelf::GetLink(const std::string &line)
{
    int64_t res {-1};
    auto pos = line.find("]");
    if (pos == std::string::npos) {
        HLOGV("incorrect section line: %s", line.c_str());
        return res;
    }
    ++pos;
    std::string tmpLine = line.substr(pos, line.length() - pos);
    auto strVec = StringSplit(tmpLine, " ");
    int index {-3};
    if (strVec.size() + index < 0) {
        return res;
    }
    std::string str = strVec[strVec.size() + index];
    if (IsDigits(str)) {
        res = std::stoll(str);
    }
    return res;
}

int64_t ShdrFromReadelf::GetInfo(const std::string &line)
{
    int64_t res {-1};
    auto pos = line.find("]");
    if (pos == std::string::npos) {
        HLOGV("incorrect section line: %s", line.c_str());
        return res;
    }
    ++pos;
    std::string tmpLine = line.substr(pos, line.length() - pos);
    auto strVec = StringSplit(tmpLine, " ");
    int index {-2};
    if (strVec.size() + index < 0) {
        return res;
    }
    std::string str = strVec[strVec.size() + index];
    if (IsDigits(str)) {
        res = std::stoll(str);
    }
    return res;
}

int64_t ShdrFromReadelf::GetAlign(const std::string &line)
{
    int64_t res {-1};
    auto pos = line.find("]");
    if (pos == std::string::npos) {
        HLOGV("incorrect section line: %s", line.c_str());
        return res;
    }
    ++pos;
    std::string tmpLine = line.substr(pos, line.length() - pos);
    auto strVec = StringSplit(tmpLine, " ");
    int index {-1};
    if (strVec.size() + index < 0) {
        return res;
    }
    std::string str = strVec[strVec.size() + index];
    if (IsDigits(str)) {
        res = std::stoll(str);
    }
    return res;
}

std::unique_ptr<PhdrFromReadelf> PhdrFromReadelf::MakeUnique(const std::string &line)
{
    std::unique_ptr<PhdrFromReadelf> phdr {new (std::nothrow) PhdrFromReadelf()};
    if (phdr == nullptr) {
        HLOGV("PhdrFromReadelf() failed");
        return nullptr;
    }
    if (!phdr->Init(line)) {
        HLOGV("PhdrFromReadelf::Init(line) failed");
        HLOGV("    line = %s", line.c_str());
        return nullptr;
    }
    HLOGD("PhdrFromReadelf::MakeUnique() done");
    return phdr;
}

bool PhdrFromReadelf::Init(const std::string &line)
{
    auto offset = GetOffset(line);
    if (offset == -1) {
        HLOGV("PhdrFromReadelf::GetOffset(line) failed");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    offset_ = static_cast<uint64_t>(offset);
    auto vaddr = GetVaddr(line);
    if (vaddr == -1) {
        HLOGV("PhdrFromReadelf::GetVaddr(line) failed");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    vaddr_ = static_cast<uint64_t>(vaddr);
    auto paddr = GetPaddr(line);
    if (paddr == -1) {
        HLOGV("PhdrFromReadelf::GetPaddr(line) failed");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    paddr_ = static_cast<uint64_t>(paddr);
    auto fileSize = GetFileSize(line);
    if (fileSize == -1) {
        HLOGV("PhdrFromReadelf::GetFileSize(line) failed");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    fileSize_ = static_cast<uint64_t>(fileSize);
    auto align = GetAlign(line);
    if (align == -1) {
        HLOGV("PhdrFromReadelf::GetAlign(line) failed");
        HLOGV("   line = %s", line.c_str());
    }
    secAlign_ = static_cast<uint64_t>(align);
    return true;
}

int64_t PhdrFromReadelf::GetOffset(const std::string &line)
{
    int64_t res {-1};
    auto strVec = StringSplit(line, " ");
    constexpr int index {1};
    if (strVec.size() <= index) {
        HLOGV("short line: %s", line.c_str());
        return res;
    }
    std::string str = strVec[index];
    if (IsHexDigits(str)) {
        constexpr int base {16};
        res = std::stoll(str, nullptr, base);
    } else {
        HLOGV("not hex number: %s", str.c_str());
    }
    return res;
}

int64_t PhdrFromReadelf::GetVaddr(const std::string &line)
{
    int64_t res {-1};
    auto strVec = StringSplit(line, " ");
    constexpr int index {2};
    if (strVec.size() <= index) {
        return res;
    }
    std::string str = strVec[index];
    if (IsHexDigits(str)) {
        constexpr int base {16};
        res = std::stoll(str, nullptr, base);
    }
    return res;
}

int64_t PhdrFromReadelf::GetPaddr(const std::string &line)
{
    int64_t res {-1};
    auto strVec = StringSplit(line, " ");
    constexpr int index {3};
    if (strVec.size() <= index) {
        return res;
    }
    std::string str = strVec[index];
    if (IsHexDigits(str)) {
        constexpr int base {16};
        res = std::stoll(str, nullptr, base);
    }
    return res;
}

int64_t PhdrFromReadelf::GetFileSize(const std::string &line)
{
    int64_t res {-1};
    auto strVec = StringSplit(line, " ");
    constexpr int index {4};
    if (strVec.size() <= index) {
        return res;
    }
    std::string str = strVec[index];
    if (IsHexDigits(str)) {
        HLOGD("program header file size: %s", str.c_str());
        constexpr int base {16};
        res = std::stoll(str, nullptr, base);
    }
    return res;
}

int64_t PhdrFromReadelf::GetMemSize(const std::string &line)
{
    int64_t res {-1};
    auto strVec = StringSplit(line, " ");
    constexpr int index {5};
    if (strVec.size() <= index) {
        return res;
    }
    std::string str = strVec[index];
    if (IsHexDigits(str)) {
        constexpr int base {16};
        res = std::stoll(str, nullptr, base);
    }
    return res;
}

int64_t PhdrFromReadelf::GetAlign(const std::string &line)
{
    int64_t res {-1};
    auto strVec = StringSplit(line, " ");
    constexpr int index {-1};
    if (strVec.size() + index < 0) {
        return res;
    }
    std::string str = strVec[strVec.size() + index];
    if (IsHexDigits(str)) {
        constexpr int base {16};
        res = std::stoll(str, nullptr, base);
    }
    return res;
}

std::unique_ptr<EhdrFromReadelf> EhdrFromReadelf::MakeUnique(FILE *fp)
{
    if (fp == nullptr) {
        HLOGE("param is null");
        return nullptr;
    }
    std::unique_ptr<EhdrFromReadelf> ehdr {new (std::nothrow) EhdrFromReadelf()};
    if (ehdr == nullptr) {
        HLOGV("EhdrFromReadelf() failed");
        return nullptr;
    }
    if (!ehdr->Init(fp)) {
        HLOGV("EhdrFromReadelf::Init(fp) failed:");
        return nullptr;
    }
    HLOGD("EhdrFromReadelf::MakeUnique() done");
    return ehdr;
}

bool EhdrFromReadelf::Init(FILE *fp)
{
    if (fp == nullptr) {
        HLOGE("param is null");
        return false;
    }
    int status {0};
    // drop header line
    GetNextLine(fp, &status);
    if (!GetMagic(fp)) {
        HLOGV("EhdrFromReadelf::InitMagic(fp) failed:");
        return false;
    }
    constexpr int numSkip {8};
    // drop unused 8 lines
    for (int count = 0; count < numSkip; ++count) {
        GetNextLine(fp, &status);
    }
    if (!GetEntryAddr(fp)) {
        HLOGV("EhdrFromReadelf::InitEntryAddr(fp) failed:");
        return false;
    }
    if (!GetPrgOffset(fp)) {
        HLOGV("EhdrFromReadelf::InitPrgOffset(fp) failed:");
        return false;
    }
    if (!GetSecOffset(fp)) {
        HLOGV("EhdrFromReadelf::InitSecOffset(fp) failed:");
        return false;
    }
    if (!GetFlag(fp)) {
        HLOGV("EhdrFromReadelf::InitFlag(fp) failed:");
        return false;
    }
    if (!GetEhdrSize(fp)) {
        HLOGV("EhdrFromReadelf::InitEhdrSize(fp) failed:");
        return false;
    }
    if (!GetPhdrSize(fp)) {
        HLOGV("EhdrFromReadelf::InitPhdrSize(fp) failed:");
        return false;
    }
    if (!GetNumPhdrs(fp)) {
        HLOGV("EhdrFromReadelf::InitNumPhdrs(fp) failed:");
        return false;
    }
    if (!GetShdrSize(fp)) {
        HLOGV("EhdrFromReadelf::InitShdrSize(fp) failed:");
        return false;
    }
    if (!GetNumShdrs(fp)) {
        HLOGV("EhdrFromReadelf::InitNumShdrs(fp) failed:");
        return false;
    }
    if (!GetShdrStrTabIdx(fp)) {
        HLOGV("EhdrFromReadelf::InitShdrStrTabIdx(fp) failed:");
        return false;
    }
    return true;
}

bool EhdrFromReadelf::GetMagic(FILE * const fp)
{
    if (fp == nullptr) {
        HLOGE("param is null");
        return false;
    }
    int status {0};
    std::string magicLine = GetNextLine(fp, &status);
    if (status == -1) {
        HLOGV("early end");
        return false;
    }
    auto tmp = StringSplit(magicLine, " ");
    std::vector<std::string> strVec {tmp.begin() + 1, tmp.end()};
    if (strVec.size() != EI_NIDENT) {
        HLOGV("line format incorrect:");
        HLOGV("    line = %s", magicLine.c_str());
        return false;
    }
    for (std::size_t count = 0; count < strVec.size(); ++count) {
        std::string valStr = strVec[count];
        constexpr int base {16};
        ehdrIdent_[count] = static_cast<unsigned char>(std::stoul(valStr, nullptr, base));
    }
    return true;
}

bool EhdrFromReadelf::GetEntryAddr(FILE * const fp)
{
    int status {0};
    std::string entryLine = GetNextLine(fp, &status);
    if (status == -1) {
        HLOGV("early end");
        return false;
    }
    auto strVec = StringSplit(entryLine, " ");
    constexpr int len {2};
    if (strVec.size() != len) {
        HLOGV("line format incorrect:");
        HLOGV("    line = %s", entryLine.c_str());
        return false;
    }
    std::string entryStr = strVec.back();
    constexpr int base {16};
    prgEntryVaddr_ = static_cast<uint64_t>(std::stoull(entryStr, nullptr, base));
    return true;
}

bool EhdrFromReadelf::GetPrgOffset(FILE * const fp)
{
    int status {0};
    std::string line = GetNextLine(fp, &status);
    if (status == -1) {
        HLOGV("early end");
        return false;
    }
    auto strVec = StringSplit(line, " ");
    constexpr int len {5};
    if (strVec.size() != len) {
        HLOGV("line format incorrect:");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    constexpr int valIndex {1};
    std::string valStr = strVec[valIndex];
    phdrOffset_ = static_cast<uint64_t>(std::stoull(valStr));
    return true;
}

bool EhdrFromReadelf::GetSecOffset(FILE * const fp)
{
    int status {0};
    std::string line = GetNextLine(fp, &status);
    if (status == -1) {
        HLOGV("early end");
        return false;
    }
    auto strVec = StringSplit(line, " ");
    constexpr int len {8};
    if (strVec.size() != len) {
        HLOGV("line format incorrect:");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    constexpr int valIndex {4};
    std::string valStr = strVec[valIndex];
    shdrOffset_ = static_cast<uint64_t>(std::stoull(valStr));
    return true;
}

bool EhdrFromReadelf::GetFlag(FILE * const fp)
{
    int status {0};
    std::string line = GetNextLine(fp, &status);
    if (status == -1) {
        HLOGV("early end");
        return false;
    }
    auto strVec = StringSplit(line, " ");
    constexpr int len {2};
    if (strVec.size() != len) {
        HLOGV("line format incorrect:");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    constexpr int valIndex {1};
    std::string valStr = strVec[valIndex];
    ehdrFlags_ = static_cast<uint32_t>(std::stoul(valStr));
    return true;
}

bool EhdrFromReadelf::GetEhdrSize(FILE * const fp)
{
    int status {0};
    std::string line = GetNextLine(fp, &status);
    if (status == -1) {
        HLOGV("early end");
        return false;
    }
    auto strVec = StringSplit(line, " ");
    constexpr int len {6};
    if (strVec.size() != len) {
        HLOGV("line format incorrect:");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    constexpr int valIndex {4};
    std::string valStr = strVec[valIndex];
    ehdrSize_ = static_cast<uint16_t>(std::stoull(valStr));
    return true;
}

bool EhdrFromReadelf::GetPhdrSize(FILE * const fp)
{
    int status {0};
    std::string line = GetNextLine(fp, &status);
    if (status == -1) {
        HLOGV("early end");
        return false;
    }
    auto strVec = StringSplit(line, " ");
    constexpr int len {6};
    if (strVec.size() != len) {
        HLOGV("line format incorrect:");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    constexpr int valIndex {4};
    std::string valStr = strVec[valIndex];
    phdrEntSize_ = static_cast<uint16_t>(std::stoull(valStr));
    return true;
}

bool EhdrFromReadelf::GetNumPhdrs(FILE * const fp)
{
    int status {0};
    std::string line = GetNextLine(fp, &status);
    if (status == -1) {
        HLOGV("early end");
        return false;
    }
    auto strVec = StringSplit(line, " ");
    constexpr int len {5};
    if (strVec.size() != len) {
        HLOGV("line format incorrect:");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    constexpr int valIndex {4};
    std::string valStr = strVec[valIndex];
    phdrNumEnts_ = static_cast<uint16_t>(std::stoull(valStr));
    return true;
}

bool EhdrFromReadelf::GetShdrSize(FILE * const fp)
{
    int status {0};
    std::string line = GetNextLine(fp, &status);
    if (status == -1) {
        HLOGV("early end");
        return false;
    }
    auto strVec = StringSplit(line, " ");
    constexpr int len {6};
    if (strVec.size() != len) {
        HLOGV("line format incorrect:");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    constexpr int valIndex {4};
    std::string valStr = strVec[valIndex];
    shdrEntSize_ = static_cast<uint16_t>(std::stoull(valStr));
    return true;
}

bool EhdrFromReadelf::GetNumShdrs(FILE * const fp)
{
    int status {0};
    std::string line = GetNextLine(fp, &status);
    if (status == -1) {
        HLOGV("early end");
        return false;
    }
    auto strVec = StringSplit(line, " ");
    constexpr int len {5};
    if (strVec.size() != len) {
        HLOGV("line format incorrect:");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    constexpr int valIndex {4};
    std::string valStr = strVec[valIndex];
    shdrNumEnts_ = static_cast<uint16_t>(std::stoull(valStr));
    return true;
}

bool EhdrFromReadelf::GetShdrStrTabIdx(FILE * const fp)
{
    int status {0};
    std::string line = GetNextLine(fp, &status);
    if (status == -1) {
        HLOGV("early end");
        return false;
    }
    auto strVec = StringSplit(line, " ");
    constexpr int len {6};
    if (strVec.size() != len) {
        HLOGV("line format incorrect:");
        HLOGV("    line = %s", line.c_str());
        return false;
    }
    constexpr int valIndex {5};
    std::string valStr = strVec[valIndex];
    shdrStrTabIdx_ = static_cast<uint16_t>(std::stoull(valStr));
    return true;
}

static bool CompareElfHeader(const std::unique_ptr<ElfFileFromReadelf> &elfFileFromReadelf,
                             const std::unique_ptr<ElfFile> &elfFile)
{
    const auto &ehdr1 = elfFile->ehdr_;
    const auto &ehdr2 = elfFileFromReadelf->ehdr_;
    if (MemCmp(ehdr1->ehdrIdent_, ehdr2->ehdrIdent_, EI_NIDENT) != EI_NIDENT) {
        return false;
    }
    if (ehdr1->ehdrSize_ != ehdr2->ehdrSize_) {
        return false;
    }
    if (ehdr1->phdrEntSize_ != ehdr2->phdrEntSize_) {
        return false;
    }
    if (ehdr1->phdrNumEnts_ != ehdr2->phdrNumEnts_) {
        return false;
    }
    if (ehdr1->shdrEntSize_ != ehdr2->shdrEntSize_) {
        return false;
    }
    if (ehdr1->shdrNumEnts_ != ehdr2->shdrNumEnts_) {
        return false;
    }
    if (ehdr1->shdrStrTabIdx_ != ehdr2->shdrStrTabIdx_) {
        return false;
    }
    if (ehdr1->ehdrFlags_ != ehdr2->ehdrFlags_) {
        return false;
    }
    if (ehdr1->prgEntryVaddr_ != ehdr2->prgEntryVaddr_) {
        return false;
    }
    if (ehdr1->phdrOffset_ != ehdr2->phdrOffset_) {
        return false;
    }
    if (ehdr1->shdrOffset_ != ehdr2->shdrOffset_) {
        return false;
    }
    return true;
}

static bool CompareSecHeaders(const std::unique_ptr<ElfFileFromReadelf> &elfFileFromReadelf,
                              const std::unique_ptr<ElfFile> &elfFile)
{
    const auto &shdrs1 = elfFile->shdrs_;
    const auto &shdrs2 = elfFileFromReadelf->shdrs_;
    std::size_t totalShdrs1 = shdrs1.size();
    std::size_t totalShdrs2 = shdrs2.size();
    HLOGV("number of section headers from elf_parser: %zu", totalShdrs1);
    HLOGV("number of section headers from readelf: %zu", totalShdrs2);
    if (totalShdrs1 != totalShdrs2) {
        return false;
    }
    return true;
}

static bool ComparePrgHeaders(const std::unique_ptr<ElfFileFromReadelf> &elfFileFromReadelf,
                              const std::unique_ptr<ElfFile> &elfFile)
{
    const auto &phdrs1 = elfFile->phdrs_;
    const auto &phdrs2 = elfFileFromReadelf->phdrs_;
    std::size_t totalPhdrs1 = phdrs1.size();
    std::size_t totalPhdrs2 = phdrs2.size();
    HLOGV("number of program headers from elf_parser: %zu", totalPhdrs1);
    HLOGV("number of program headers from readelf: %zu", totalPhdrs2);
    if (totalPhdrs1 != totalPhdrs2) {
        return false;
    }
    return true;
}

class ElfParserTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void PrintElfHeader(const std::unique_ptr<ElfHeader> &ehdr) const;
    void PrintSecHeader(const std::unique_ptr<SectionHeader> &shdr) const;
    void PrintSecHeaders(const ElfFile::SecHeaderTableType &shdrs) const;
    std::unique_ptr<ElfFile> elfFile64_ {nullptr};
    std::unique_ptr<ElfFile> elfFile32_ {nullptr};
    std::unique_ptr<ElfFileFromReadelf> elfFile64FromReadelf_ {nullptr};
    std::unique_ptr<ElfFileFromReadelf> elfFile32FromReadelf_ {nullptr};
};

void ElfParserTest::SetUpTestCase() {}

void ElfParserTest::TearDownTestCase() {}

void ElfParserTest::SetUp()
{
    elfFile64_ = ElfFile::MakeUnique(file64);
    ASSERT_FALSE(elfFile64_ == nullptr);
    HLOGD("elfFile64_ setup");
    elfFile32_ = ElfFile::MakeUnique(file32);
    ASSERT_FALSE(elfFile32_ == nullptr);
    HLOGD("elfFile32_ setup");
    elfFile64FromReadelf_ = ElfFileFromReadelf::MakeUnique(ElfFileFromReadelf::ElfFileType::ELF64);
    ASSERT_FALSE(elfFile64FromReadelf_ == nullptr);
    HLOGD("elfFile64FromReadelf_ setup");
    elfFile32FromReadelf_ = ElfFileFromReadelf::MakeUnique(ElfFileFromReadelf::ElfFileType::ELF32);
    ASSERT_FALSE(elfFile32FromReadelf_ == nullptr);
    HLOGD("elfFile32FromReadelf_ setup");
}

void ElfParserTest::TearDown() {}

HWTEST_F(ElfParserTest, ParseElfHeader, TestSize.Level1)
{
    EXPECT_TRUE(CompareElfHeader(elfFile64FromReadelf_, elfFile64_));
    EXPECT_TRUE(CompareElfHeader(elfFile32FromReadelf_, elfFile32_));
}

HWTEST_F(ElfParserTest, ParseSecHeaders, TestSize.Level1)
{
    EXPECT_TRUE(CompareSecHeaders(elfFile64FromReadelf_, elfFile64_));
    EXPECT_TRUE(CompareSecHeaders(elfFile32FromReadelf_, elfFile32_));
}

HWTEST_F(ElfParserTest, ParsePrgHeaders, TestSize.Level1)
{
    EXPECT_TRUE(ComparePrgHeaders(elfFile64FromReadelf_, elfFile64_));
    EXPECT_TRUE(ComparePrgHeaders(elfFile32FromReadelf_, elfFile32_));
}
// This is not code HWTEST_F(ElfParserTest, ParseSymTable, TestSize.Level1)
// This is not code {
// This is not code     EXPECT_TRUE(CompareSymTable(elfFile64FromReadelf_, elfFile64_));
// This is not code     EXPECT_TRUE(CompareSymTable(elfFile32FromReadelf_, elfFile32_));
// This is not code }
// This is not code
// This is not code HWTEST_F(ElfParserTest, ParseDynSymTable, TestSize.Level1)
// This is not code {
// This is not code     EXPECT_TRUE(CompareDynSymTable(elfFile64FromReadelf_, elfFile64_));
// This is not code     EXPECT_TRUE(CompareDynSymTable(elfFile32FromReadelf_, elfFile32_));
// This is not code }
} // namespace UnitTest
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
