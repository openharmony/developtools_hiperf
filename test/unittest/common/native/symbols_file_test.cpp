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

#include "symbols_file_test.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <hilog/log.h>
#include <random>
#include <unistd.h>

using namespace testing::ext;

namespace OHOS {
namespace Developtools {
namespace HiPerf {
class SymbolsFileTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void CheckSymbols(const std::unique_ptr<SymbolsFile> &symbolsFile) const;
    void PrintSymbols(const std::vector<DfxSymbol> &symbol) const;
    bool KptrRestrict() const;

    std::unique_ptr<SymbolsFile> LoadSymbols(SymbolsFileType symbolsFileType)
    {
        std::unique_ptr<SymbolsFile> symbolsFile = SymbolsFile::CreateSymbolsFile(symbolsFileType);
        EXPECT_EQ(symbolsFile->setSymbolsFilePath(PATH_RESOURCE_TEST_DATA), true);
        return symbolsFile;
    }

    bool TestLoadSymbols(SymbolsFileType symbolsFileType, const std::string &path)
    {
        std::unique_ptr<SymbolsFile> symbolsFile = SymbolsFile::CreateSymbolsFile(symbolsFileType);
        EXPECT_EQ(symbolsFile->setSymbolsFilePath(PATH_RESOURCE_TEST_DATA), true);
        return symbolsFile->LoadSymbols(nullptr, path);
    }
    std::default_random_engine rnd_;
};

void SymbolsFileTest::SetUpTestCase() {}

void SymbolsFileTest::TearDownTestCase() {}

void SymbolsFileTest::SetUp() {}

void SymbolsFileTest::TearDown() {}

bool SymbolsFileTest::KptrRestrict() const
{
    std::ifstream inputString(KPTR_RESTRICT, std::ios::in);
    if (inputString) {
        string kptrRestrict = "1";
        inputString >> kptrRestrict;
        if (kptrRestrict == "0") {
            return false;
        }
    }
    return true;
}

void SymbolsFileTest::CheckSymbols(const std::unique_ptr<SymbolsFile> &symbolsFile) const
{
    auto symbols = symbolsFile->GetSymbols();
    EXPECT_EQ(symbols.empty(), false);
    ASSERT_GE(symbols.size(), 1u);
    PrintSymbols(symbols);

    // first is 0
    EXPECT_EQ(symbolsFile->GetSymbolWithVaddr(0x0).funcVaddr_, 0u);

    // last is IsValid
    EXPECT_EQ(symbolsFile->GetSymbolWithVaddr(std::numeric_limits<uint64_t>::max()).IsValid(),
              true);

    for (uint64_t pos = 0; pos < symbols.size(); ++pos) {
        uint64_t vaddr = symbols[pos].funcVaddr_;
        EXPECT_EQ(symbolsFile->GetSymbolWithVaddr(vaddr).funcVaddr_, vaddr);
    }
    for (auto symbol : symbols) {
        if (symbol.name_.find("_Z") != std::string::npos) {
            EXPECT_NE(symbol.demangle_.find("_Z"), 0u);
        }
    }
}

void SymbolsFileTest::PrintSymbols(const std::vector<DfxSymbol> &symbols) const
{
    size_t printNumber = 15;
    if (printNumber > symbols.size())
        printNumber = symbols.size();

    printf("first %zu:\n", printNumber);
    for (size_t i = 0; i < printNumber; i++) {
        printf("%s\n", symbols[i].ToDebugString().c_str());
    }
    if (printNumber < symbols.size()) {
        printf("last %zu:\n", printNumber);
        for (size_t i = printNumber; i > 0; i--) {
            printf("%s\n", symbols[symbols.size() - i].ToDebugString().c_str());
        }
    }
}

/**
 * @tc.name: setSymbolsFilePath
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, setSymbolsFilePath, TestSize.Level2)
{
    auto symbolsFile = SymbolsFile::CreateSymbolsFile(SYMBOL_UNKNOW_FILE);
    EXPECT_EQ(symbolsFile->setSymbolsFilePath(PATH_DATA_TEMP), true);
    EXPECT_EQ(symbolsFile->setSymbolsFilePath(PATH_NOT_EXISTS), false);
    EXPECT_EQ(symbolsFile->setSymbolsFilePath(PATH_DATA_TEMP_WINDOS), false);
    EXPECT_EQ(symbolsFile->setSymbolsFilePath(PATH_ILLEGAL), false);
    EXPECT_EQ(symbolsFile->setSymbolsFilePath(PATH_RESOURCE_TEST_DATA), true);
    EXPECT_EQ(symbolsFile->setSymbolsFilePath(PATH_RESOURCE_TEST_DATA_NO_ENDPATH), true);
}

/**
 * @tc.name: setSymbolsFilePath
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, setSymbolsFilePathVectorSuccess, TestSize.Level1)
{
    auto symbolsFile = SymbolsFile::CreateSymbolsFile(SYMBOL_UNKNOW_FILE);
    std::vector<std::string> symbolsSearchPaths;

    symbolsSearchPaths.clear();
    symbolsSearchPaths.push_back(PATH_DATA_TEMP);
    EXPECT_EQ(symbolsFile->setSymbolsFilePath(symbolsSearchPaths), true);

    symbolsSearchPaths.clear();
    symbolsSearchPaths.push_back(PATH_DATA_TEMP);
    symbolsSearchPaths.push_back(PATH_DATA_TEMP);
    EXPECT_EQ(symbolsFile->setSymbolsFilePath(symbolsSearchPaths), true);

    symbolsSearchPaths.clear();
    symbolsSearchPaths.push_back(PATH_DATA_TEMP);
    symbolsSearchPaths.push_back(PATH_DATA_TEMP);
    symbolsSearchPaths.push_back(PATH_DATA_TEMP);
    EXPECT_EQ(symbolsFile->setSymbolsFilePath(symbolsSearchPaths), true);
}

/**
 * @tc.name: setSymbolsFilePath
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, setSymbolsFilePathVectorFailed, TestSize.Level3)
{
    auto symbolsFile = SymbolsFile::CreateSymbolsFile(SYMBOL_UNKNOW_FILE);
    std::vector<std::string> symbolsSearchPaths;

    symbolsSearchPaths.clear();
    symbolsSearchPaths.push_back(PATH_NOT_EXISTS);
    EXPECT_EQ(symbolsFile->setSymbolsFilePath(symbolsSearchPaths), false);

    symbolsSearchPaths.clear();
    symbolsSearchPaths.push_back(PATH_NOT_EXISTS);
    symbolsSearchPaths.push_back(PATH_NOT_EXISTS);
    EXPECT_EQ(symbolsFile->setSymbolsFilePath(symbolsSearchPaths), false);

    symbolsSearchPaths.clear();
    symbolsSearchPaths.push_back(PATH_NOT_EXISTS);
    symbolsSearchPaths.push_back(PATH_NOT_EXISTS);
    symbolsSearchPaths.push_back(PATH_NOT_EXISTS);
    EXPECT_EQ(symbolsFile->setSymbolsFilePath(symbolsSearchPaths), false);
}

/**
 * @tc.name: setSymbolsFilePath
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, setSymbolsFilePathVectorMixSucessed, TestSize.Level1)
{
    auto symbolsFile = SymbolsFile::CreateSymbolsFile(SYMBOL_UNKNOW_FILE);
    std::vector<std::string> symbolsSearchPaths;

    symbolsSearchPaths.clear();
    symbolsSearchPaths.push_back(PATH_DATA_TEMP);
    symbolsSearchPaths.push_back(PATH_NOT_EXISTS);
    EXPECT_EQ(symbolsFile->setSymbolsFilePath(symbolsSearchPaths), true);

    symbolsSearchPaths.clear();
    symbolsSearchPaths.push_back(PATH_DATA_TEMP);
    symbolsSearchPaths.push_back(PATH_NOT_EXISTS);
    symbolsSearchPaths.push_back(PATH_DATA_TEMP);
    symbolsSearchPaths.push_back(PATH_NOT_EXISTS);
    EXPECT_EQ(symbolsFile->setSymbolsFilePath(symbolsSearchPaths), true);

    symbolsSearchPaths.clear();
    symbolsSearchPaths.push_back(PATH_DATA_TEMP);
    symbolsSearchPaths.push_back(PATH_NOT_EXISTS);
    symbolsSearchPaths.push_back(PATH_DATA_TEMP);
    symbolsSearchPaths.push_back(PATH_NOT_EXISTS);
    symbolsSearchPaths.push_back(PATH_DATA_TEMP);
    symbolsSearchPaths.push_back(PATH_NOT_EXISTS);
    EXPECT_EQ(symbolsFile->setSymbolsFilePath(symbolsSearchPaths), true);
}

bool TestLoadSymbols(SymbolsFileType symbolsFileType, const std::string &path)
{
    std::unique_ptr<SymbolsFile> symbolsFile = SymbolsFile::CreateSymbolsFile(symbolsFileType);
    EXPECT_EQ(symbolsFile->setSymbolsFilePath(PATH_RESOURCE_TEST_DATA), true);
    return symbolsFile->LoadSymbols(nullptr, path);
}

/**
 * @tc.name: SymbolsFile Default Virtual
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, SymbolsFileDefaultVirtual, TestSize.Level2)
{
    std::unique_ptr<SymbolsFile> symbolsFile = SymbolsFile::CreateSymbolsFile(SYMBOL_UNKNOW_FILE);
    uint64_t value = 0;
    ASSERT_EQ(symbolsFile->LoadDebugInfo(), false);
    EXPECT_EQ(symbolsFile->GetSectionInfo("", value, value, value), false);
#ifndef __arm__
    EXPECT_EQ(symbolsFile->GetHDRSectionInfo(value, value, value), false);
#endif
}

/**
 * @tc.name: LoaderKernelSymbols
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, LoadKernelSymbols, TestSize.Level0)
{
    if (access("/sys/kernel/notes", F_OK) == 0) {
        // read from kernel runtime
        std::unique_ptr<SymbolsFile> symbolsFile = SymbolsFile::CreateSymbolsFile(SYMBOL_KERNEL_FILE);
        ScopeDebugLevel tempLogLevel(LEVEL_VERBOSE);
        ASSERT_EQ(symbolsFile->LoadSymbols(), true);

        const std::vector<DfxSymbol> &symbols = symbolsFile->GetSymbols();
        EXPECT_EQ(symbols.empty(), false);

        std::string modulesMap = ReadFileToString("/proc/modules");
        int lines = std::count(modulesMap.begin(), modulesMap.end(), '\n');
        if (lines >= 0) {
            std::set<std::string> modulesCount;
            for (auto &symbol : symbols) {
                if (symbol.module_.length()) {
                    modulesCount.emplace(symbol.module_);
                }
            }

            // add [kernel.kallsyms]
            if (modulesCount.size() != lines + 1u) {
                printf("warn: modulesCount != lines + 1\n");
            }
            if (HasFailure()) {
                for (auto &module : modulesCount) {
                    printf("%s\n", module.c_str());
                }
            }

            // try vmlinux
            EXPECT_EQ(TestLoadSymbols(SYMBOL_KERNEL_FILE, TEST_FILE_VMLINUX), true);
            EXPECT_EQ(TestLoadSymbols(SYMBOL_KERNEL_FILE, TEST_FILE_VMLINUX_STRIPPED), true);
            EXPECT_EQ(TestLoadSymbols(SYMBOL_KERNEL_FILE, TEST_FILE_VMLINUX_STRIPPED_NOBUILDID), true);
            // will be load from runtime, still return true
            EXPECT_EQ(TestLoadSymbols(SYMBOL_KERNEL_FILE, TEST_FILE_VMLINUX_STRIPPED_BROKEN), true);
        }
    } else {
        printf("cannot access /sys/kernel/notes\n");
    }
}

/**
 * @tc.name: LoaderElfSymbols
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, LoadElfSymbols, TestSize.Level1)
{
    auto symbolsElfLoader = SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE);
    auto symbolsElfStrippedLoader = SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE);
    ScopeDebugLevel tempLogLevel(LEVEL_VERBOSE);

    EXPECT_EQ(symbolsElfLoader->LoadSymbols(), false);

    ASSERT_EQ(symbolsElfLoader->setSymbolsFilePath(PATH_RESOURCE_TEST_DATA), true);
    EXPECT_EQ(symbolsElfLoader->LoadSymbols(nullptr, TEST_FILE_ELF), true);
    if (HasFailure()) {
        PrintSymbols(symbolsElfLoader->GetSymbols());
    }

    ASSERT_EQ(symbolsElfStrippedLoader->setSymbolsFilePath(PATH_RESOURCE_TEST_DATA), true);
    EXPECT_EQ(symbolsElfStrippedLoader->LoadSymbols(nullptr, TEST_FILE_ELF_STRIPPED), true);
    if (HasFailure()) {
        PrintSymbols(symbolsElfStrippedLoader->GetSymbols());
    }
    EXPECT_GT(symbolsElfLoader->GetSymbols().size(), symbolsElfStrippedLoader->GetSymbols().size());

    ASSERT_EQ(symbolsElfStrippedLoader->setSymbolsFilePath(PATH_RESOURCE_TEST_DATA), true);
    EXPECT_EQ(symbolsElfStrippedLoader->LoadSymbols(nullptr, TEST_FILE_ELF), true);
    if (HasFailure()) {
        PrintSymbols(symbolsElfStrippedLoader->GetSymbols());
    }

    // no symbols not means failed.
    EXPECT_EQ(TestLoadSymbols(SYMBOL_ELF_FILE, TEST_FILE_ELF_STRIPPED), true);

    // no build id not means failed.
    EXPECT_EQ(TestLoadSymbols(SYMBOL_ELF_FILE, TEST_FILE_ELF_STRIPPED_NOBUILDID), true);

    EXPECT_EQ(TestLoadSymbols(SYMBOL_ELF_FILE, TEST_FILE_ELF_STRIPPED_BROKEN), false);
}

/**
 * @tc.name: GetSymbolWithVaddr
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, GetSymbolWithVaddr, TestSize.Level0)
{
    if (access("/sys/kernel/notes", F_OK) == 0) {
        auto symbols = SymbolsFile::CreateSymbolsFile(SYMBOL_KERNEL_FILE);
        if ((0 == getuid())) {
            HLOGD("in root mode");
            EXPECT_EQ(symbols->LoadSymbols(), true);
            CheckSymbols(symbols);
        } else {
            EXPECT_EQ(symbols->LoadSymbols(), true);
            if (!KptrRestrict()) {
                HLOGD("NOT KptrRestrict");
                if (!symbols->GetSymbols().empty()) {
                    CheckSymbols(symbols);
                } else {
                    printf("we found this issue in linux-5.10\n");
                }
            } else {
                HLOGD("KptrRestrict");
                ASSERT_EQ(symbols->GetSymbols().empty(), true);
            }
        }
    } else {
        printf("cannot access /sys/kernel/notes\n");
    }
}

/**
 * @tc.name: GetSymbolWithVaddr
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, GetSymbolWithVaddr2, TestSize.Level1)
{
    auto elfSymbols = SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE);
    ASSERT_EQ(elfSymbols->setSymbolsFilePath(PATH_RESOURCE_TEST_DATA), true);
    EXPECT_EQ(elfSymbols->LoadSymbols(nullptr, TEST_FILE_ELF), true);
    ASSERT_EQ(elfSymbols->GetSymbols().empty(), false);

    /*
        part of elf32_test's symbols
        vaddr(hex)  size(dec)   name
        00001000    0           _init
        00001030    0
        00001320    58           _start
        00001512    27          main
        0000145d    124         TestGlobalChildFunction
        000014d9    57          TestGlobalParentFunction
        // last one
        00001b38    0           _fini

        part of elf_test's symbols
        vaddr(hex)          size(dec)   name
        0000000000002000    0           _init
        0000000000002020    0
        00000000000022f0    47         _start
        0000000000002478    15          main
        00000000000023d9    110         TestGlobalChildFunction
        0000000000002447    49          TestGlobalParentFunction
        //last one
        0000000000002aa8    0           _fini
    */
#ifdef __arm__
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH, true);
    EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(0x00001320).GetName(), "_start");
    EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(0x00001359).GetName(), "_start");
    EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(0x00001512).GetName(), "main");
    EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(0x0000152c).GetName(), "main");
    EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(0x0000145d).GetName(), "TestGlobalChildFunction");
    EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(0x000014d9).GetName(), "TestGlobalParentFunction");
#else
    EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(0x000022f0).GetName(), "_start");
    EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(0x0000231e).GetName(), "_start");
    EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(0x00002478).GetName(), "main");
    EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(0x00002486).GetName(), "main");
    EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(0x000023d9).GetName(), "TestGlobalChildFunction");
    EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(0x00002447).GetName(), "TestGlobalParentFunction");
#endif
    if (HasFailure()) {
        PrintSymbols(elfSymbols->GetSymbols());
    }
}

/**
 * @tc.name: GetSymbolWithVaddr
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, GetSymbolWithVaddrFullMatch, TestSize.Level2)
{
    auto elfSymbols = SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE);
    ASSERT_EQ(elfSymbols->setSymbolsFilePath(PATH_RESOURCE_TEST_DATA), true);
    if (elfSymbols->LoadSymbols(nullptr, TEST_SYMBOLS_FILE_ELF)) {
        ASSERT_EQ(elfSymbols->GetSymbols().empty(), false);
        /*
            nm -C --defined-only symbols_file_test_elf64
            addr = 1000 mangle name = _init
            addr = 1040 mangle name = _start
            addr = 1070 mangle name = deregister_tm_clones
            addr = 10a0 mangle name = register_tm_clones
            addr = 10e0 mangle name = __do_global_dtors_aux
            addr = 1120 mangle name = frame_dummy
            addr = 1129 mangle name = main
            addr = 1140 mangle name = __libc_csu_init
            addr = 11b0 mangle name = __libc_csu_fini

            //last one
            addr = 11b8 mangle name = _fini

            nm -C --defined-only symbols_file_test_elf32
            00001000 t _init
            00001070 T _start
            000010c0 t deregister_tm_clones
            00001100 t register_tm_clones
            00001150 t __do_global_dtors_aux
            000011a0 t frame_dummy
            000011ad T main
            000011d0 T __libc_csu_init
            00001240 T __libc_csu_fini

            // last one
            0000124c T _fini
        */
#ifdef __arm__
        enum SymbolAddr : uint64_t {
            PLT = 0X1030U,
            START = 0X1070U,
            THUNK_AX = 0X10B0U,
            DEREG = 0X10C0U,
            REG = 0X1100U,
            AUX = 0X1150U,
            FRAME = 0X11A0U,
            THUNK_DX = 0X11A9U,
            MAIN = 0X11ADU,
            THUNK_BX = 0X11C5U,
            CSU_INIT = 0X11D0U,
            CSU_FINI = 0X1240U,
            THUNK_BP = 0X1245U,
        };
#else
        enum SymbolAddr : uint64_t {
            PLT = 0X1020U,
            START = 0X1040U,
            DEREG = 0X1070U,
            REG = 0X10A0U,
            AUX = 0X10E0U,
            FRAME = 0X1120U,
            MAIN = 0X1129U,
            CSU_INIT = 0X1140U,
            CSU_FINI = 0X11B0U,
        };
#endif
#ifdef __arm__
        for (uint64_t addr = SymbolAddr::START; addr < SymbolAddr::THUNK_AX; ++addr) {
#else
        for (uint64_t addr = SymbolAddr::START; addr < SymbolAddr::START; ++addr) {
#endif
            if (elfSymbols->GetSymbolWithVaddr(addr).IsValid()) {
                EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(addr).demangle_, "_start");
            }
        }
        for (uint64_t addr = SymbolAddr::DEREG; addr < SymbolAddr::REG; ++addr) {
            if (elfSymbols->GetSymbolWithVaddr(addr).IsValid()) {
                EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(addr).demangle_, "deregister_tm_clones");
            }
        }
        for (uint64_t addr = SymbolAddr::REG; addr < SymbolAddr::AUX; ++addr) {
            if (elfSymbols->GetSymbolWithVaddr(addr).IsValid()) {
                EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(addr).demangle_, "register_tm_clones");
            }
        }
        for (uint64_t addr = SymbolAddr::AUX; addr < SymbolAddr::FRAME; ++addr) {
            if (elfSymbols->GetSymbolWithVaddr(addr).IsValid()) {
                EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(addr).demangle_, "__do_global_dtors_aux");
            }
        }
#ifdef __arm__
        for (uint64_t addr = SymbolAddr::FRAME; addr < SymbolAddr::THUNK_DX; ++addr) {
#else
        for (uint64_t addr = SymbolAddr::FRAME; addr < SymbolAddr::MAIN; ++addr) {
#endif
            if (elfSymbols->GetSymbolWithVaddr(addr).IsValid()) {
                EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(addr).demangle_, "frame_dummy");
            }
        }
#ifdef __arm__
        for (uint64_t addr = SymbolAddr::MAIN; addr < SymbolAddr::THUNK_BX; ++addr) {
#else
        for (uint64_t addr = SymbolAddr::MAIN; addr < SymbolAddr::CSU_INIT; ++addr) {
#endif
            if (elfSymbols->GetSymbolWithVaddr(addr).IsValid()) {
                EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(addr).demangle_, "main");
            }
        }
        for (uint64_t addr = SymbolAddr::CSU_INIT; addr < SymbolAddr::CSU_FINI; ++addr) {
            if (elfSymbols->GetSymbolWithVaddr(addr).IsValid()) {
                EXPECT_EQ(elfSymbols->GetSymbolWithVaddr(addr).demangle_, "__libc_csu_init");
            }
        }
        if (HasFailure()) {
            PrintSymbols(elfSymbols->GetSymbols());
        }
    }
}

/**
 * @tc.name: GetVaddrInSymbols
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, GetVaddrInSymbols, TestSize.Level1)
{
    /*
        00200000-002c5000 r--p 00000000 08:02 46400311
        002c5000-00490000 r-xp 000c5000 08:02 4640031

        [14] .text             PROGBITS         00000000002c5000  000c5000

        if ip is 0x46e6ab
        1. find the map range is 002c5000-00490000
        2. ip - map start(002c5000) = map section offset
        3. map section offset + map page offset(000c5000) = elf file offset
        4. elf file offset - exec file offset(000c5000)
            = ip offset (ip always in exec file offset)
        5. ip offset + exec begin vaddr(2c5000) = virtual ip in elf
    */
    auto elfSymbols = SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE);
    elfSymbols->textExecVaddrFileOffset_ = 0x000c5000;
    elfSymbols->textExecVaddr_ = 0x002c5000;

    // most easy case
    EXPECT_EQ(elfSymbols->GetVaddrInSymbols(0x002c5123, 0x002c5000, 0x000c5000), 0x002c5123U);

    // ip and map both change
    EXPECT_EQ(elfSymbols->GetVaddrInSymbols(0xFF2c5123, 0xFF2c5000, 0x000c5000), 0x002c5123U);
    EXPECT_EQ(elfSymbols->GetVaddrInSymbols(0x00000123, 0x00000000, 0x000c5000), 0x002c5123U);

    // map page and offset change
    EXPECT_EQ(elfSymbols->GetVaddrInSymbols(0x002ca123, 0x002c5000, 0x000c0000), 0x002c5123U);
    EXPECT_EQ(elfSymbols->GetVaddrInSymbols(0x002c4123, 0x002c5000, 0x000c6000), 0x002c5123U);

    // kernel dont care offset
    auto kernelSymbols = SymbolsFile::CreateSymbolsFile(SYMBOL_KERNEL_FILE);
    EXPECT_EQ(kernelSymbols->GetVaddrInSymbols(0x001234, 0x002c5000, 0x000c5000), 0x001234U);
}

/**
 * @tc.name: FindSymbolFile
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, FindSymbolFile, TestSize.Level1)
{
    auto symbols = SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE);

    std::vector<std::string> symbolsFileSearchPaths;
    std::string symboleFilePath;

    symboleFilePath = TEST_FILE_VMLINUX;
    EXPECT_EQ(symbols->FindSymbolFile(symbolsFileSearchPaths, symboleFilePath).empty(), true);

    symbolsFileSearchPaths.emplace_back(PATH_RESOURCE_TEST_DATA);
    EXPECT_EQ(symbols->FindSymbolFile(symbolsFileSearchPaths, symboleFilePath).empty(), false);

    symbolsFileSearchPaths.clear();
    EXPECT_EQ(symbols->FindSymbolFile(symbolsFileSearchPaths, symboleFilePath).empty(), true);

    symboleFilePath = PATH_RESOURCE_TEST_DATA + TEST_FILE_VMLINUX;
    EXPECT_EQ(symbols->FindSymbolFile(symbolsFileSearchPaths, symboleFilePath).empty(), false);

    symbolsFileSearchPaths.emplace_back(PATH_RESOURCE_TEST_DATA);
    EXPECT_EQ(symbols->FindSymbolFile(symbolsFileSearchPaths, symboleFilePath).empty(), false);

    symboleFilePath = TEST_FILE_ELF;
    EXPECT_EQ(symbols->FindSymbolFile(symbolsFileSearchPaths, symboleFilePath).empty(), false);

    symbolsFileSearchPaths.clear();
    EXPECT_EQ(symbols->FindSymbolFile(symbolsFileSearchPaths, symboleFilePath).empty(), true);
}

/**
 * @tc.name: GetBuildId
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, GetBuildId, TestSize.Level2)
{
    std::unique_ptr<SymbolsFile> symbolsFile = SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE);
    // empty elf
    EXPECT_EQ(symbolsFile->GetBuildId().empty(), true);
    // set search path
    ASSERT_EQ(symbolsFile->setSymbolsFilePath(PATH_RESOURCE_TEST_DATA), true);

    symbolsFile = SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE);
    ASSERT_EQ(symbolsFile->setSymbolsFilePath(PATH_RESOURCE_TEST_DATA), true);
    // kernel elf
    EXPECT_EQ(symbolsFile->LoadSymbols(nullptr, TEST_FILE_VMLINUX), true);
    EXPECT_EQ(symbolsFile->GetBuildId().empty(), false);

    symbolsFile = SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE);
    ASSERT_EQ(symbolsFile->setSymbolsFilePath(PATH_RESOURCE_TEST_DATA), true);
    // stripped elf
    EXPECT_EQ(symbolsFile->LoadSymbols(nullptr, TEST_FILE_ELF), true);
    EXPECT_EQ(symbolsFile->GetBuildId().empty(), false);

    symbolsFile = SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE);
    ASSERT_EQ(symbolsFile->setSymbolsFilePath(PATH_RESOURCE_TEST_DATA), true);
    // stripped elf
    EXPECT_EQ(symbolsFile->LoadSymbols(nullptr, TEST_FILE_ELF_STRIPPED), true);
    EXPECT_EQ(symbolsFile->GetBuildId().empty(), false);
}

struct SectionInfo {
    const std::string name;
    uint64_t addr;
    uint64_t size;
    uint64_t offset;
};

/**
 * @tc.name: GetSectionInfo
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, GetSectionInfo, TestSize.Level1)
{
    std::unique_ptr<SymbolsFile> symbolsFile =
        SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE, TEST_FILE_ELF_FULL_PATH);
    ASSERT_EQ(symbolsFile->LoadDebugInfo(), true);
    ASSERT_EQ(symbolsFile->LoadSymbols(), true);

    /*
    from readelf -e elf32_test
    32bit
    [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
    [ 0]                   NULL            00000000 000000 000000 00      0   0  0
    [ 1] .interp           PROGBITS        000001b4 0001b4 000013 00   A  0   0  1
    [ 2] .note.gnu.build-i NOTE            000001c8 0001c8 000024 00   A  0   0  4
    [16] .text             PROGBITS        00001320 001320 000818 00  AX  0   0 16
    [19] .eh_frame_hdr     PROGBITS        00002034 002034 0000dc 00   A  0   0  4
    [20] .eh_frame         PROGBITS        00002110 002110 0003a0 00   A  0   0  4
    [29] .symtab           SYMTAB          00000000 003034 000710 10     30  50  4
    [30] .strtab           STRTAB          00000000 003744 000c3d 00      0   0  1
    [31] .shstrtab         STRTAB          00000000 004381 00012a 00      0   0  1

    from readelf -e elf_test
    64bit
    Section Headers:
    [Nr] Name              Type             Address           Offset
        Size              EntSize          Flags  Link  Info  Align
    [ 0]                   NULL             0000000000000000  00000000
        0000000000000000  0000000000000000           0     0     0
    [ 1] .interp           PROGBITS         0000000000000318  00000318
        000000000000001c  0000000000000000   A       0     0     1
    [ 2] .note.gnu.propert NOTE             0000000000000338  00000338
        0000000000000020  0000000000000000   A       0     0     8
    [16] .text             PROGBITS         00000000000022f0  000022f0
        00000000000007b5  0000000000000000  AX       0     0     16
    [19] .eh_frame_hdr     PROGBITS         0000000000003034  00003034
        00000000000000bc  0000000000000000   A       0     0     4
    [20] .eh_frame         PROGBITS         00000000000030f0  000030f0
        0000000000000320  0000000000000000   A       0     0     8
    [29] .symtab           SYMTAB           0000000000000000  00004040
        00000000000009f0  0000000000000018          30    50     8
    [30] .strtab           STRTAB           0000000000000000  00004a30
        0000000000000bbb  0000000000000000           0     0     1
    [31] .shstrtab         STRTAB           0000000000000000  000055eb
        000000000000012c  0000000000000000           0     0     1
    */
#ifdef __arm__
    const std::vector<SectionInfo> sectionCheckList = {
        {".note.gnu.build-id", 0x000001c8, 0x000024, 0x0001c8},
        {".text", 0x00001320, 0x000818, 0x001320},
        {".eh_frame_hdr", 0x00002034, 0x0000dc, 0x002034},
        {".eh_frame", 0x00002110, 0x0003a0, 0x002110},
        {".symtab", 0x00000000, 0x000710, 0x003034},
        {".strtab", 0x00000000, 0x000c3d, 0x003744},
    };
#else
    const std::vector<SectionInfo> sectionCheckList = {
        {".note.gnu.build-id", 0x0000000000000358, 0x0000000000000024, 0x00000358},
        {".text", 0x00000000000022f0, 0x00000000000007b5, 0x000022f0},
        {".eh_frame_hdr", 0x0000000000003034, 0x00000000000000bc, 0x00003034},
        {".eh_frame", 0x00000000000030f0, 0x0000000000000320, 0x000030f0},
        {".symtab", 0x00000000, 0x00000000000009f0, 0x00004040},
        {".strtab", 0x00000000, 0x0000000000000bbb, 0x00004a30},
    };
#endif
    for (SectionInfo info : sectionCheckList) {
        uint64_t addr;
        uint64_t size;
        uint64_t offset;
        EXPECT_EQ(symbolsFile->GetSectionInfo(info.name, addr, size, offset), true);
        EXPECT_EQ(addr, info.addr);
        EXPECT_EQ(size, info.size);
        EXPECT_EQ(offset, info.offset);
        if (HasFailure()) {
            printf("SectionInfo check failed at '%s', %" PRIx64 ",%" PRIx64 ",%" PRIx64 "\n",
                   info.name.c_str(), info.addr, info.size, info.offset);
        }
    }
}

#ifndef __arm__
/**
 * @tc.name: GetHDRSectionInfo
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, GetHDRSectionInfo, TestSize.Level1)
{
    std::unique_ptr<SymbolsFile> symbolsFile =
        SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE, TEST_FILE_ELF_FULL_PATH);

    ASSERT_EQ(symbolsFile->LoadSymbols(), true);
    ASSERT_EQ(symbolsFile->LoadDebugInfo(), true);

    uint64_t ehFrameHdrElfOffset;
    uint64_t fdeTableElfOffset;
    uint64_t fdeTableSize;

    /*
        readelf -e elf32_test | grep .eh_frame_hdr
        [19] .eh_frame_hdr     PROGBITS        00002034 002034 0000dc 00   A  0   0  4

        readelf --debug-dump=frames elf32_test | grep FDE | wc -l
        26

        readelf -e elf_test | grep .eh_frame_hdr
        [19] .eh_frame_hdr     PROGBITS         0000000000003034  00003034

        readelf --debug-dump=frames elf_test | grep FDE | wc -l
        22
    */
    symbolsFile->GetHDRSectionInfo(ehFrameHdrElfOffset, fdeTableElfOffset, fdeTableSize);

    EXPECT_EQ(ehFrameHdrElfOffset, 0x00003034u);
    EXPECT_EQ(fdeTableSize, 22U);
}

/**
 * @tc.name: GetHDRSectionInfo
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, GetHDRSectionInfoStripped, TestSize.Level2)
{
    std::unique_ptr<SymbolsFile> symbolsFile = SymbolsFile::CreateSymbolsFile(
        SYMBOL_ELF_FILE, PATH_RESOURCE_TEST_DATA + TEST_FILE_ELF_STRIPPED_NOEFHDR);

    ASSERT_EQ(symbolsFile->LoadDebugInfo(), true);

    uint64_t ehFrameHdrElfOffset;
    uint64_t fdeTableElfOffset;
    uint64_t fdeTableSize;

    symbolsFile->GetHDRSectionInfo(ehFrameHdrElfOffset, fdeTableElfOffset, fdeTableSize);
    uint64_t addr = 0;
    uint64_t size = 0;
    uint64_t offset = 0;
    EXPECT_EQ(symbolsFile->GetSectionInfo(EH_FRAME_HR, addr, size, offset), false);
    EXPECT_EQ(offset, 0U);
    EXPECT_EQ(size, 0U);
    EXPECT_EQ(addr, 0U);
}
#endif

/**
 * @tc.name: CreateSymbolsFile
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, CreateSymbolsFile, TestSize.Level1)
{
    EXPECT_NE(SymbolsFile::CreateSymbolsFile(), nullptr);
    EXPECT_NE(SymbolsFile::CreateSymbolsFile(SYMBOL_KERNEL_FILE), nullptr);
    EXPECT_NE(SymbolsFile::CreateSymbolsFile(SYMBOL_KERNEL_MODULE_FILE), nullptr);
    EXPECT_NE(SymbolsFile::CreateSymbolsFile(SYMBOL_KERNEL_THREAD_FILE), nullptr);
    EXPECT_NE(SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE), nullptr);
    EXPECT_NE(SymbolsFile::CreateSymbolsFile(SYMBOL_JAVA_FILE), nullptr);
    EXPECT_NE(SymbolsFile::CreateSymbolsFile(SYMBOL_JS_FILE), nullptr);
    EXPECT_NE(SymbolsFile::CreateSymbolsFile(SYMBOL_HAP_FILE), nullptr);
    EXPECT_NE(SymbolsFile::CreateSymbolsFile(SYMBOL_CJ_FILE), nullptr);
    EXPECT_NE(SymbolsFile::CreateSymbolsFile(SYMBOL_UNKNOW_FILE), nullptr);
    EXPECT_NE(SymbolsFile::CreateSymbolsFile(SymbolsFileType(-1)), nullptr);
    EXPECT_EQ(SymbolsFile::CreateSymbolsFile(SymbolsFileType(-2))->symbolFileType_,
              SYMBOL_UNKNOW_FILE);

    EXPECT_EQ(SymbolsFile::CreateSymbolsFile(KERNEL_MMAP_NAME)->symbolFileType_,
              SYMBOL_KERNEL_FILE);
    EXPECT_EQ(SymbolsFile::CreateSymbolsFile(TEST_FILE_ELF_FULL_PATH)->symbolFileType_,
              SYMBOL_ELF_FILE);
}

/**
 * @tc.name: LoadSymbolsFromSaved
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, LoadSymbolsFromSaved, TestSize.Level1)
{
    SymbolFileStruct sfs;
    for (unsigned int type = 0; type < SYMBOL_UNKNOW_FILE; type++) {
        sfs.filePath_ = std::to_string(rnd_());
        sfs.symbolType_ = type;
        sfs.textExecVaddrFileOffset_ = rnd_();
        sfs.textExecVaddr_ = rnd_();
        sfs.buildId_ = std::to_string(rnd_());
        int nameIndex = 0;
        // after LoadSymbolsFromSaved it will sort from low to high
        // so we make a order item to test
        constexpr int rndMax = 10000;
        std::uniform_int_distribution<int> rndLimi(0, rndMax);
        sfs.symbolStructs_.emplace_back(rndLimi(rnd_) + nameIndex * rndMax, rnd_(),
                                        std::to_string(nameIndex));
        nameIndex++;
        sfs.symbolStructs_.emplace_back(rndLimi(rnd_) + nameIndex * rndMax, rnd_(),
                                        std::to_string(nameIndex));
        nameIndex++;
        sfs.symbolStructs_.emplace_back(rndLimi(rnd_) + nameIndex * rndMax, rnd_(),
                                        std::to_string(nameIndex));
        nameIndex++;

        // setup the min vaddr

        std::unique_ptr<SymbolsFile> symbolsFile = SymbolsFile::LoadSymbolsFromSaved(sfs);

        EXPECT_EQ(symbolsFile->filePath_, sfs.filePath_);
        EXPECT_EQ(symbolsFile->symbolFileType_, sfs.symbolType_);
        EXPECT_EQ(symbolsFile->textExecVaddr_, sfs.textExecVaddr_);
        EXPECT_EQ(symbolsFile->textExecVaddrFileOffset_, sfs.textExecVaddrFileOffset_);
        EXPECT_EQ(symbolsFile->GetBuildId(), sfs.buildId_);
        EXPECT_EQ(symbolsFile->GetSymbols().size(), sfs.symbolStructs_.size());

        for (DfxSymbol symbol : symbolsFile->GetSymbols()) {
            SymbolStruct symbolStruct = sfs.symbolStructs_.front();
            EXPECT_EQ(symbol.funcVaddr_, symbolStruct.vaddr_);
            EXPECT_EQ(symbol.size_, symbolStruct.len_);
            EXPECT_EQ(symbol.name_, symbolStruct.symbolName_);
            sfs.symbolStructs_.erase(sfs.symbolStructs_.begin());
        }
    }
}

/**
 * @tc.name: exportSymbolToFileFormatMatched
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, exportSymbolToFileFormatMatched, TestSize.Level2)
{
    for (int type = 0; type < SYMBOL_UNKNOW_FILE; type++) {
        auto symbolsFile = SymbolsFile::CreateSymbolsFile();
        symbolsFile->filePath_ = std::to_string(rnd_());
        symbolsFile->symbolFileType_ = static_cast<SymbolsFileType>(type);
        symbolsFile->textExecVaddrFileOffset_ = rnd_();
        symbolsFile->buildId_ = std::to_string(rnd_());
        int nameIndex = 0;
        // after LoadSymbolsFromSaved it will sort from low to high
        // so we make a order item to test
        constexpr int rndMax = 10000;
        std::uniform_int_distribution<int> rndLimi(0, rndMax);
        symbolsFile->symbols_.emplace_back(rndLimi(rnd_) + nameIndex * rndMax, rnd_(),
                                           std::to_string(nameIndex), symbolsFile->filePath_);
        nameIndex++;
        symbolsFile->symbols_.emplace_back(rndLimi(rnd_) + nameIndex * rndMax, rnd_(),
                                           std::to_string(nameIndex), symbolsFile->filePath_);
        nameIndex++;
        symbolsFile->symbols_.emplace_back(rndLimi(rnd_) + nameIndex * rndMax, rnd_(),
                                           std::to_string(nameIndex), symbolsFile->filePath_);
        nameIndex++;

        // setup the min vaddr
        symbolsFile->textExecVaddr_ = std::numeric_limits<uint64_t>::max();

        for (auto &symbol : symbolsFile->symbols_) {
            symbolsFile->textExecVaddr_ = std::min(symbol.funcVaddr_, symbolsFile->textExecVaddr_);
        }

        // access last one to make it as matched.
        uint64_t matchedVaddr = symbolsFile->symbols_.back().funcVaddr_;
        auto symbol = symbolsFile->GetSymbolWithVaddr(matchedVaddr);
        EXPECT_EQ(symbol.funcVaddr_, matchedVaddr);
        if (HasFailure()) {
            PrintSymbols(symbolsFile->GetSymbols());
        }

        SymbolFileStruct sfs {};
        symbolsFile->ExportSymbolToFileFormat(sfs);

        EXPECT_EQ(symbolsFile->symbolFileType_, sfs.symbolType_);
        EXPECT_EQ(symbolsFile->textExecVaddrFileOffset_, sfs.textExecVaddrFileOffset_);
        EXPECT_EQ(symbolsFile->GetBuildId(), sfs.buildId_);

        // matched one should be remove
        EXPECT_EQ(sfs.symbolStructs_.size(), 1u);
        for (SymbolStruct symbolStruct : sfs.symbolStructs_) {
            // nomore found for matched vaddr
            EXPECT_EQ(symbolStruct.vaddr_, matchedVaddr);
        }
    }
}

/**
 * @tc.name: UpdateBuildIdIfMatch
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, UpdateBuildIdIfMatch, TestSize.Level1)
{
    auto file = SymbolsFile::CreateSymbolsFile();
    file->buildId_ = "123";
    file->UpdateBuildIdIfMatch("456");
    EXPECT_STREQ(file->buildId_.c_str(), "123");
    EXPECT_STRNE(file->buildId_.c_str(), "456");
}

/**
 * @tc.name: CreateCJSymbolsFile
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, CreateCJSymbolsFile, TestSize.Level1)
{
    std::string cjLibPath = "/system/lib64/platformsdk/cjsdk/libcangjie-std-core.so";
    std::filesystem::path cjPath(cjLibPath);
    if (std::filesystem::exists(cjPath)) {
        auto file = SymbolsFile::CreateSymbolsFile(cjLibPath);
        EXPECT_NE(file, nullptr);
        EXPECT_EQ(file->symbolFileType_, SYMBOL_CJ_FILE);
    }
}

/**
 * @tc.name: CreateCJSymbolsFile2
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, CreateCJSymbolsFile2, TestSize.Level1)
{
    std::string cjLibPath = "/data/storage/libohos_app_cangjie_entry.so";
    std::filesystem::path cjPath(cjLibPath);
    auto file = SymbolsFile::CreateSymbolsFile(cjLibPath);
    EXPECT_NE(file, nullptr);
}

/**
 * @tc.name: CreateV8Symbols
 * @tc.desc: Test CreateSymbolsFile function and parse symbol
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, CreateV8Symbols, TestSize.Level1)
{
    SymbolsFile::needParseJsFunc_ = false;
    const std::string filename = "[anon:JSVM_JIT]";
    auto symbolsFile = SymbolsFile::CreateSymbolsFile(filename);
    EXPECT_EQ(symbolsFile->IsV8(), true);
    uint64_t ip = rnd_();
    uint64_t begin = rnd_();
    uint64_t len = rnd_();
    uint64_t offset = rnd_();
    uint32_t prot = rnd_();
    std::shared_ptr<DfxMap> map = std::make_shared<DfxMap>(begin, begin + len, offset, prot, filename);
    EXPECT_EQ(symbolsFile->LoadDebugInfo(map, "/system/lib64/libv8_shared.so"), true);
    EXPECT_EQ(symbolsFile->LoadSymbols(map, "/system/lib64/libv8_shared.so"), true);
    auto symbol = symbolsFile->GetSymbolWithPcAndMap(ip, map);
    EXPECT_EQ(symbol.IsValid(), false);
}

/**
 * @tc.name: CreateV8Symbols2
 * @tc.desc: Test CreateSymbolsFile function and parse symbol
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, CreateV8Symbols2, TestSize.Level1)
{
    SymbolsFile::needParseJsFunc_ = false;
    const std::string filename = "[anon:JSVM_JIT]";
    auto symbolsFile = SymbolsFile::CreateSymbolsFile(filename);
    EXPECT_EQ(symbolsFile->IsV8(), true);
    uint64_t ip = rnd_();
    uint64_t begin = rnd_();
    uint64_t len = rnd_();
    uint64_t offset = rnd_();
    uint32_t prot = rnd_();
    std::shared_ptr<DfxMap> map = std::make_shared<DfxMap>(begin, begin + len, offset, prot, filename);
    symbolsFile->symbolsMap_.insert(std::make_pair(ip,
        DfxSymbol(ip, 0, "", "", map->name)));
    auto symbol = symbolsFile->GetSymbolWithPcAndMap(ip, map);
    EXPECT_EQ(symbol.IsValid(), true);
}

/**
 * @tc.name: CreateV8Symbols3
 * @tc.desc: Only test CreateSymbolsFile function
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, CreateV8Symbols3, TestSize.Level1)
{
    SymbolsFile::needParseJsFunc_ = true;
    const std::string filename = "[anon:ARKWEB_JIT]";
    auto symbolsFile = SymbolsFile::CreateSymbolsFile(filename);
    EXPECT_EQ(symbolsFile->IsV8(), false);
    uint64_t ip = rnd_();
    uint64_t begin = rnd_();
    uint64_t len = rnd_();
    uint64_t offset = rnd_();
    uint32_t prot = rnd_();
    std::shared_ptr<DfxMap> map = std::make_shared<DfxMap>(begin, begin + len, offset, prot, filename);
    symbolsFile->symbolsMap_.insert(std::make_pair(ip,
        DfxSymbol(ip, 0, "", "", map->name)));
    auto symbol = symbolsFile->GetSymbolWithPcAndMap(ip, map);
    EXPECT_EQ(symbol.IsValid(), true);
}

/**
 * @tc.name: CreateV8Symbols4
 * @tc.desc: Test CreateSymbolsFile function and parse symbol
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, CreateV8Symbols4, TestSize.Level1)
{
    SymbolsFile::needParseJsFunc_ = true;
    const std::string filename = "[anon:JSVM_JIT]";
    auto symbolsFile = SymbolsFile::CreateSymbolsFile(filename);
    EXPECT_EQ(symbolsFile->IsV8(), false);
    uint64_t ip = rnd_();
    uint64_t begin = rnd_();
    uint64_t len = rnd_();
    uint64_t offset = rnd_();
    uint32_t prot = rnd_();
    std::shared_ptr<DfxMap> map = std::make_shared<DfxMap>(begin, begin + len, offset, prot, filename);
    EXPECT_EQ(symbolsFile->LoadDebugInfo(map, "/system/lib64/libv8_shared.so"), true);
    EXPECT_EQ(symbolsFile->LoadSymbols(map, "/system/lib64/libv8_shared.so"), true);
    auto symbol = symbolsFile->GetSymbolWithPcAndMap(ip, map);
    EXPECT_EQ(symbol.IsValid(), false);
}

/**
 * @tc.name: V8SymbolsErr
 * @tc.desc: Test CreateSymbolsFile error
 * @tc.type: FUNC
 */
HWTEST_F(SymbolsFileTest, V8SymbolsErr, TestSize.Level1)
{
    const std::string filename = "[anon:JSVM_JIT]";
    auto symbolsFile = SymbolsFile::CreateSymbolsFile(filename);
    std::shared_ptr<DfxMap> map = nullptr;
    uint64_t ip = rnd_();
    EXPECT_EQ(symbolsFile->LoadDebugInfo(map, "/system/lib64/libv8_shared.so"), false);
    EXPECT_EQ(symbolsFile->LoadSymbols(map, "/system/lib64/libv8_shared.so"), false);
    auto symbol = symbolsFile->GetSymbolWithPcAndMap(ip, map);
    EXPECT_EQ(symbol.IsValid(), false);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
