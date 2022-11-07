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

#include "virtual_thread_test.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <link.h>
#include <random>
#include <sys/mman.h>

#include <hilog/log.h>

#include "symbols_file_test.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class VirtualThreadTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    const std::string TEST_LOG_MESSAGE = "<HELLO_TEST_LOG_MESSAGE>";
    void LogLevelTest(std::vector<std::string> args, DebugLevel level);
    default_random_engine rnd_;
    static std::string myFilePath_;
    static std::string GetFullPath()
    {
        char path[PATH_MAX];
        int i = readlink("/proc/self/exe", path, sizeof(path));
        path[i] = '\0';
        return path;
    }
    static int PhdrCallBack(struct dl_phdr_info *info, size_t size, void *data);
    static void MakeMapsFromDlpi(const std::string &dlpiName, const struct dl_phdr_info *info,
                                 std::vector<MemMapItem> &phdrMaps);
};

std::string VirtualThreadTest::myFilePath_;

void VirtualThreadTest::SetUpTestCase()
{
    DebugLogger::GetInstance()->OpenLog(DEFAULT_UT_LOG_DIR + "VirtualThreadTest.txt");
}

void VirtualThreadTest::TearDownTestCase()
{
    DebugLogger::GetInstance()->RestoreLog();
}

void VirtualThreadTest::SetUp() {}

void VirtualThreadTest::TearDown() {}

/**
 * @tc.name: MemMapItem Same
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualThreadTest, MemMapItemSame, TestSize.Level1)
{
    MemMapItem a;
    EXPECT_EQ(a == "a", false);
    EXPECT_EQ(a == "b", false);
    EXPECT_EQ(a == "", true);

    a.name_ = "a";
    EXPECT_EQ(a == "a", true);
    EXPECT_EQ(a == "b", false);

    a.name_ = "a1";
    EXPECT_EQ(a == "a", false);
    EXPECT_EQ(a == "b", false);

    a.name_ = "1";
    EXPECT_EQ(a == "a", false);
    EXPECT_EQ(a == "b", false);

    a.name_ = "";
    EXPECT_EQ(a == "a", false);
    EXPECT_EQ(a == "b", false);
}

/**
 * @tc.name: MemMapItem FileOffsetFromAddr
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualThreadTest, MemMapItemFileOffsetFromAddr, TestSize.Level1)
{
    MemMapItem a;

    a.begin_ = 100;
    a.pageoffset_ = 200;
    EXPECT_EQ(a.FileOffsetFromAddr(0), 100u);
    EXPECT_EQ(a.FileOffsetFromAddr(10), 110u);
    EXPECT_EQ(a.FileOffsetFromAddr(100), 200u);
    EXPECT_EQ(a.FileOffsetFromAddr(1000), 1100u);

    a.begin_ = 300;
    a.pageoffset_ = 200;
    EXPECT_EQ(a.FileOffsetFromAddr(0), std::numeric_limits<uint64_t>::max() - 100u + 1u);
    EXPECT_EQ(a.FileOffsetFromAddr(10), std::numeric_limits<uint64_t>::max() - 90u + 1u);
    EXPECT_EQ(a.FileOffsetFromAddr(100), 0u);
    EXPECT_EQ(a.FileOffsetFromAddr(1000), 900u);
}

/**
 * @tc.name: MemMapItem ToString
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualThreadTest, MemMapItemFileToString, TestSize.Level1)
{
    MemMapItem a;

    a.begin_ = 0x100;
    a.pageoffset_ = 0x200;
    EXPECT_EQ(a.ToString().find("100") != std::string::npos, true);
    EXPECT_EQ(a.ToString().find("200") != std::string::npos, true);
    EXPECT_EQ(a.ToString().find("300") != std::string::npos, false);

    a.begin_ = 0x300;
    a.pageoffset_ = 0x200;
    EXPECT_EQ(a.ToString().find("100") != std::string::npos, false);
    EXPECT_EQ(a.ToString().find("200") != std::string::npos, true);
    EXPECT_EQ(a.ToString().find("300") != std::string::npos, true);
}

void VirtualThreadTest::MakeMapsFromDlpi(const std::string &dlpiName,
                                         const struct dl_phdr_info *info,
                                         std::vector<MemMapItem> &phdrMaps)
{
    if (info == nullptr) {
        HLOGE("param is null");
        return;
    }
    int phdrType;
    HLOGV("Name: \"%s\" (%d segments)", dlpiName.c_str(), info->dlpi_phnum);
    for (int i = 0; i < info->dlpi_phnum; i++) {
        phdrType = info->dlpi_phdr[i].p_type;
        if (phdrType != PT_LOAD) {
            continue;
        }
        HLOGV("    %2d: [%14p; memsz:%7jx] align %jx flags: %#jx [(%#x)]", i,
              (void *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr),
              (uintmax_t)info->dlpi_phdr[i].p_memsz, (uintmax_t)info->dlpi_phdr[i].p_align,
              (uintmax_t)info->dlpi_phdr[i].p_flags, phdrType);

        MemMapItem &item = phdrMaps.emplace_back();
        item.begin_ = (info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
        item.end_ = RoundUp(item.begin_ + info->dlpi_phdr[i].p_memsz, info->dlpi_phdr[i].p_align);
        item.pageoffset_ = info->dlpi_phdr[i].p_offset;
        item.name_ = dlpiName;
    }
    for (const MemMapItem &item : phdrMaps) {
        HLOGV("%s", item.ToString().c_str());
    }
    EXPECT_NE(phdrMaps.size(), 0u);
}

int VirtualThreadTest::PhdrCallBack(struct dl_phdr_info *info, size_t size, void *data)
{
    if (info == nullptr || data == nullptr) {
        HLOGE("param is null");
        return -1;
    }
    VirtualThread *thread = static_cast<VirtualThread *>(data);
    std::vector<MemMapItem> phdrMaps {};
    std::vector<const MemMapItem *> memMaps {};
    static std::string myFilePath = GetFullPath();
    EXPECT_NE(thread->GetMaps().size(), 0u);
    std::string dlpiName = info->dlpi_name;
    if (StringStartsWith(dlpiName, "./") and !StringEndsWith(dlpiName, ".so")) {
        dlpiName = myFilePath;
    }
    if (info->dlpi_name == nullptr || info->dlpi_name[0] == '\0') {
        // dont care empty pt
        return 0;
    } else {
        MakeMapsFromDlpi(dlpiName, info, phdrMaps);
    }

    for (const MemMapItem &item : thread->GetMaps()) {
        if (item.name_ == dlpiName) {
            HLOGV("%s", item.ToString().c_str());
            memMaps.emplace_back(&item);
        }
    }

    if (memMaps.size() == 0u) {
        // show all the items if not any match mapitem found
        for (const MemMapItem &item : thread->GetMaps()) {
            HLOGV("%s", item.ToString().c_str());
        }
        return 0;
    }

    if (memMaps.size() == phdrMaps.size()) {
        EXPECT_EQ(memMaps.front()->begin_, phdrMaps.front().begin_);
        EXPECT_EQ(memMaps.front()->pageoffset_, phdrMaps.front().pageoffset_);
    }
    return 0;
}

/**
 * @tc.name: ParseMap
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualThreadTest, ParseMap, TestSize.Level1)
{
    std::vector<std::unique_ptr<SymbolsFile>> files;
    VirtualThread thread(getpid(), files);
    thread.ParseMap();

    dl_iterate_phdr(PhdrCallBack, static_cast<void *>(&thread));

    for (const MemMapItem &item : thread.GetMaps()) {
        EXPECT_EQ(item.name_.empty(), false);
        EXPECT_STRNE(item.name_.c_str(), MMAP_NAME_HEAP.c_str());
        EXPECT_STRNE(item.name_.c_str(), MMAP_NAME_ANON.c_str());
    }
}

/**
 * @tc.name: CreateMapItem
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualThreadTest, CreateMapItem, TestSize.Level1)
{
    std::vector<std::unique_ptr<SymbolsFile>> files;
    VirtualThread thread(getpid(), files);
    thread.CreateMapItem("0.so", 1000, 2000, 3000);
    thread.CreateMapItem("1.so", 3000, 4000, 5000);
    thread.CreateMapItem("2.so", 10000, 20000, 30000);

    const std::vector<MemMapItem> &maps = thread.GetMaps();

    EXPECT_EQ(maps.size(), 3u);
    EXPECT_EQ(maps.at(0).begin_, 1000u);
    EXPECT_EQ(maps.at(1).begin_, 3000u);
    EXPECT_EQ(maps.at(2).begin_, 10000u);

    EXPECT_EQ(maps.at(0).end_, 1000u + 2000u);
    EXPECT_EQ(maps.at(1).end_, 3000u + 4000u);
    EXPECT_EQ(maps.at(2).end_, 10000u + 20000u);

    EXPECT_EQ(maps.at(0).pageoffset_, 3000u);
    EXPECT_EQ(maps.at(1).pageoffset_, 5000u);
    EXPECT_EQ(maps.at(2).pageoffset_, 30000u);

    EXPECT_STREQ(maps.at(0).name_.c_str(), "0.so");
    EXPECT_STREQ(maps.at(1).name_.c_str(), "1.so");
    EXPECT_STREQ(maps.at(2).name_.c_str(), "2.so");
}

/**
 * @tc.name: InheritMaps
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualThreadTest, InheritMaps, TestSize.Level1)
{
    std::vector<std::unique_ptr<SymbolsFile>> files;
    VirtualThread thread(getpid(), files);
    thread.ParseMap();

    VirtualThread thread2(getpid(), gettid() + 1u, thread, files);

    const std::vector<MemMapItem> &maps = thread.GetMaps();
    const std::vector<MemMapItem> &maps2 = thread2.GetMaps();

    ASSERT_EQ(maps.size(), maps2.size());
    for (size_t i = 0; i < maps.size(); i++) {
        EXPECT_STREQ(maps[i].ToString().c_str(), maps2[i].ToString().c_str());
    }

    size_t oldSize = thread.GetMaps().size();
    thread.CreateMapItem("new", 0u, 1u, 2u);
    size_t newSize = thread.GetMaps().size();
    ASSERT_EQ(oldSize, newSize);
    ASSERT_EQ(maps.size(), maps2.size());
    for (size_t i = 0; i < maps.size(); i++) {
        EXPECT_STREQ(maps[i].ToString().c_str(), maps2[i].ToString().c_str());
    }
}

/**
 * @tc.name: FindMapByAddr
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualThreadTest, FindMapByAddr, TestSize.Level1)
{
    std::vector<std::unique_ptr<SymbolsFile>> files;
    VirtualThread thread(getpid(), files);

    thread.CreateMapItem("0.so", 1000u, 2000u, 3000u);
    thread.CreateMapItem("1.so", 3000u, 4000u, 5000u);
    thread.CreateMapItem("2.so", 10000u, 20000u, 30000u);

    const MemMapItem *outMap;
    outMap = thread.FindMapByAddr(0000u);
    EXPECT_EQ(outMap != nullptr, false);

    outMap = thread.FindMapByAddr(1000u);
    ASSERT_EQ(outMap != nullptr, true);
    EXPECT_EQ(outMap->begin_, 1000u);

    outMap = thread.FindMapByAddr(2000u);
    ASSERT_EQ(outMap != nullptr, true);
    EXPECT_EQ(outMap->begin_, 1000u);

    outMap = thread.FindMapByAddr(2999u);
    ASSERT_EQ(outMap != nullptr, true);
    EXPECT_EQ(outMap->begin_, 1000u);

    outMap = thread.FindMapByAddr(3000u);
    ASSERT_EQ(outMap != nullptr, true);
    EXPECT_EQ(outMap->begin_, 3000u);

    EXPECT_EQ(thread.FindMapByAddr(30000u - 1u) != nullptr, true);
    EXPECT_EQ(thread.FindMapByAddr(30000u) != nullptr, false);
    EXPECT_EQ(thread.FindMapByAddr(30000u + 1u) != nullptr, false);
}

/**
 * @tc.name: FindMapByFileInfo
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualThreadTest, FindMapByFileInfo, TestSize.Level1)
{
    std::vector<std::unique_ptr<SymbolsFile>> files;
    VirtualThread thread(getpid(), files);

    thread.CreateMapItem("0.so", 1000u, 2000u, 3000u);
    thread.CreateMapItem("1.so", 3000u, 4000u, 5000u);
    thread.CreateMapItem("2.so", 10000u, 20000u, 30000u);

    const MemMapItem *outMap;
    EXPECT_EQ(thread.FindMapByFileInfo("", 0000u), nullptr);
    EXPECT_EQ(thread.FindMapByFileInfo("0.so", 0000u), nullptr);

    EXPECT_EQ(thread.FindMapByFileInfo("1.so", 3000u), nullptr);
    ASSERT_NE(outMap = thread.FindMapByFileInfo("0.so", 3000u), nullptr);
    EXPECT_EQ(outMap->begin_, 1000u);

    EXPECT_EQ(thread.FindMapByFileInfo("1.so", 4000u), nullptr);
    ASSERT_NE(outMap = thread.FindMapByFileInfo("0.so", 4000u), nullptr);
    EXPECT_EQ(outMap->begin_, 1000u);

    EXPECT_EQ(thread.FindMapByFileInfo("1.so", 4999u), nullptr);
    ASSERT_NE(outMap = thread.FindMapByFileInfo("0.so", 4999u), nullptr);
    EXPECT_EQ(outMap->begin_, 1000u);

    EXPECT_EQ(thread.FindMapByFileInfo("0.so", 5000u), nullptr);
    ASSERT_NE(outMap = thread.FindMapByFileInfo("1.so", 5000u), nullptr);
    EXPECT_EQ(outMap->begin_, 3000u);

    EXPECT_EQ(thread.FindMapByFileInfo("1.so", 50000u - 1), nullptr);
    EXPECT_EQ(thread.FindMapByFileInfo("x.so", 50000u - 1), nullptr);
    EXPECT_NE(thread.FindMapByFileInfo("2.so", 50000u - 1), nullptr);
    EXPECT_EQ(thread.FindMapByFileInfo("2.so", 50000u), nullptr);
    EXPECT_EQ(thread.FindMapByFileInfo("2.so", 50000u + 1), nullptr);
}

/**
 * @tc.name: FindSymbolsFileByMap
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualThreadTest, FindSymbolsFileByMap, TestSize.Level1)
{
    std::vector<std::unique_ptr<SymbolsFile>> files;
    SymbolFileStruct symbolFileStruct;
    symbolFileStruct.filePath_ = "1.elf";
    files.emplace_back(SymbolsFile::LoadSymbolsFromSaved(symbolFileStruct));
    symbolFileStruct.filePath_ = "2.elf";
    files.emplace_back(SymbolsFile::LoadSymbolsFromSaved(symbolFileStruct));
    symbolFileStruct.filePath_ = "3.elf";
    files.emplace_back(SymbolsFile::LoadSymbolsFromSaved(symbolFileStruct));
    VirtualThread thread(getpid(), files);

    MemMapItem inMap;

    inMap.name_ = "";
    EXPECT_EQ(thread.FindSymbolsFileByMap(inMap), nullptr);

    inMap.name_ = "1";
    EXPECT_EQ(thread.FindSymbolsFileByMap(inMap), nullptr);

    inMap.name_ = "1.elf";
    ASSERT_NE(thread.FindSymbolsFileByMap(inMap), nullptr);
    EXPECT_STREQ(thread.FindSymbolsFileByMap(inMap)->filePath_.c_str(), inMap.name_.c_str());

    inMap.name_ = "2.elf";
    ASSERT_NE(thread.FindSymbolsFileByMap(inMap), nullptr);
    EXPECT_STREQ(thread.FindSymbolsFileByMap(inMap)->filePath_.c_str(), inMap.name_.c_str());

    inMap.name_ = "3.elf";
    ASSERT_NE(thread.FindSymbolsFileByMap(inMap), nullptr);
    EXPECT_STREQ(thread.FindSymbolsFileByMap(inMap)->filePath_.c_str(), inMap.name_.c_str());
}

/**
 * @tc.name: ReadRoMemory
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualThreadTest, ReadRoMemory, TestSize.Level1)
{
    std::vector<std::unique_ptr<SymbolsFile>> symbolsFiles;
    VirtualThread thread(getpid(), symbolsFiles);
    std::unique_ptr<FILE, decltype(&fclose)> fp(fopen(TEST_FILE_ELF_FULL_PATH.c_str(), "rb"),
                                                fclose);
    if (fp) {
        struct stat sb = {};
        if (fstat(fileno(fp.get()), &sb) == -1) {
            HLOGE("unable to check the file size");
        } else {
            HLOGV("file stat size %" PRIu64 "", sb.st_size);
        }

        thread.CreateMapItem(TEST_FILE_ELF_FULL_PATH, 0u, sb.st_size, 0u);
        ASSERT_EQ(thread.GetMaps().size(), 1u);

        std::unique_ptr<SymbolsFile> symbolsFile =
            SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE, TEST_FILE_ELF_FULL_PATH);
        ASSERT_NE(symbolsFile, nullptr);
        ASSERT_EQ(symbolsFile->LoadSymbols(), true);

        // add to symbols list
        symbolsFiles.emplace_back(std::move(symbolsFile));

        uint8_t freadByte = '\0';
        uint8_t readRoByte = '\0';
        uint64_t addr = 0x0;

        // first byte
        ASSERT_EQ(fread(&freadByte, 1, 1, fp.get()), 1u);

        const MemMapItem *map = thread.FindMapByAddr(addr);
        ASSERT_EQ(map != nullptr, true);
        if (HasFailure()) {
            printf("map: %s\n", thread.GetMaps().at(0).ToString().c_str());
        }

        EXPECT_NE(thread.FindSymbolsFileByMap(*map), nullptr);
        if (HasFailure()) {
            printf("symbols: %s\n", thread.symbolsFiles_.front().get()->filePath_.c_str());
        }

        ASSERT_EQ(thread.ReadRoMemory(addr++, &readRoByte, 1u), true);
        ASSERT_EQ(freadByte, readRoByte);

        while (fread(&freadByte, 1, 1, fp.get()) == 1u) {
            ASSERT_EQ(thread.ReadRoMemory(addr++, &readRoByte, 1u), true);
            ASSERT_EQ(freadByte, readRoByte);
        }

        // EOF , out of file size should return 0
        ASSERT_EQ(thread.ReadRoMemory(addr++, &readRoByte, 1u), false);
    }
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
