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

#include "virtual_runtime_test.h"

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
class VirtualRuntimeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    const std::string TEST_LOG_MESSAGE = "<HELLO_TEST_LOG_MESSAGE>";
    void LogLevelTest(std::vector<std::string> args, DebugLevel level);
    default_random_engine rnd_;
    std::unique_ptr<VirtualRuntime> runtime_;
    bool RecordCallBack(std::unique_ptr<PerfEventRecord> record);
    size_t callbackCount_ = 0;

    void PrepareKernelSymbol();
    void PrepareUserSymbol();
};

void VirtualRuntimeTest::SetUpTestCase()
{
    DebugLogger::GetInstance()->OpenLog(DEFAULT_UT_LOG_DIR + "VirtualRuntimeTest.txt");
}

void VirtualRuntimeTest::TearDownTestCase()
{
    DebugLogger::GetInstance()->RestoreLog();
}

void VirtualRuntimeTest::SetUp()
{
    runtime_ = std::make_unique<VirtualRuntime>();
    callbackCount_ = 0;
}

void VirtualRuntimeTest::TearDown()
{
    runtime_.release();
}

bool VirtualRuntimeTest::RecordCallBack(std::unique_ptr<PerfEventRecord> record)
{
    callbackCount_++;
    printf("callbackCount_ %zu: type %d\n", callbackCount_, record->GetType());
    return true;
}

/**
 * @tc.name: VirtualRuntimeTest
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualRuntimeTest, VirtualRuntimeTest, TestSize.Level1) {}

/**
 * @tc.name: SetRecordMode
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualRuntimeTest, SetRecordMode, TestSize.Level1)
{
    auto callBack = std::bind(&VirtualRuntimeTest::RecordCallBack, this, std::placeholders::_1);

    EXPECT_EQ(runtime_->recordCallBack_, nullptr);
    runtime_->SetRecordMode(callBack);
    EXPECT_NE(runtime_->recordCallBack_, nullptr);
}

/**
 * @tc.name: SetRecordMode
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualRuntimeTest, UpdateFromRecord, TestSize.Level1)
{
    HLOGD("Func2:%s", __FUNCTION__);
    PerfRecordComm recordComm(false, -1, -2, "3");
    PerfEventRecord &record = static_cast<PerfEventRecord &>(recordComm);
    auto callBack = std::bind(&VirtualRuntimeTest::RecordCallBack, this, std::placeholders::_1);

    runtime_->SetRecordMode(callBack);
    runtime_->UpdateFromRecord(record);
    // one is -1 the other is -2
    EXPECT_EQ(callbackCount_, 2u);
}

/**
 * @tc.name: UpdateKernelSymbols
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualRuntimeTest, UpdateKernelSymbols, TestSize.Level1)
{
    runtime_->UpdateKernelSymbols();
    if (access("/sys/kernel/notes", F_OK) == 0) {
        EXPECT_EQ(runtime_->symbolsFiles_.size(), 1u);
    } else {
        printf("cannot access /sys/kernel/notes\n");
    }
}

/**
 * @tc.name: UpdateKernelModulesSymbols
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualRuntimeTest, UpdateKernelModulesSymbols, TestSize.Level1)
{
    runtime_->UpdateKernelModulesSpaceMaps();
    runtime_->UpdateKernelModulesSymbols();
    std::string modulesMap = ReadFileToString("/proc/modules");
    size_t lines = std::count(modulesMap.begin(), modulesMap.end(), '\n');
    std::set<std::string> modulesCount;
    EXPECT_EQ(runtime_->kernelSpaceMemMaps_.size(), lines);
    for (const std::unique_ptr<SymbolsFile> &symbolsFile : runtime_->GetSymbolsFiles()) {
        EXPECT_EQ(symbolsFile->GetBuildId().empty(), false);
    }
}

/**
 * @tc.name: SetSymbolsPaths
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualRuntimeTest, SetSymbolsPaths, TestSize.Level1)
{
    std::vector<std::string> symbolsSearchPaths;
    runtime_->SetSymbolsPaths(symbolsSearchPaths);

    symbolsSearchPaths.clear();
    symbolsSearchPaths.push_back(PATH_DATA_TEMP);
    symbolsSearchPaths.push_back(PATH_NOT_EXISTS);
    EXPECT_EQ(runtime_->SetSymbolsPaths(symbolsSearchPaths), true);

    symbolsSearchPaths.clear();
    symbolsSearchPaths.push_back(PATH_DATA_TEMP);
    symbolsSearchPaths.push_back(PATH_NOT_EXISTS);
    symbolsSearchPaths.push_back(PATH_DATA_TEMP);
    symbolsSearchPaths.push_back(PATH_NOT_EXISTS);
    EXPECT_EQ(runtime_->SetSymbolsPaths(symbolsSearchPaths), true);

    symbolsSearchPaths.clear();
    symbolsSearchPaths.push_back(PATH_DATA_TEMP);
    symbolsSearchPaths.push_back(PATH_NOT_EXISTS);
    symbolsSearchPaths.push_back(PATH_DATA_TEMP);
    symbolsSearchPaths.push_back(PATH_NOT_EXISTS);
    symbolsSearchPaths.push_back(PATH_DATA_TEMP);
    symbolsSearchPaths.push_back(PATH_NOT_EXISTS);
    EXPECT_EQ(runtime_->SetSymbolsPaths(symbolsSearchPaths), true);
}

/**
 * @tc.name: GetSymbolsFiles
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualRuntimeTest, GetSymbolsFiles, TestSize.Level1)
{
    EXPECT_EQ(runtime_->GetSymbolsFiles().size(), 0u);
    runtime_->UpdateKernelSymbols();
    if (access("/sys/kernel/notes", F_OK) == 0) {
        EXPECT_EQ(runtime_->GetSymbolsFiles().size(), 1u);
    } else {
        printf("cannot access /sys/kernel/notes\n");
    }
}

/**
 * @tc.name: SetCallStackExpend
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualRuntimeTest, SetCallStackExpend, TestSize.Level1)
{
    runtime_->SetCallStackExpend(true);
    EXPECT_EQ(runtime_->callstackMergeLevel_, true);
    runtime_->SetCallStackExpend(false);
    EXPECT_EQ(runtime_->callstackMergeLevel_, false);
}

/**
 * @tc.name: SetDisableUnwind
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualRuntimeTest, SetDisableUnwind, TestSize.Level1)
{
    runtime_->SetDisableUnwind(true);
    EXPECT_EQ(runtime_->disableUnwind_, true);
    runtime_->SetDisableUnwind(false);
    EXPECT_EQ(runtime_->disableUnwind_, false);
}

namespace {
constexpr const pid_t testTid = 1;
constexpr const uint64_t testUserVaddr = 0x1000;
constexpr const uint64_t testKernelVaddr = testUserVaddr / 4;
constexpr const uint64_t testKernelLen = testUserVaddr / 2;
constexpr const uint64_t testUserMapBegin = 0x2000;
constexpr const uint64_t testUserMapLen = 0x4000;
} // namespace

void VirtualRuntimeTest::PrepareKernelSymbol()
{
    std::string kernelSymbol = "kernel_symbol";
    auto kernel = SymbolsFile::CreateSymbolsFile(SYMBOL_KERNEL_FILE);
    kernel->filePath_ = kernelSymbol;
    kernel->symbols_.emplace_back(testKernelVaddr, 1u, "first_kernel_func", kernel->filePath_);
    kernel->symbols_.emplace_back(testKernelVaddr + 1u, 1u, "second_kernel_func",
                                  kernel->filePath_);
    runtime_->symbolsFiles_.emplace_back(std::move(kernel));

    auto &kernelMap = runtime_->kernelSpaceMemMaps_.emplace_back();
    kernelMap.name_ = kernelSymbol;
    kernelMap.begin_ = 0;
    kernelMap.end_ = 0 + testKernelLen;
    kernelMap.pageoffset_ = 0;
}

void VirtualRuntimeTest::PrepareUserSymbol()
{
    std::string userSymbol = "user_symbol";
    auto user = SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE);
    user->filePath_ = userSymbol;
    user->symbols_.emplace_back(testUserVaddr, 1u, "first_user_func", user->filePath_);
    user->symbols_.emplace_back(testUserVaddr + 1u, 1u, "second_user_func", user->filePath_);
    user->textExecVaddrFileOffset_ = testUserVaddr;
    user->textExecVaddr_ = testUserVaddr;
    user->debugInfoLoadResult_ = true;
    runtime_->symbolsFiles_.emplace_back(std::move(user));

    VirtualThread &thread = runtime_->GetThread(testTid, testTid);
    thread.CreateMapItem(userSymbol, testUserMapBegin, testUserMapLen, 0);
}

/**
 * @tc.name: GetSymbol
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualRuntimeTest, GetSymbol, TestSize.Level1)
{
    Symbol symbol;
    PrepareKernelSymbol();
    PrepareUserSymbol();

    ScopeDebugLevel tempLogLevel(LEVEL_MUCH);

    symbol = runtime_->GetSymbol(0u, testTid, testTid);
    EXPECT_EQ(symbol.isValid(), false);

    symbol = runtime_->GetSymbol(testKernelVaddr, testTid, testTid);
    // in kernel
    EXPECT_EQ(symbol.isValid(), true);
    EXPECT_EQ(symbol.funcVaddr_, testKernelVaddr);
    EXPECT_STREQ(symbol.name_.data(), "first_kernel_func");

    symbol = runtime_->GetSymbol(testUserVaddr + testUserMapBegin, testTid, testTid);
    // in user
    EXPECT_EQ(symbol.isValid(), true);
    EXPECT_EQ(symbol.funcVaddr_, testUserVaddr);
    EXPECT_STREQ(symbol.name_.data(), "first_user_func");
}

/**
 * @tc.name: GetThread
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualRuntimeTest, GetThread, TestSize.Level1)
{
    runtime_->GetThread(1, 2);
    runtime_->GetThread(3, 4);
    runtime_->GetThread(5, 6);
    // runtime have 0 thread, so here need +1u
    EXPECT_EQ(runtime_->GetThreads().size(), 7u);
    if (HasFailure()) {
        for (auto &pair : runtime_->GetThreads()) {
            printf("pid %d tid %d\n", pair.second.pid_, pair.second.tid_);
        }
    }
}

/**
 * @tc.name: UpdateFromPerfData
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualRuntimeTest, UpdateFromPerfData, TestSize.Level1)
{
    std::vector<SymbolFileStruct> symbolFileStructs;
    SymbolFileStruct &symbolFileStruct = symbolFileStructs.emplace_back();
    symbolFileStruct.filePath_ = "a";
    symbolFileStruct.textExecVaddr_ = testUserVaddr;
    symbolFileStruct.textExecVaddrFileOffset_ = testUserVaddr;
    symbolFileStruct.buildId_ = "b";
    symbolFileStruct.symbolStructs_.emplace_back(testUserVaddr, 1u, "first_user_func");
    symbolFileStruct.symbolStructs_.emplace_back(testUserVaddr + 1u, 1u, "second_user_func");

    runtime_->UpdateFromPerfData(symbolFileStructs);
    ASSERT_EQ(runtime_->GetSymbolsFiles().size(), 1u);
    ASSERT_STREQ(runtime_->GetSymbolsFiles().front()->filePath_.c_str(), "a");
    ASSERT_STREQ(runtime_->GetSymbolsFiles().front()->GetBuildId().c_str(), "b");
    ASSERT_EQ(runtime_->GetSymbolsFiles().front()->GetSymbols().size(), 2u);
}

/**
 * @tc.name: UnwindFromRecord
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(VirtualRuntimeTest, UnwindFromRecord, TestSize.Level1)
{
    // symbol
    auto &symbolsFile = runtime_->symbolsFiles_.emplace_back(
        SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE, TEST_DWARF_ELF));
    ASSERT_EQ(symbolsFile->setSymbolsFilePath(PATH_RESOURCE_TEST_DWARF_DATA), true);
    ASSERT_EQ(symbolsFile->LoadSymbols(TEST_DWARF_ELF), true);
    symbolsFile->filePath_ = TEST_DWARF_ELF;

    // thread
    VirtualThread &thread = runtime_->GetThread(TEST_DWARF_RECORD_PID, TEST_DWARF_RECORD_TID);
    MakeMaps(thread);

    // record
    std::vector<uint8_t> data;
    LoadFromFile(PATH_RESOURCE_TEST_DWARF_DATA + TEST_DWARF_RECORD, data);
    ASSERT_NE(data.size(), 0u);
    perf_event_attr attr;
    if (memset_s(&attr, sizeof(perf_event_attr), 0, sizeof(perf_event_attr)) != EOK) {
        printf("error: memset_s failed.");
        return;
    }
    attr.sample_type = TEST_RECORD_SAMPLE_TYPE;
    attr.sample_regs_user = TEST_DWARF_RECORD_REGS_USER;
    PerfRecordSample sample(data.data(), attr);
    sample.DumpLog("UnwindFromRecord");
    ASSERT_EQ(sample.data_.stack_size, TEST_DWARF_RECORD_STACK_SIZE);

    // unwind
    runtime_->UnwindFromRecord(sample);
    ASSERT_LE(TEST_RECORD_CALLSTACK_IP_FUNC.size(), sample.callFrames_.size());
    for (size_t i = 0; i < TEST_RECORD_CALLSTACK_IP_FUNC.size(); i++) {
        EXPECT_EQ(TEST_RECORD_CALLSTACK_IP_FUNC[i].first, sample.callFrames_[i].vaddrInFile_);
        EXPECT_STREQ(TEST_RECORD_CALLSTACK_IP_FUNC[i].second.data(),
                     sample.callFrames_[i].symbolName_.data());
    }
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
