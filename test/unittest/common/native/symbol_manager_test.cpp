/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "symbol_manager_test.h"

#include <gtest/gtest.h>

#include "symbols_file_test.h"

using namespace testing::ext;
namespace OHOS {
namespace Developtools {
namespace HiPerf {

namespace {
constexpr const pid_t testTid = 99999;
constexpr const uint64_t testUserVaddr = 0x1000;
constexpr const uint64_t testKernelVaddr = testUserVaddr / 4;
constexpr const uint64_t testKernelLen = testUserVaddr / 2;
constexpr const uint64_t testUserMapBegin = 0x2000;
constexpr const uint64_t testUserMapLen = 0x4000;
}

class SymbolManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::vector<std::unique_ptr<SymbolsFile>> symbolsFiles_;
    std::vector<DfxMap> kernelMaps_;
    RuntimeContext runtimeContext_;
    std::unique_ptr<SymbolManager> symbolManager_;

    void PrepareKernelSymbol();
    void PrepareUserSymbol();
};

void SymbolManagerTest::SetUpTestCase() {}
void SymbolManagerTest::TearDownTestCase() {}

void SymbolManagerTest::SetUp()
{
    runtimeContext_ = RuntimeContext{};
    symbolManager_ = std::make_unique<SymbolManager>(symbolsFiles_, kernelMaps_, runtimeContext_);
}

void SymbolManagerTest::TearDown()
{
    symbolsFiles_.clear();
    kernelMaps_.clear();
    symbolManager_.reset();
}

void SymbolManagerTest::PrepareKernelSymbol()
{
    auto kernel = SymbolsFile::CreateSymbolsFile(SYMBOL_KERNEL_FILE);
    kernel->filePath_ = "kernel_symbol";
    kernel->symbols_.emplace_back(testKernelVaddr, 1u, "first_kernel_func", kernel->filePath_);
    kernel->symbols_.emplace_back(testKernelVaddr + 1u, 1u, "second_kernel_func", kernel->filePath_);
    kernel->SetSymbolsLoaded(true);
    symbolsFiles_.emplace_back(std::move(kernel));

    auto& kernelMap = kernelMaps_.emplace_back();
    kernelMap.name = "kernel_symbol";
    kernelMap.begin = 0;
    kernelMap.end = testKernelLen;
    kernelMap.offset = 0;
}

void SymbolManagerTest::PrepareUserSymbol()
{
    auto user = SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE);
    user->filePath_ = "user_symbol";
    user->symbols_.emplace_back(testUserVaddr, 1u, "first_user_func", user->filePath_);
    user->symbols_.emplace_back(testUserVaddr + 1u, 1u, "second_user_func", user->filePath_);
    user->textExecVaddrFileOffset_ = testUserVaddr;
    user->textExecVaddr_ = testUserVaddr;
    user->SetSymbolsLoaded(true);
    user->debugInfoLoadResult_ = true;
    symbolsFiles_.emplace_back(std::move(user));
}

HWTEST_F(SymbolManagerTest, ResolveSymbolInvalidIP, TestSize.Level1)
{
    std::vector<std::unique_ptr<SymbolsFile>> emptyFiles;
    std::vector<DfxMap> emptyMaps;
    RuntimeContext ctx;
    SymbolManager mgr(emptyFiles, emptyMaps, ctx);

    std::vector<std::unique_ptr<SymbolsFile>> threadFiles;
    VirtualThread thread(testTid, threadFiles);
    DfxSymbol sym = mgr.ResolveSymbol(0u, thread);
    EXPECT_EQ(sym.IsValid(), false);
}

HWTEST_F(SymbolManagerTest, ResolveSymbolKernel, TestSize.Level0)
{
    PrepareKernelSymbol();

    SymbolManager mgr(symbolsFiles_, kernelMaps_, runtimeContext_);
    std::vector<std::unique_ptr<SymbolsFile>> threadFiles;
    VirtualThread thread(testTid, threadFiles);

    DfxSymbol sym = mgr.ResolveSymbol(testKernelVaddr, thread, PERF_CONTEXT_KERNEL);
    EXPECT_EQ(sym.IsValid(), true);
    EXPECT_EQ(sym.funcVaddr_, testKernelVaddr);
    EXPECT_STREQ(sym.name_.data(), "first_kernel_func");
}

HWTEST_F(SymbolManagerTest, ResolveSymbolUser, TestSize.Level0)
{
    PrepareUserSymbol();

    SymbolManager mgr(symbolsFiles_, kernelMaps_, runtimeContext_);
    VirtualThread thread(testTid, symbolsFiles_);
    thread.CreateMapItem("user_symbol", testUserMapBegin, testUserMapLen, 0);

    DfxSymbol sym = mgr.ResolveSymbol(testUserVaddr + testUserMapBegin, thread, PERF_CONTEXT_USER);
    EXPECT_EQ(sym.IsValid(), true);
}

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS