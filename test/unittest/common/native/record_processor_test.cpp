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

#include "record_processor_test.h"

#include <gtest/gtest.h>

#include "symbols_file_test.h"

using namespace testing::ext;
namespace OHOS {
namespace Developtools {
namespace HiPerf {

class RecordProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::vector<std::unique_ptr<SymbolsFile>> symbolsFiles_;
    std::vector<DfxMap> kernelMaps_;
    RuntimeContext runtimeContext_;
    std::unique_ptr<ThreadManager> threadManager_;
    std::unique_ptr<MemoryMapManager> mapManager_;
    std::unique_ptr<SymbolManager> symbolManager_;
    std::unique_ptr<CallStackProcessor> callStackProcessor_;
    std::unique_ptr<SmoProcessor> smoProcessor_;
    std::unique_ptr<RecordProcessor> recordProcessor_;
    RecordProcessor::SymbolsFileRegisterFunc registerFunc_;
};

void RecordProcessorTest::SetUpTestCase() {}
void RecordProcessorTest::TearDownTestCase() {}

void RecordProcessorTest::SetUp()
{
    runtimeContext_ = RuntimeContext{};
    registerFunc_ = [](std::unique_ptr<SymbolsFile> file) -> int32_t { return 0; };

    threadManager_ = std::make_unique<ThreadManager>(symbolsFiles_, runtimeContext_);
    mapManager_ = std::make_unique<MemoryMapManager>(*threadManager_, runtimeContext_);
    symbolManager_ = std::make_unique<SymbolManager>(symbolsFiles_, kernelMaps_, runtimeContext_);
    callStackProcessor_ = std::make_unique<CallStackProcessor>(
        *symbolManager_, *threadManager_, runtimeContext_);
    smoProcessor_ = std::make_unique<SmoProcessor>(
        symbolsFiles_, *symbolManager_, registerFunc_);
    recordProcessor_ = std::make_unique<RecordProcessor>(
        *threadManager_, *mapManager_, *callStackProcessor_, *smoProcessor_,
        symbolsFiles_, runtimeContext_, registerFunc_);
}

void RecordProcessorTest::TearDown()
{
    recordProcessor_.reset();
    smoProcessor_.reset();
    callStackProcessor_.reset();
    symbolManager_.reset();
    mapManager_.reset();
    threadManager_.reset();
}

HWTEST_F(RecordProcessorTest, UpdateFromRecordComm, TestSize.Level1)
{
    PerfRecordComm recordComm(false, 1, 2, "test_comm");
    PerfEventRecord& record = static_cast<PerfEventRecord&>(recordComm);

    auto callBack = [](PerfEventRecord& record) { return true; };
    recordProcessor_->SetRecordMode(callBack);

    recordProcessor_->UpdateFromRecord(record);

    EXPECT_NE(threadManager_->GetThreads().find(1), threadManager_->GetThreads().end());
    EXPECT_NE(threadManager_->GetThreads().find(2), threadManager_->GetThreads().end());
}

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS