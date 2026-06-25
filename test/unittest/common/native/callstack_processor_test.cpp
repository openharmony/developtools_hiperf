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

#include "callstack_processor_test.h"

#include <gtest/gtest.h>

#include "symbols_file_test.h"

using namespace testing::ext;
namespace OHOS {
namespace Developtools {
namespace HiPerf {

class CallStackProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::vector<std::unique_ptr<SymbolsFile>> symbolsFiles_;
    std::vector<DfxMap> kernelMaps_;
    RuntimeContext runtimeContext_;
    std::unique_ptr<ThreadManager> threadManager_;
    std::unique_ptr<SymbolManager> symbolManager_;
    std::unique_ptr<CallStackProcessor> callStackProcessor_;
};

void CallStackProcessorTest::SetUpTestCase() {}
void CallStackProcessorTest::TearDownTestCase() {}

void CallStackProcessorTest::SetUp()
{
    runtimeContext_ = RuntimeContext{};
    threadManager_ = std::make_unique<ThreadManager>(symbolsFiles_, runtimeContext_);
    symbolManager_ = std::make_unique<SymbolManager>(symbolsFiles_, kernelMaps_, runtimeContext_);
    callStackProcessor_ = std::make_unique<CallStackProcessor>(
        *symbolManager_, *threadManager_, runtimeContext_);
}

void CallStackProcessorTest::TearDown()
{
    callStackProcessor_.reset();
    symbolManager_.reset();
    threadManager_.reset();
}

HWTEST_F(CallStackProcessorTest, SymbolicRecord, TestSize.Level1)
{
    callStackProcessor_->Clear();
    PerfRecordSample sample;
    sample.data_.pid = 99999;
    sample.data_.tid = 99999;
    sample.data_.nr = 2;
    u64 testIps[2] = {0x1000, 0x2000};
    sample.data_.ips = reinterpret_cast<u64*>(testIps);

    callStackProcessor_->SymbolicRecord(sample);

    EXPECT_EQ(sample.callFrames_.size(), 2);
    EXPECT_EQ(sample.callFrames_[0].pc, 0x1000);
    EXPECT_EQ(sample.callFrames_[1].pc, 0x2000);
}

HWTEST_F(CallStackProcessorTest, DedupFromRecord, TestSize.Level1)
{
    callStackProcessor_->Clear();
    PerfRecordSample sample;
    sample.data_.pid = 99999;
    sample.data_.nr = 2;
    u64 testIps[2] = {0x1000, 0x2000};
    sample.data_.ips = reinterpret_cast<u64*>(testIps);
    sample.header_.size = sizeof(perf_event_header) + 2 * sizeof(u64);

    callStackProcessor_->SetRecordMode([](PerfEventRecord&) { return true; });
    callStackProcessor_->SetDedupStack(true);
    callStackProcessor_->SetCollectSymbolCallBack([](PerfRecordSample*) {});

    callStackProcessor_->DedupFromRecord(&sample);

    EXPECT_EQ(sample.data_.nr, 0);
    EXPECT_NE(sample.stackId_.value, 0);
    EXPECT_TRUE(sample.removeStack_);
    EXPECT_EQ(sample.header_.size, sizeof(perf_event_header) + sizeof(StackId));
}

HWTEST_F(CallStackProcessorTest, NeedDropKernelCallChain, TestSize.Level1)
{
    PerfRecordSample sample;
    sample.data_.nr = 4;
    u64 testIps[4] = {PERF_CONTEXT_KERNEL, PERF_CONTEXT_KERNEL,
                      PERF_CONTEXT_USER, 0x4000};
    sample.data_.ips = reinterpret_cast<u64*>(testIps);
    sample.header_.misc |= PERF_RECORD_MISC_KERNEL;
    sample.header_.size = sizeof(perf_event_header) + 4 * sizeof(uint64_t);
    sample.data_.server_nr = 0;
    sample.data_.ip = 0xFFFF000000000000ULL;

    callStackProcessor_->SetRecordMode([](PerfEventRecord&) { return true; });
    callStackProcessor_->SetNeedKernelCallChain(false);

    callStackProcessor_->NeedDropKernelCallChain(sample);

    EXPECT_EQ(sample.skipKernel_, 2);
    EXPECT_EQ(sample.data_.nr, 2);
    EXPECT_EQ(sample.header_.size, sizeof(perf_event_header) + 2 * sizeof(uint64_t));
}

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS