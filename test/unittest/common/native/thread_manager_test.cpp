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

#include "thread_manager_test.h"

#include <gtest/gtest.h>

#include "symbols_file_test.h"

using namespace testing::ext;
namespace OHOS {
namespace Developtools {
namespace HiPerf {

class ThreadManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::vector<std::unique_ptr<SymbolsFile>> symbolsFiles_;
    RuntimeContext runtimeContext_;
    std::unique_ptr<ThreadManager> threadManager_;
};

void ThreadManagerTest::SetUpTestCase() {}
void ThreadManagerTest::TearDownTestCase() {}

void ThreadManagerTest::SetUp()
{
    runtimeContext_ = RuntimeContext{};
    threadManager_ = std::make_unique<ThreadManager>(symbolsFiles_, runtimeContext_);
}

void ThreadManagerTest::TearDown()
{
    threadManager_.reset();
}

HWTEST_F(ThreadManagerTest, GetThread, TestSize.Level1)
{
    VirtualThread& t1 = threadManager_->GetThread(1, 2);
    EXPECT_EQ(t1.pid_, 1);
    EXPECT_EQ(t1.tid_, 2);

    VirtualThread& t2 = threadManager_->GetThread(3, 4);
    EXPECT_EQ(t2.pid_, 3);
    EXPECT_EQ(t2.tid_, 4);

    EXPECT_EQ(threadManager_->GetThreads().size(), 4u);
}

HWTEST_F(ThreadManagerTest, Clear, TestSize.Level1)
{
    threadManager_->GetThread(1, 2);
    threadManager_->GetThread(3, 4);
    EXPECT_NE(threadManager_->GetThreads().size(), 0u);

    threadManager_->Clear();
    EXPECT_EQ(threadManager_->GetThreads().size(), 0u);
}

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS