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

#include "memory_map_manager_test.h"

#include <gtest/gtest.h>

#include "symbols_file_test.h"

using namespace testing::ext;
namespace OHOS {
namespace Developtools {
namespace HiPerf {

class MemoryMapManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::vector<std::unique_ptr<SymbolsFile>> symbolsFiles_;
    RuntimeContext runtimeContext_;
    std::unique_ptr<ThreadManager> threadManager_;
    std::unique_ptr<MemoryMapManager> mapManager_;
};

void MemoryMapManagerTest::SetUpTestCase() {}
void MemoryMapManagerTest::TearDownTestCase() {}

void MemoryMapManagerTest::SetUp()
{
    runtimeContext_ = RuntimeContext{};
    threadManager_ = std::make_unique<ThreadManager>(symbolsFiles_, runtimeContext_);
    mapManager_ = std::make_unique<MemoryMapManager>(*threadManager_, runtimeContext_);
}

void MemoryMapManagerTest::TearDown()
{
    mapManager_.reset();
    threadManager_.reset();
}

HWTEST_F(MemoryMapManagerTest, UpdateThreadMaps, TestSize.Level1)
{
    auto map = mapManager_->UpdateThreadMaps(1, 1, "test.so", 0x1000, 0x2000, 0x0);
    EXPECT_NE(map, nullptr);
    EXPECT_EQ(map->name, "test.so");
}

HWTEST_F(MemoryMapManagerTest, UpdateKernelMap, TestSize.Level1)
{
    mapManager_->UpdateKernelMap(0x0, 0x1000, 0x0, "kernel");
    EXPECT_EQ(mapManager_->GetKernelMaps().size(), 1u);
    EXPECT_EQ(mapManager_->GetKernelMaps()[0].name, "kernel");
}

HWTEST_F(MemoryMapManagerTest, UpdateKernelSpaceMaps, TestSize.Level1)
{
    mapManager_->UpdateKernelSpaceMaps();
    if (access("/proc/kallsyms", F_OK) == 0) {
        EXPECT_NE(mapManager_->GetKernelMaps().size(), 0u);
    }
}

HWTEST_F(MemoryMapManagerTest, Clear, TestSize.Level1)
{
    mapManager_->UpdateKernelMap(0x0, 0x1000, 0x0, "kernel");
    EXPECT_NE(mapManager_->GetKernelMaps().size(), 0u);

    mapManager_->Clear();
    EXPECT_EQ(mapManager_->GetKernelMaps().size(), 0u);
}

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS