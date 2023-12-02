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

#include "unique_stack_table_test.h"

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <sched.h>
#include <sstream>
#include <thread>

#include "command.h"
#include "debug_logger.h"
#include "utilities.h"

using namespace std::literals::chrono_literals;
using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class UniqueStackTableTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

};

void UniqueStackTableTest::SetUpTestCase()
{
}

void UniqueStackTableTest::TearDownTestCase() {}

void UniqueStackTableTest::SetUp()
{
}

void UniqueStackTableTest::TearDown()
{
}

/**
 * @tc.name: Test_Normal
 * @tc.desc: Test stack compress normal function
 * @tc.type: FUNC
 */
HWTEST_F(UniqueStackTableTest, Test_Normal, TestSize.Level1)
{
    u64 baseips[] = {0x6bcc,
                    0x35A8,
                    0x880,
                    0x04};

    u64 partips[] = {0x01,
                    0x02,
                    0x03};

    u64 partips1[] = {0x02,
                    0x03,
                    0x04};

    std::shared_ptr<UniqueStackTable> table = std::make_shared<UniqueStackTable>(1);

    StackId stackId = {0};
    StackId stackIdpart = {0};
    StackId stackIdpart1 = {0};

    EXPECT_NE(table->PutIpsInTable(&stackId, baseips, sizeof(baseips)/sizeof(uint64_t)), 0);
    EXPECT_NE(table->PutIpsInTable(&stackIdpart, partips, sizeof(partips)/sizeof(uint64_t)), 0);
    EXPECT_NE(table->PutIpsInTable(&stackIdpart1, partips1, sizeof(partips1)/sizeof(uint64_t)), 0);
    EXPECT_NE(stackId.value, 0);
    EXPECT_NE(stackIdpart.value, 0);
    EXPECT_NE(stackIdpart1.value, 0);

    EXPECT_EQ(0, 0);

    std::vector<u64> checkbaseips;
    std::vector<u64> checkpartips;
    std::vector<u64> checkpartips1;
    table->GetIpsByStackId(stackId, checkbaseips);
    table->GetIpsByStackId(stackIdpart, checkpartips);
    table->GetIpsByStackId(stackIdpart1, checkpartips1);

    EXPECT_EQ(memcmp(baseips, checkbaseips.data(), checkbaseips.size()*sizeof(u64)), 0);
}

HWTEST_F(UniqueStackTableTest, Test_Resize, TestSize.Level1)
{
    uint32_t maxsize = 64 * 1024 * 1024;
    std::shared_ptr<UniqueStackTable> table = std::make_shared<UniqueStackTable>(1, maxsize);
    EXPECT_EQ(table->Resize(), false);
}

HWTEST_F(UniqueStackTableTest, Test_Oversize, TestSize.Level1)
{
    uint32_t oversize = 128 * 1024 * 1024;
    std::shared_ptr<UniqueStackTable> table = std::make_shared<UniqueStackTable>(1, oversize);

    u64 baseips[] = {0x6bcc,
                    0x35A8,
                    0x880,
                    0x04};
    StackId stackId = {0};

    EXPECT_EQ(table->PutIpsInTable(&stackId, baseips, sizeof(baseips)/sizeof(uint64_t)), 0);
}

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
