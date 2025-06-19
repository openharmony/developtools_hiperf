/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hiperf_local_test.h"

#include "test_utilities.h"

using namespace testing::ext;
using namespace std;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class HiperfLocalTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HiperfLocalTest::SetUpTestCase() {}

void HiperfLocalTest::TearDownTestCase()
{
}

void HiperfLocalTest::SetUp() {}

void HiperfLocalTest::TearDown()
{
}

HWTEST_F(HiperfLocalTest, RecordWithInvalidTid, TestSize.Level2)
{
    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().StartProcessStackSampling({}, 100, 5000, false), -1);
    std::string sampleStack;

    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().CollectSampleStackByTid(getpid(), sampleStack), -1);
    ASSERT_TRUE(sampleStack.size() == 0);
    std::string heaviestStack;

    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().CollectHeaviestStackByTid(getpid(), heaviestStack), -1);
    ASSERT_TRUE(heaviestStack.size() == 0);

    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().FinishProcessStackSampling(), 0);
}

HWTEST_F(HiperfLocalTest, RecordWithInvalidFreq1, TestSize.Level2)
{
    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().StartProcessStackSampling({ getpid() }, 2000, 5000, false), -1);
    std::string sampleStack;

    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().CollectSampleStackByTid(getpid(), sampleStack), -1);
    ASSERT_TRUE(sampleStack.size() == 0);
    std::string heaviestStack;

    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().CollectHeaviestStackByTid(getpid(), heaviestStack), -1);
    ASSERT_TRUE(heaviestStack.size() == 0);

    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().FinishProcessStackSampling(), 0);
}

HWTEST_F(HiperfLocalTest, RecordWithInvalidFreq2, TestSize.Level2)
{
    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().StartProcessStackSampling({ getpid() }, -1, 5000, false), -1);
    std::string sampleStack;

    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().CollectSampleStackByTid(getpid(), sampleStack), -1);
    ASSERT_TRUE(sampleStack.size() == 0);
    std::string heaviestStack;

    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().CollectHeaviestStackByTid(getpid(), heaviestStack), -1);
    ASSERT_TRUE(heaviestStack.size() == 0);

    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().FinishProcessStackSampling(), 0);
}

HWTEST_F(HiperfLocalTest, RecordWithInvalidTime1, TestSize.Level2)
{
    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().StartProcessStackSampling({ getpid() }, 100, 20000, false), -1);
    std::string sampleStack;

    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().CollectSampleStackByTid(getpid(), sampleStack), -1);
    ASSERT_TRUE(sampleStack.size() == 0);
    std::string heaviestStack;

    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().CollectHeaviestStackByTid(getpid(), heaviestStack), -1);
    ASSERT_TRUE(heaviestStack.size() == 0);

    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().FinishProcessStackSampling(), 0);
}

HWTEST_F(HiperfLocalTest, RecordWithInvalidTime2, TestSize.Level2)
{
    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().StartProcessStackSampling({ getpid() }, 100, -1, false), -1);
    std::string sampleStack;

    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().CollectSampleStackByTid(getpid(), sampleStack), -1);
    ASSERT_TRUE(sampleStack.size() == 0);
    std::string heaviestStack;

    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().CollectHeaviestStackByTid(getpid(), heaviestStack), -1);
    ASSERT_TRUE(heaviestStack.size() == 0);

    EXPECT_EQ(HiPerfLocal::Lperf::GetInstance().FinishProcessStackSampling(), 0);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS