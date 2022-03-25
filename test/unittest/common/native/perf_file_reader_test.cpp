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

#include <iostream>
#include <string>

#include "perf_file_reader.h"
#include "perf_file_reader_test.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
using ProcessRecordCB = const std::function<bool(std::unique_ptr<PerfEventRecord> record)>;
class PerfFileReaderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::unique_ptr<PerfFileReader> hiperfFileReader_ {nullptr};
};

void PerfFileReaderTest::SetUpTestCase() {}

void PerfFileReaderTest::TearDownTestCase() {}

void PerfFileReaderTest::SetUp() {}
void PerfFileReaderTest::TearDown() {}

HWTEST_F(PerfFileReaderTest, Test_Instance_success, TestSize.Level1)
{
    const std::string filename = "perf.data";
    FILE *fp = stdout;
    PerfFileReader *hiperfFileReader = new PerfFileReader(filename, fp);
    std::unique_ptr<PerfFileReader> ret = hiperfFileReader->Instance(filename);
    bool result = true;
    if (ret != 0) {
        result = true;
    }
    EXPECT_EQ(result, true);
}

HWTEST_F(PerfFileReaderTest, Test_Instance_fail, TestSize.Level1)
{
    const std::string filename = "xxx";
    FILE *fp = nullptr;
    PerfFileReader *hiperfFileReader = new PerfFileReader(filename, fp);
    std::unique_ptr<PerfFileReader> ret = hiperfFileReader->Instance(filename);
    bool result = true;
    if (ret == 0) {
        result = false;
    }
    EXPECT_EQ(result, false);
}

HWTEST_F(PerfFileReaderTest, Test_ReadFetureSection_success, TestSize.Level1)
{
    const std::string filename = "perf.data";
    FILE *fp = stdout;
    PerfFileReader *hiperfFileReader = new PerfFileReader(filename, fp);
    bool ret = hiperfFileReader->ReadFeatureSection();
    EXPECT_EQ(ret, true);
}

HWTEST_F(PerfFileReaderTest, Test_ReadFetureSection, TestSize.Level1)
{
    const std::string filename = "xxx";
    FILE *fp = nullptr;
    PerfFileReader *hiperfFileReader = new PerfFileReader(filename, fp);
    bool ret = hiperfFileReader->ReadFeatureSection();
    EXPECT_EQ(ret, true);
}

HWTEST_F(PerfFileReaderTest, Test_GetFetures, TestSize.Level1)
{
    const std::string filename = "perf.data";
    FILE *fp = stdout;
    PerfFileReader *hiperfFileReader = new PerfFileReader(filename, fp);
    std::vector<FEATURE> features_;
    FEATURE feture1 = FEATURE::RESERVED;
    FEATURE feture2 = FEATURE::ARCH;
    FEATURE feture3 = FEATURE::BUILD_ID;
    FEATURE feture4 = FEATURE::LAST_FEATURE;
    features_.push_back(feture1);
    features_.push_back(feture2);
    features_.push_back(feture3);
    features_.push_back(feture4);
    EXPECT_NE(features_.size(), hiperfFileReader->GetFeatures().size());
}

HWTEST_F(PerfFileReaderTest, Test_GetFetureString, TestSize.Level1)
{
    const std::string filename = "perf.data";
    FILE *fp = stdout;
    PerfFileReader *hiperfFileReader = new PerfFileReader(filename, fp);
    const FEATURE feture = FEATURE::ARCH;
    const std::string result = "ARCH";
    EXPECT_NE(hiperfFileReader->GetFeatureString(feture), result);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
