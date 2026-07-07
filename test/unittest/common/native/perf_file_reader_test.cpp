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

#include <cstdio>
#include <iostream>
#include <string>

#include "perf_file_reader.h"
#include "perf_file_reader_test.h"

using namespace testing::ext;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
using ProcessRecordCB = const std::function<bool(PerfEventRecord& record)>;
class PerfFileReaderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PerfFileReaderTest::SetUpTestCase() {}

void PerfFileReaderTest::TearDownTestCase() {}

void PerfFileReaderTest::SetUp() {}
void PerfFileReaderTest::TearDown() {}

HWTEST_F(PerfFileReaderTest, Test_Instance_success, TestSize.Level1)
{
    const std::string filename = "perf.data";
    FILE *fp = stdout;
    PerfFileReader hiperfFileReader(filename, fp);
    std::unique_ptr<PerfFileReader> ret = hiperfFileReader.Instance(filename);
    EXPECT_EQ(ret == nullptr, true);
}

HWTEST_F(PerfFileReaderTest, Test_Instance_fail, TestSize.Level3)
{
    const std::string filename = "xxx";
    FILE *fp = nullptr;
    PerfFileReader hiperfFileReader(filename, fp);
    std::unique_ptr<PerfFileReader> ret = hiperfFileReader.Instance(filename);
    EXPECT_EQ(ret == nullptr, true);
}

HWTEST_F(PerfFileReaderTest, Test_ReadFetureSection_success, TestSize.Level0)
{
    const std::string filename = "perf.data";
    FILE *fp = stdout;
    PerfFileReader hiperfFileReader(filename, fp);
    bool ret = hiperfFileReader.ReadFeatureSection();
    EXPECT_EQ(ret, true);
}

HWTEST_F(PerfFileReaderTest, Test_ReadFetureSection, TestSize.Level1)
{
    const std::string filename = "xxx";
    FILE *fp = nullptr;
    PerfFileReader hiperfFileReader(filename, fp);
    bool ret = hiperfFileReader.ReadFeatureSection();
    EXPECT_EQ(ret, true);
}

HWTEST_F(PerfFileReaderTest, Test_GetFetures, TestSize.Level2)
{
    const std::string filename = "perf.data";
    FILE *fp = stdout;
    PerfFileReader hiperfFileReader(filename, fp);
    std::vector<FEATURE> features_;
    FEATURE feture1 = FEATURE::RESERVED;
    FEATURE feture2 = FEATURE::ARCH;
    FEATURE feture3 = FEATURE::BUILD_ID;
    FEATURE feture4 = FEATURE::LAST_FEATURE;
    features_.push_back(feture1);
    features_.push_back(feture2);
    features_.push_back(feture3);
    features_.push_back(feture4);
    EXPECT_NE(features_.size(), hiperfFileReader.GetFeatures().size());
}

HWTEST_F(PerfFileReaderTest, Test_GetFetureString, TestSize.Level1)
{
    const std::string filename = "perf.data";
    FILE *fp = stdout;
    PerfFileReader hiperfFileReader(filename, fp);
    const FEATURE feture = FEATURE::ARCH;
    const std::string result = "ARCH";
    EXPECT_NE(hiperfFileReader.GetFeatureString(feture), result);
}

HWTEST_F(PerfFileReaderTest, ReadIdsForAttr1, TestSize.Level2)
{
    perf_file_attr attr;
    attr.ids.size = 2000000000;
    std::vector<uint64_t> v;
    PerfFileReader reader("", nullptr);
    EXPECT_FALSE(reader.ReadIdsForAttr(attr, &v));
}

HWTEST_F(PerfFileReaderTest, ReadIdsForAttr2, TestSize.Level0)
{
    perf_file_attr attr;
    attr.ids.size = 1;
    std::string fileName = "/proc/" + std::to_string(getpid()) + "/cmdline";
    FILE* fp = fopen(fileName.c_str(), "r");
    EXPECT_NE(fp, nullptr);
    std::vector<uint64_t> v;
    PerfFileReader reader("", fp);
    EXPECT_TRUE(reader.ReadIdsForAttr(attr, &v));
    EXPECT_NE(v.size(), 0);
}

HWTEST_F(PerfFileReaderTest, ReadIdsForAttr3, TestSize.Level1)
{
    perf_file_attr attr;
    attr.ids.size = 4;
    attr.ids.offset = 0;
    std::string fileName = "/proc/" + std::to_string(getpid()) + "/cmdline";
    FILE* fp = fopen(fileName.c_str(), "r");
    EXPECT_NE(fp, nullptr);
    std::vector<uint64_t> v;
    PerfFileReader reader("", fp);
    EXPECT_TRUE(reader.ReadIdsForAttr(attr, &v));
    EXPECT_TRUE(v.size() * sizeof(uint64_t) >= attr.ids.size);
}

HWTEST_F(PerfFileReaderTest, Test_OverAttrSize, TestSize.Level2)
{
    const uint64_t overSize = 100 * sizeof(perf_file_attr);
    std::string fileName = "/proc/" + std::to_string(getpid()) + "/cmdline";
    FILE* fp = fopen(fileName.c_str(), "r");
    EXPECT_NE(fp, nullptr);
    PerfFileReader hiperfFileReader("", fp);
    perf_file_header header = hiperfFileReader.GetHeader();
    header.attrSize = overSize;
    EXPECT_EQ(hiperfFileReader.ReadAttrSection(), false);
}

HWTEST_F(PerfFileReaderTest, ReadIdsForAttr_NoZero, TestSize.Level1)
{
    std::string tempFile = "test_ids_no_zero.tmp";
    FILE* tempFp = fopen(tempFile.c_str(), "wb");
    ASSERT_NE(tempFp, nullptr) << "Failed to create temp file";
    uint32_t testData = 0x12345678;
    fwrite(&testData, sizeof(testData), 1, tempFp);
    fclose(tempFp);

    perf_file_attr attr;
    attr.ids.size = 4;
    attr.ids.offset = 0;
    FILE* fp = fopen(tempFile.c_str(), "rb");
    ASSERT_NE(fp, nullptr) << "Failed to open temp file for reading";

    PerfFileReader reader("", fp);
    std::vector<uint64_t> v;
    EXPECT_TRUE(reader.ReadIdsForAttr(attr, &v)) << "ReadIdsForAttr failed";
    printf("v contains %zu elements:\n", v.size());
    for (size_t i = 0; i < v.size(); ++i) {
        printf("  v[%zu] = %" PRIu64 "\n", i, v[i]);
    }

    EXPECT_EQ(v.size(), 1u) << "Vector size mismatch (expected 1 element)";
    for (uint64_t id : v) {
        EXPECT_NE(id, 0u) << "Found unexpected 0 in attr.ids";
    }

    fclose(fp);
    unlink(tempFile.c_str());
}

/**
 * @tc.name: Instance_RealPerfData
 * @tc.desc: Test Instance with real perf.data covers ReadFileHeader and ReadAttrSection
 * @tc.type: FUNC
 */
HWTEST_F(PerfFileReaderTest, Instance_RealPerfData, TestSize.Level0)
{
    const std::string fileName = "/data/test/resource/testdata/perf.data";
    if (access(fileName.c_str(), R_OK) != 0) {
        printf("perf.data not exist.\n");
        return;
    }
    auto reader = PerfFileReader::Instance(fileName);
    ASSERT_NE(reader, nullptr);
    EXPECT_TRUE(reader->IsValidDataFile());
    EXPECT_FALSE(reader->IsGzipFile());
    EXPECT_GT(reader->GetFeatures().size(), 0u);
    EXPECT_GT(reader->GetAttrSection().size(), 0u);
}

/**
 * @tc.name: ReadDataSection_RealPerfData
 * @tc.desc: Test ReadDataSection with real perf.data covers ReadRecord and callback
 * @tc.type: FUNC
 */
HWTEST_F(PerfFileReaderTest, ReadDataSection_RealPerfData, TestSize.Level0)
{
    const std::string fileName = "/data/test/resource/testdata/perf.data";
    if (access(fileName.c_str(), R_OK) != 0) {
        printf("perf.data not exist.\n");
        return;
    }
    auto reader = PerfFileReader::Instance(fileName);
    ASSERT_NE(reader, nullptr);
    int recordCount = 0;
    ProcessRecordCB callback = [&recordCount](PerfEventRecord& record) -> bool {
        recordCount++;
        return true;
    };
    reader->ReadDataSection(callback);
    EXPECT_GT(recordCount, 0);
}

/**
 * @tc.name: ReadFeatureSection_RealPerfData
 * @tc.desc: Test ReadFeatureSection with real perf.data covers feature section parsing
 * @tc.type: FUNC
 */
HWTEST_F(PerfFileReaderTest, ReadFeatureSection_RealPerfData, TestSize.Level1)
{
    const std::string fileName = "/data/test/resource/testdata/perf.data";
    if (access(fileName.c_str(), R_OK) != 0) {
        printf("perf.data not exist.\n");
        return;
    }
    auto reader = PerfFileReader::Instance(fileName);
    ASSERT_NE(reader, nullptr);
    EXPECT_TRUE(reader->ReadFeatureSection());
    EXPECT_GE(reader->GetFeatureSections().size(), 0u);
}

/**
 * @tc.name: GetFeatureString_RealPerfData
 * @tc.desc: Test GetFeatureString with real perf.data covers GetFeatureSection and ToString
 * @tc.type: FUNC
 */
HWTEST_F(PerfFileReaderTest, GetFeatureString_RealPerfData, TestSize.Level1)
{
    const std::string fileName = "/data/test/resource/testdata/perf.data";
    if (access(fileName.c_str(), R_OK) != 0) {
        printf("perf.data not exist.\n");
        return;
    }
    auto reader = PerfFileReader::Instance(fileName);
    ASSERT_NE(reader, nullptr);
    reader->ReadFeatureSection();
    const std::string archStr = reader->GetFeatureString(FEATURE::ARCH);
    EXPECT_FALSE(archStr.empty());
    const std::string nonStr = reader->GetFeatureString(FEATURE::BUILD_ID);
    EXPECT_TRUE(nonStr.empty());
}

/**
 * @tc.name: GetFeatureSection_NotFound
 * @tc.desc: Test GetFeatureSection returns nullptr when feature not found
 * @tc.type: FUNC
 */
HWTEST_F(PerfFileReaderTest, GetFeatureSection_NotFound, TestSize.Level2)
{
    const std::string fileName = "/data/test/resource/testdata/perf.data";
    if (access(fileName.c_str(), R_OK) != 0) {
        printf("perf.data not exist.\n");
        return;
    }
    auto reader = PerfFileReader::Instance(fileName);
    ASSERT_NE(reader, nullptr);
    EXPECT_EQ(reader->GetFeatureSection(FEATURE::RESERVED), nullptr);
}

/**
 * @tc.name: ReadIdsForAttr_SizeZero
 * @tc.desc: Test ReadIdsForAttr returns true when attr.ids.size is zero
 * @tc.type: FUNC
 */
HWTEST_F(PerfFileReaderTest, ReadIdsForAttr_SizeZero, TestSize.Level2)
{
    perf_file_attr attr;
    attr.ids.size = 0;
    std::vector<uint64_t> v;
    PerfFileReader reader("", nullptr);
    EXPECT_TRUE(reader.ReadIdsForAttr(attr, &v));
    EXPECT_EQ(v.size(), 0u);
}

/**
 * @tc.name: GetHeader_Default
 * @tc.desc: Test GetHeader returns default header when no file read
 * @tc.type: FUNC
 */
HWTEST_F(PerfFileReaderTest, GetHeader_Default, TestSize.Level2)
{
    PerfFileReader reader("", nullptr);
    const perf_file_header &header = reader.GetHeader();
    EXPECT_EQ(header.attrSize, (uint64_t)sizeof(perf_file_attr));
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
