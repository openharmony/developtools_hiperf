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

#include "perf_file_writer_test.h"

#include "virtual_runtime.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;

namespace OHOS {
namespace Developtools {
namespace HiPerf {
const uint TESTRECORDCOUNT = 10;

class PerfFileWriterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static void TestEventDescInit(std::vector<AttrWithId> &eventDesc);
    static const int TESTNUMBER1 = 1;
    static const int TESTNUMBER2 = 2;
    static const int TESTNUMBER3 = 3;
    static const int TESTNUMBER4 = 4;
    static const int TESTNUMBER5 = 5;
};

void PerfFileWriterTest::SetUpTestCase() {}

void PerfFileWriterTest::TearDownTestCase() {}

void PerfFileWriterTest::SetUp() {}

void PerfFileWriterTest::TearDown() {}

/**
 * @tc.name: Test
 * @tc.desc: push several records of all type into the buffer
 * @tc.type: FUNC
 */
void PerfFileWriterTest::TestEventDescInit(std::vector<AttrWithId> &eventDesc)
{
    for (uint32_t nr = TESTNUMBER2; nr > 0; nr--) {
        auto &item = eventDesc.emplace_back();
        item.attr = {};
        item.attr.size = 0;
        item.attr.type = TESTNUMBER1 * nr;
        item.attr.config = TESTNUMBER2 * nr;
        item.attr.__reserved_2 = TESTNUMBER3 * nr;
        item.ids = {TESTNUMBER4 * nr, TESTNUMBER5 * nr};
        item.name = "test event desc";
    }
}

HWTEST_F(PerfFileWriterTest, TestFileWriter_Normal, TestSize.Level1)
{
    std::string filename = "./TestFileWriter_Normal";
    PerfFileWriter fileWriter;
    ASSERT_TRUE(fileWriter.Open(filename)) << "current path no write permission?";

    std::vector<AttrWithId> attrIds;
    AttrWithId attrId;
    perf_event_attr attr;
    attrId.attr = attr;
    attrId.ids.emplace_back(0);
    attrIds.emplace_back(attrId);
    ASSERT_TRUE(fileWriter.WriteAttrAndId(attrIds));

    uint64_t dataSize = 0;
    for (uint i = 0; i < TESTRECORDCOUNT; i++) {
        std::string testStr = "testFeature " + std::to_string(i);
        PerfRecordMmap recordmmap(true, i, i, i, i, i, testStr);
        dataSize += recordmmap.GetSize();
        ASSERT_TRUE(fileWriter.WriteRecord(recordmmap));
        ASSERT_TRUE(fileWriter.AddStringFeature(FEATURE::RESERVED, testStr));
        ASSERT_TRUE(fileWriter.AddNrCpusFeature(FEATURE::RESERVED, 0, TESTNUMBER1));
        ASSERT_TRUE(fileWriter.AddU64Feature(FEATURE::RESERVED, TESTNUMBER2));
        std::vector<AttrWithId> eventDesces;
        TestEventDescInit(eventDesces);
        ASSERT_TRUE(fileWriter.AddEventDescFeature(FEATURE::RESERVED, eventDesces));
        VirtualRuntime vr;
        ASSERT_TRUE(fileWriter.AddSymbolsFeature(vr.GetSymbolsFiles()));
    }
    ASSERT_EQ(fileWriter.GetDataSize(), dataSize);
    ASSERT_EQ(fileWriter.GetRecordCount(), TESTRECORDCOUNT);
    ASSERT_TRUE(fileWriter.Close());
    // check file
    ASSERT_TRUE((access(filename.c_str(), F_OK) == 0));
}

HWTEST_F(PerfFileWriterTest, TestFileWriter_Compress, TestSize.Level1)
{
    std::string filename = "./TestFileWriter_Compress";
    PerfFileWriter fileWriter;
    ASSERT_TRUE(fileWriter.Open(filename, true)) << "current path no write permission?";

    std::vector<AttrWithId> attrIds;
    AttrWithId attrId;
    perf_event_attr attr;
    attrId.attr = attr;
    attrId.ids.emplace_back(0);
    attrIds.emplace_back(attrId);
    ASSERT_TRUE(fileWriter.WriteAttrAndId(attrIds));

    uint64_t dataSize = 0;
    for (uint i = 0; i < TESTRECORDCOUNT; i++) {
        std::string testStr = "testFeature " + std::to_string(i);
        PerfRecordMmap recordmmap(true, i, i, i, i, i, testStr);
        dataSize += recordmmap.GetSize();
        ASSERT_TRUE(fileWriter.WriteRecord(recordmmap));
        ASSERT_TRUE(fileWriter.AddStringFeature(FEATURE::RESERVED, testStr));
        ASSERT_TRUE(fileWriter.AddNrCpusFeature(FEATURE::RESERVED, 0, TESTNUMBER1));
        ASSERT_TRUE(fileWriter.AddU64Feature(FEATURE::RESERVED, TESTNUMBER2));
        VirtualRuntime vr;
        ASSERT_TRUE(fileWriter.AddSymbolsFeature(vr.GetSymbolsFiles()));
    }
    ASSERT_EQ(fileWriter.GetDataSize(), dataSize);
    ASSERT_EQ(fileWriter.GetRecordCount(), TESTRECORDCOUNT);
    ASSERT_TRUE(fileWriter.Close());
    // check file
    ASSERT_TRUE((access(filename.c_str(), F_OK) == 0));
    filename += ".gz";
    ASSERT_TRUE((access(filename.c_str(), F_OK) != 0));
}

HWTEST_F(PerfFileWriterTest, TestFileWriter_NoWriteAttrAndId, TestSize.Level1)
{
    std::string filename = "./TestFileWriter_NoWriteAttrAndId";
    PerfFileWriter fileWriter;
    ASSERT_TRUE(fileWriter.Open(filename)) << "current path no write permission?";

    for (uint i = 0; i < TESTRECORDCOUNT; i++) {
        std::string testStr = "test " + std::to_string(i);
        ASSERT_TRUE(fileWriter.AddStringFeature(FEATURE::RESERVED, testStr));
        VirtualRuntime vr;
        ASSERT_TRUE(fileWriter.AddSymbolsFeature(vr.GetSymbolsFiles()));
    }

    std::string testStr = "testFeature ";
    PerfRecordMmap recordmmap(true, 0, 0, 0, 0, 0, testStr);
    ASSERT_FALSE(fileWriter.WriteRecord(recordmmap));
    ASSERT_TRUE(fileWriter.Close());
    // check file
    ASSERT_TRUE((access(filename.c_str(), F_OK) == 0));
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
