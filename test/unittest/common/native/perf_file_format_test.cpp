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

#include "perf_file_format_test.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;

namespace OHOS {
namespace Developtools {
namespace HiPerf {
class PerfFileFormatTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static void CompareVecSymFile(const std::vector<SymbolFileStruct> &a,
                                  const std::vector<SymbolFileStruct> &b);
    static void TestEventDescInit(std::vector<AttrWithId> &eventDesc, size_t &size);
    static void CompareEventDesc(const std::vector<AttrWithId> &a,
                                 const std::vector<AttrWithId> &b);

    static const int BIGK = 1024;
    static const int TWO = 2;
    static const int TESTNUMBER1 = 1;
    static const int TESTNUMBER2 = 2;
    static const int TESTNUMBER3 = 3;
    static const int TESTNUMBER4 = 4;
    static const int TESTNUMBER5 = 5;
};

void PerfFileFormatTest::SetUpTestCase() {}

void PerfFileFormatTest::TearDownTestCase() {}

void PerfFileFormatTest::SetUp() {}

void PerfFileFormatTest::TearDown() {}

/**
 * @tc.name: Test
 * @tc.desc: push several records of all type into the buffer
 * @tc.type: FUNC
 */
HWTEST_F(PerfFileFormatTest, GetFeatureName, TestSize.Level1)
{
    const char *unknownFeature = "unknown_feature";

    FEATURE i = FEATURE::FIRST_FEATURE;
    while (i <= FEATURE::LAST_FEATURE) {
        std::string name = PerfFileSection::GetFeatureName(i);
        ASSERT_NE(name, "") << "must return a string";
        ASSERT_NE(name, unknownFeature) << "should be special name";
        i = FEATURE(int(i) + 1);
    }
    while (i < FEATURE::HIPERF_FIRST_FEATURE) {
        std::string name = PerfFileSection::GetFeatureName(i);
        ASSERT_EQ(name, unknownFeature) << "should be unknown";
        i = FEATURE(int(i) + 1);
    }
    while (i <= FEATURE::HIPERF_LAST_FEATURE) {
        std::string name = PerfFileSection::GetFeatureName(i);
        ASSERT_NE(name, "") << "must return a string";
        ASSERT_NE(name, unknownFeature) << "should be special name";
        i = FEATURE(int(i) + 1);
    }
    while (i <= FEATURE::FEATURE_MAX_BITS) {
        std::string name = PerfFileSection::GetFeatureName(i);
        ASSERT_EQ(name, unknownFeature) << "should be unknown";
        i = FEATURE(int(i) + 1);
    }
}

HWTEST_F(PerfFileFormatTest, PerfFileSectionString, TestSize.Level1)
{
    std::string testString("this is test string");
    char buff[BIGK] = {0};
    perf_header_string *p = reinterpret_cast<perf_header_string *>(&buff[0]);

    PerfFileSectionString withString = {FEATURE::RESERVED, testString};
    ASSERT_EQ(withString.toString(), testString);
    ASSERT_EQ(withString.GetSize(), (testString.size() + sizeof(uint32_t) + 1));
    ASSERT_TRUE(withString.GetBinary(buff, sizeof(buff)));
    ASSERT_EQ(testString, p->string);

    PerfFileSectionString withBuff(FEATURE::RESERVED, buff, sizeof(buff));
    ASSERT_EQ(withBuff.toString(), testString);
    ASSERT_EQ(withBuff.GetSize(), (testString.size() + sizeof(uint32_t) + 1));
    ASSERT_TRUE(withBuff.GetBinary(buff, sizeof(buff)));
    ASSERT_EQ(testString, p->string);
}

void PerfFileFormatTest::CompareVecSymFile(const std::vector<SymbolFileStruct> &a,
                                           const std::vector<SymbolFileStruct> &b)
{
    ASSERT_EQ(a.size(), b.size());
    for (size_t i = 0; i < a.size(); i++) {
        ASSERT_EQ(a[i].filePath_, b[i].filePath_);
        ASSERT_EQ(a[i].symbolType_, b[i].symbolType_);
        ASSERT_EQ(a[i].textExecVaddr_, b[i].textExecVaddr_);
        ASSERT_EQ(a[i].textExecVaddrFileOffset_, b[i].textExecVaddrFileOffset_);
        ASSERT_EQ(a[i].buildId_, b[i].buildId_);
        ASSERT_EQ(a[i].symbolStructs_.size(), b[i].symbolStructs_.size());
        for (size_t j = 0; j < a[i].symbolStructs_.size(); j++) {
            ASSERT_EQ(a[i].symbolStructs_[j].vaddr_, b[i].symbolStructs_[j].vaddr_);
            ASSERT_EQ(a[i].symbolStructs_[j].len_, b[i].symbolStructs_[j].len_);
            ASSERT_EQ(a[i].symbolStructs_[j].symbolName_, b[i].symbolStructs_[j].symbolName_);
        }
    }
}

HWTEST_F(PerfFileFormatTest, PerfFileSectionSymbolsFiles, TestSize.Level1)
{
    std::vector<SymbolFileStruct> testVecSymFile;
    char buff[BIGK] = {0};

    size_t testSize = sizeof(uint32_t);
    int count = TWO;
    while (count--) {
        auto &symFile = testVecSymFile.emplace_back();
        symFile.filePath_ = "this is test";
        testSize += (sizeof(uint32_t) + symFile.filePath_.size() + 1);
        symFile.symbolType_ = BIGK;
        testSize += sizeof(symFile.symbolType_);
        symFile.textExecVaddr_ = BIGK;
        testSize += sizeof(symFile.textExecVaddr_);
        symFile.textExecVaddrFileOffset_ = BIGK;
        testSize += sizeof(symFile.textExecVaddrFileOffset_);
        symFile.buildId_ = "this is test";
        testSize += (sizeof(uint32_t) + symFile.buildId_.size() + 1);

        testSize += sizeof(uint32_t);
        auto &symbol = symFile.symbolStructs_.emplace_back();
        symbol.vaddr_ = BIGK;
        testSize += sizeof(symbol.vaddr_);
        symbol.len_ = BIGK;
        testSize += sizeof(symbol.len_);
        symbol.symbolName_ = "this is test";
        testSize += (sizeof(uint32_t) + symbol.symbolName_.size() + 1);
    }

    PerfFileSectionSymbolsFiles withVector(FEATURE::RESERVED, testVecSymFile);
    ASSERT_EQ(withVector.GetSize(), testSize);
    ASSERT_TRUE(withVector.GetBinary(buff, BIGK));

    PerfFileSectionSymbolsFiles withBUff(FEATURE::RESERVED, buff, BIGK);
    CompareVecSymFile(withBUff.symbolFileStructs_, testVecSymFile);
}

HWTEST_F(PerfFileFormatTest, PerfFileSectionNrCpus, TestSize.Level1)
{
    uint32_t nr[2] = {TESTNUMBER1, TESTNUMBER2};
    char buff[BIGK] = {0};

    PerfFileSectionNrCpus nrCpus = {FEATURE::NRCPUS, nr[0], nr[1]};
    ASSERT_EQ(nrCpus.GetSize(), (sizeof(uint32_t) + sizeof(uint32_t)));
    ASSERT_TRUE(nrCpus.GetBinary(buff, sizeof(buff)));

    PerfFileSectionNrCpus withBuff(FEATURE::NRCPUS, buff, sizeof(buff));
    uint32_t nrAvailable = 0;
    uint32_t nrOnline = 0;
    withBuff.GetValue(nrAvailable, nrOnline);
    ASSERT_EQ(nrAvailable, nr[0]);
    ASSERT_EQ(nrOnline, nr[1]);
    ASSERT_EQ(withBuff.featureId_, FEATURE::NRCPUS);
}

HWTEST_F(PerfFileFormatTest, PerfFileSectionU64, TestSize.Level1)
{
    uint64_t v = TESTNUMBER1;
    char buff[BIGK] = {0};

    PerfFileSectionU64 pfsu64 = {FEATURE::RESERVED, v};
    ASSERT_EQ(pfsu64.GetSize(), sizeof(v));
    ASSERT_TRUE(pfsu64.GetBinary(buff, sizeof(buff)));

    PerfFileSectionU64 withBuff(FEATURE::RESERVED, buff, sizeof(buff));
    uint64_t vCheck = 0;
    withBuff.GetValue(vCheck);
    ASSERT_EQ(vCheck, v);
    ASSERT_EQ(withBuff.featureId_, FEATURE::RESERVED);
}

void PerfFileFormatTest::TestEventDescInit(std::vector<AttrWithId> &eventDesc, size_t &size)
{
    size = sizeof(uint32_t) + sizeof(uint32_t); // nr + attr_size
    for (uint32_t nr = TESTNUMBER2; nr > 0; nr--) {
        auto &item = eventDesc.emplace_back();
        size += sizeof(perf_event_attr);
        item.attr = {};
        item.attr.size = 0;
        item.attr.type = TESTNUMBER1 * nr;
        item.attr.config = TESTNUMBER2 * nr;
        item.attr.__reserved_2 = TESTNUMBER3 * nr;
        item.ids = {TESTNUMBER4 * nr, TESTNUMBER5 * nr};
        size += sizeof(uint32_t); // nr_ids
        size += (sizeof(uint64_t) * item.ids.size());
        item.name = "123456789";
        size += sizeof(uint32_t) + item.name.size() + 1;
    }
}

void PerfFileFormatTest::CompareEventDesc(const std::vector<AttrWithId> &a,
                                          const std::vector<AttrWithId> &b)
{
    ASSERT_EQ(a.size(), b.size());
    for (size_t i = 0; i < a.size(); i++) {
        ASSERT_EQ(a[i].name, b[i].name);
        ASSERT_EQ(a[i].attr.size, b[i].attr.size);
        ASSERT_EQ(a[i].attr.type, b[i].attr.type);
        ASSERT_EQ(a[i].attr.config, b[i].attr.config);
        ASSERT_EQ(a[i].attr.__reserved_2, b[i].attr.__reserved_2);
        ASSERT_EQ(a[i].ids.size(), b[i].ids.size());
        for (size_t j = 0; j < a[i].ids.size(); j++) {
            ASSERT_EQ(a[i].ids[j], b[i].ids[j]);
        }
    }
}

HWTEST_F(PerfFileFormatTest, PerfFileSectionEventDesc, TestSize.Level1)
{
    std::vector<AttrWithId> eventDesc;
    size_t size = 0;
    TestEventDescInit(eventDesc, size);
    char buff[BIGK] = {0};

    PerfFileSectionEventDesc pfsEventDesc = {FEATURE::EVENT_DESC, eventDesc};
    ASSERT_EQ(pfsEventDesc.GetSize(), size);
    ASSERT_TRUE(pfsEventDesc.GetBinary(buff, sizeof(buff)));

    PerfFileSectionEventDesc withBuff(FEATURE::EVENT_DESC, buff, sizeof(buff));
    std::vector<AttrWithId> eventDescOut;
    withBuff.GetValue(eventDescOut);
    CompareEventDesc(eventDesc, eventDescOut);
    ASSERT_EQ(withBuff.featureId_, FEATURE::EVENT_DESC);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
