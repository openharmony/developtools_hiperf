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

#include "report_json_file_test.h"

#include <bitset>
#include <memory>

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
using namespace ::testing;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class ReportJsonFileTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::unique_ptr<ReportJsonFile> PrepairReportJson(const VirtualRuntime &virtualRuntime) const;
};

void ReportJsonFileTest::SetUpTestCase() {}

void ReportJsonFileTest::TearDownTestCase() {}

void ReportJsonFileTest::SetUp() {}

void ReportJsonFileTest::TearDown() {}

/*
this func give a report json object which have
1 conifg with name "eventName" and ids is  1,2,3
    1 process : pid 1
    2 thread : tid is 3 and 4
    3 lib : liba , libb and libc
    5 func :
        funca1 in liba
        funca2 in liba
        funcb1 in libb
        funcc1 in libc

    2 callstack
        in thread id 3:
            funca1 - liba count 10
            funca2 - liba count 0
        in thread id 4:
            funcc1 - libc count 20
            funcb1 - libb count 0
*/
std::unique_ptr<ReportJsonFile> ReportJsonFileTest::PrepairReportJson(
    const VirtualRuntime &virtualRuntime) const
{
    std::unique_ptr<ReportJsonFile> json =
        std::make_unique<ReportJsonFile>(nullptr, virtualRuntime);
    std::vector<CallFrame> frames = {
        {0x1u, 0x1u, "funca1", "liba"},
        {0x2u, 0x1u, "funca2", "liba"},
        {0x3u, 0x1u, "funcb1", "libb"},
    };
    std::vector<CallFrame> frames2 = {
        {0x1u, 0x1u, "funcc1", "libc"},
        {0x2u, 0x1u, "funcb1", "libb"},
    };
    std::vector<uint64_t> ids = {1, 2, 3};
    json->reportConfigItems_.emplace(
        ids, ReportConfigItem(json->reportConfigItems_.size(), "eventName"));
    json->libList_ = {"liba", "libb", "libc"};
    json->functionList_ = {
        functionKey(0, "funca1"),
        functionKey(0, "funca2"),
        functionKey(1, "funcb1"),
        functionKey(2, "funcc1"),
    };
    // id , pid , tid , event count
    uint64_t id = 1;
    uint64_t eventCount = 10;
    uint64_t eventCount2 = 20;
    int pid = 2;
    int tid = 3;
    int tid2 = 4;
    json->UpdateReportCallStack(id, pid, tid, eventCount, frames);
    json->UpdateReportCallStack(id, pid, tid2, eventCount2, frames2);

    return json;
}

/**
 * @tc.name: OutputJsonKey
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, OutputJsonKey, TestSize.Level1)
{
    StdoutRecord output;

    // no name
    output.Start();
    OutputJsonKey(stdout, std::string());
    EXPECT_STREQ(output.Stop().c_str(), "");

    output.Start();
    OutputJsonKey(stdout, "");
    EXPECT_STREQ(output.Stop().c_str(), "");

    // have name
    output.Start();
    OutputJsonKey(stdout, "keyname");
    EXPECT_STREQ(output.Stop().c_str(), "\"keyname\":");

    output.Start();
    OutputJsonKey(stdout, static_cast<int>(1));
    EXPECT_STREQ(output.Stop().c_str(), "\"1\":");

    output.Start();
    OutputJsonKey(stdout, static_cast<long>(1));
    EXPECT_STREQ(output.Stop().c_str(), "\"1\":");

    output.Start();
    OutputJsonKey(stdout, static_cast<size_t>(2));
    EXPECT_STREQ(output.Stop().c_str(), "\"2\":");

    output.Start();

    OutputJsonKey(stdout, std::string("keyname"));
    EXPECT_STREQ(output.Stop().c_str(), "\"keyname\":");
}

/**
 * @tc.name: OutputJsonValue
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, OutputJsonValue, TestSize.Level1)
{
    StdoutRecord output;

    output.Start();
    OutputJsonValue(stdout, std::string("value"));
    EXPECT_STREQ(output.Stop().c_str(), "\"value\"");

    output.Start();
    OutputJsonValue(stdout, int(1));
    EXPECT_STREQ(output.Stop().c_str(), "1");

    output.Start();
    OutputJsonValue(stdout, uint64_t(1));
    EXPECT_STREQ(output.Stop().c_str(), "1");

    output.Start();
    OutputJsonValue(stdout, bool(true));
    EXPECT_STREQ(output.Stop().c_str(), "1");

    output.Start();
    OutputJsonValue(stdout, size_t(1));
    EXPECT_STREQ(output.Stop().c_str(), "1");

    output.Start();
    OutputJsonValue(stdout, "value");
    EXPECT_STREQ(output.Stop().c_str(), "\"value\"");

    output.Start();
    OutputJsonValue(stdout, "value", false);
    EXPECT_STREQ(output.Stop().c_str(), ",\"value\"");
}

/**
 * @tc.name: OutputJsonPair
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, OutputJsonPair, TestSize.Level1)
{
    StdoutRecord output;
    output.Start();
    OutputJsonValue(stdout, std::string("value"));
    EXPECT_STREQ(output.Stop().c_str(), "\"value\"");
}

/**
 * @tc.name: OutputJsonVectorList
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, OutputJsonVectorList, TestSize.Level1)
{
    StdoutRecord output;

    output.Start();
    OutputJsonVectorList<int>(stdout, "listname", {1, 2, 3}, true);
    EXPECT_STREQ(output.Stop().c_str(), "\"listname\":[1,2,3]");

    output.Start();
    OutputJsonVectorList<std::string>(stdout, "listname", {"1", "2", "3"}, true);
    EXPECT_STREQ(output.Stop().c_str(), "\"listname\":[\"1\",\"2\",\"3\"]");
}

/**
 * @tc.name: OutputJsonMapList
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, OutputJsonMapList, TestSize.Level1)
{
    StdoutRecord output;
    std::map<int, int> map = {
        {1, 2},
        {3, 4},
        {5, 6},
    };

    output.Start();
    OutputJsonMapList(stdout, "map", map, true);
    EXPECT_STREQ(output.Stop().c_str(), "\"map\":[2,4,6]");

    std::map<std::string, std::string> map2 = {
        {"1", "2"},
        {"3", "4"},
        {"5", "6"},
    };

    output.Start();
    OutputJsonMapList(stdout, "map2", map2, true);
    EXPECT_STREQ(output.Stop().c_str(), "\"map2\":[\"2\",\"4\",\"6\"]");
}

/**
 * @tc.name: OutputJsonMap
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, OutputJsonMap, TestSize.Level1)
{
    StdoutRecord output;
    std::map<int, int> map = {
        {1, 2},
        {3, 4},
        {5, 6},
    };

    output.Start();
    OutputJsonMap(stdout, "map", map, true);
    EXPECT_STREQ(output.Stop().c_str(), "\"map\":{\"1\":2,\"3\":4,\"5\":6}");

    std::map<std::string, std::string> map2 = {
        {"1", "2"},
        {"3", "4"},
        {"5", "6"},
    };

    output.Start();
    OutputJsonMap(stdout, "map2", map2, true);
    EXPECT_STREQ(output.Stop().c_str(), "\"map2\":{\"1\":\"2\",\"3\":\"4\",\"5\":\"6\"}");
}

/**
 * @tc.name: GetOrCreateMapItem
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, GetOrCreateMapItem, TestSize.Level1)
{
    std::map<int, int> map = {
        {1, 2},
        {3, 4},
        {5, 6},
    };

    EXPECT_EQ(GetOrCreateMapItem(map, 1), 2);
    EXPECT_EQ(GetOrCreateMapItem(map, 2), 2);
    EXPECT_EQ(GetOrCreateMapItem(map, 3), 4);
    EXPECT_EQ(GetOrCreateMapItem(map, 4), 4);
}

/**
 * @tc.name: ReportFuncItem
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, ReportFuncItem, TestSize.Level1)
{
    StdoutRecord output;
    ReportFuncItem func(1);
    func.sampleCount_ = 2;
    func.eventCount_ = 3;
    func.subTreeEventCount_ = 4;

    output.Start();
    func.OutputJson(stdout);

    EXPECT_STREQ(output.Stop().c_str(), "{\"symbol\":1,\"counts\":[2,3,4]}");
}

/**
 * @tc.name: ReportCallNodeItem
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, ReportCallNodeItem, TestSize.Level1)
{
    StdoutRecord output;
    /*
    2 / 12
        4 / 10
            6 / 6
    */

    ReportCallNodeItem callnode(1);
    callnode.selfEventCount_ = 2;
    callnode.subTreeEventCount_ = 12;

    output.Start();
    callnode.OutputJson(stdout);

    EXPECT_STREQ(output.Stop().c_str(),
                 "{\"selfEvents\":2,\"subEvents\":12,\"symbol\":1,\"callStack\":[]}");

    ReportCallNodeItem &callnode2 = GetOrCreateMapItem(callnode.childrenMap, 2);
    callnode2.selfEventCount_ = 4;
    callnode2.subTreeEventCount_ = 10;
    output.Start();
    callnode.OutputJson(stdout);
    EXPECT_STREQ(output.Stop().c_str(),
                 "{\"selfEvents\":2,\"subEvents\":12,\"symbol\":1,\"callStack\":[{\"selfEvents\":4,"
                 "\"subEvents\":10,\"symbol\":2,\"callStack\":[]}]}");

    ReportCallNodeItem &callnode3 = GetOrCreateMapItem(callnode2.childrenMap, 3);
    callnode3.selfEventCount_ = 6;
    callnode3.subTreeEventCount_ = 6;
    output.Start();
    callnode.OutputJson(stdout);

    EXPECT_STREQ(output.Stop().c_str(),
                 "{\"selfEvents\":2,\"subEvents\":12,\"symbol\":1,\"callStack\":[{\"selfEvents\":4,"
                 "\"subEvents\":10,\"symbol\":2,\"callStack\":[{\"selfEvents\":6,\"subEvents\":6,"
                 "\"symbol\":3,\"callStack\":[]}]}]}");
}

/**
 * @tc.name: ReportCallNodeItem
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, UpdateChildrenEventCount, TestSize.Level1)
{
    StdoutRecord output;
    /*
    2 / 12
        4 / 10
            6 / 6
    */

    ReportCallNodeItem callnode(1);
    callnode.selfEventCount_ = 2;
    callnode.subTreeEventCount_ = 0;

    ReportCallNodeItem &callnode2 = GetOrCreateMapItem(callnode.childrenMap, 2);
    callnode2.selfEventCount_ = 4;
    callnode2.subTreeEventCount_ = 0;

    ReportCallNodeItem &callnode3 = GetOrCreateMapItem(callnode2.childrenMap, 3);
    callnode3.selfEventCount_ = 6;
    callnode3.subTreeEventCount_ = 0;

    output.Start();
    callnode.UpdateChildrenEventCount();
    callnode.OutputJson(stdout);

    EXPECT_STREQ(output.Stop().c_str(),
                 "{\"selfEvents\":2,\"subEvents\":12,\"symbol\":1,\"callStack\":[{\"selfEvents\":4,"
                 "\"subEvents\":10,\"symbol\":2,\"callStack\":[{\"selfEvents\":6,\"subEvents\":6,"
                 "\"symbol\":3,\"callStack\":[]}]}]}");
}

/**
 * @tc.name: ReportLibItem
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, ReportLibItem, TestSize.Level1)
{
    StdoutRecord output;
    ReportLibItem lib;
    lib.libId_ = 1;
    lib.eventCount_ = 2;

    ReportFuncItem &func = GetOrCreateMapItem(lib.funcs_, 1);
    func.sampleCount_ = 2;
    func.eventCount_ = 3;
    func.subTreeEventCount_ = 4;

    output.Start();
    lib.OutputJson(stdout);

    EXPECT_STREQ(
        output.Stop().c_str(),
        "{\"fileId\":1,\"eventCount\":2,\"functions\":[{\"symbol\":1,\"counts\":[2,3,4]}]}");
}

/**
 * @tc.name: ReportThreadItem
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, ReportThreadItem, TestSize.Level1)
{
    StdoutRecord output;
    ReportThreadItem thread(1);
    thread.tid_ = 2;
    thread.eventCount_ = 3;
    thread.sampleCount_ = 4;

    output.Start();
    thread.OutputJson(stdout);

    EXPECT_STREQ(output.Stop().c_str(),
                 "{\"tid\":2,\"eventCount\":3,\"sampleCount\":4,\"libs\":[],\"CallOrder\":{"
                 "\"selfEvents\":0,\"subEvents\":0,\"symbol\":-1,\"callStack\":[]},\"CalledOrder\":"
                 "{\"selfEvents\":0,\"subEvents\":0,\"symbol\":-1,\"callStack\":[]}}");
}

/**
 * @tc.name: ReportProcessItem
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, ReportProcessItem, TestSize.Level1)
{
    StdoutRecord output;
    ReportProcessItem process(1);
    process.pid_ = 2;
    process.eventCount_ = 3;

    output.Start();
    process.OutputJson(stdout);

    EXPECT_STREQ(output.Stop().c_str(), "{\"pid\":2,\"eventCount\":3,\"threads\":[]}");
}

/**
 * @tc.name: ReportConfigItem
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, ReportConfigItem, TestSize.Level1)
{
    StdoutRecord output;
    ReportConfigItem config(1, "configname");
    config.eventCount_ = 3;

    output.Start();
    config.OutputJson(stdout);

    EXPECT_STREQ(output.Stop().c_str(),
                 "{\"eventConfigName\":\"configname\",\"eventCount\":3,\"processes\":[]}");
}

/**
 * @tc.name: UpdateReportSample
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, UpdateReportSample, TestSize.Level1)
{
    StdoutRecord output;
    VirtualRuntime virtualRuntime;
    ReportJsonFile json(nullptr, virtualRuntime);
    std::vector<uint64_t> ids = {1, 2, 3};
    json.reportConfigItems_.emplace(ids, ReportConfigItem(1, "eventName"));
    // id , pid , tid , event count
    json.UpdateReportSample(1, 2, 3, 4);
    auto configIt = json.reportConfigItems_.begin();

    EXPECT_EQ(configIt->second.eventCount_, 4u);
    ASSERT_EQ(configIt->second.processes_.size(), 1u);
    EXPECT_EQ(configIt->second.processes_.at(2).pid_, 2);
    EXPECT_EQ(configIt->second.processes_.at(2).eventCount_, 4u);
    ASSERT_EQ(configIt->second.processes_.at(2).threads_.size(), 1u);
    EXPECT_EQ(configIt->second.processes_.at(2).threads_.at(3).tid_, 3);
    EXPECT_EQ(configIt->second.processes_.at(2).threads_.at(3).eventCount_, 4u);
    EXPECT_EQ(configIt->second.processes_.at(2).threads_.at(3).sampleCount_, 1u);
    EXPECT_EQ(json.sampleCount_, 1u);
}

/**
 * @tc.name: UpdateReportCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, UpdateReportCallStack, TestSize.Level1)
{
    StdoutRecord output;
    VirtualRuntime virtualRuntime;
    std::unique_ptr<ReportJsonFile> json = PrepairReportJson(virtualRuntime);

    // check
    auto configIt = json->reportConfigItems_.begin();

    // this should not update here
    EXPECT_EQ(configIt->second.eventCount_, 0u);
    ASSERT_EQ(configIt->second.processes_.size(), 1u);
    ASSERT_EQ(configIt->second.processes_.begin()->second.threads_.size(), 2u);
    ReportProcessItem &process = configIt->second.processes_.begin()->second;
    ReportThreadItem &thread = process.threads_.begin()->second;
    // only liba and libb
    ASSERT_EQ(thread.libs_.size(), 2u);
    ReportLibItem &lib = thread.libs_.begin()->second;
    // we have to function , a1 and a2 in liba
    ASSERT_EQ(lib.libId_, 0);
    ASSERT_EQ(lib.funcs_.size(), 2u);

    // chec func count
    ReportFuncItem &funca1 = lib.funcs_.at(0);
    ReportFuncItem &funca2 = lib.funcs_.at(1);

    // only fist one have count
    ASSERT_EQ(funca1.eventCount_, 10u);
    ASSERT_EQ(funca1.subTreeEventCount_, 10u);
    ASSERT_EQ(funca2.eventCount_, 0u);
    ASSERT_EQ(funca2.subTreeEventCount_, 10u);
}

/**
 * @tc.name: UpdateCallNodeEventCount
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, UpdateCallNodeEventCount, TestSize.Level1)
{
    StdoutRecord output;
    VirtualRuntime virtualRuntime;
    std::unique_ptr<ReportJsonFile> json = PrepairReportJson(virtualRuntime);

    auto configIt = json->reportConfigItems_.begin();
    ReportProcessItem &process = configIt->second.processes_.begin()->second;
    ReportThreadItem &thread = process.threads_.begin()->second;
    ReportLibItem &lib = thread.libs_.begin()->second;

    ReportFuncItem &funca1 = lib.funcs_.at(0);
    ReportFuncItem &funca2 = lib.funcs_.at(1);

    // only fist one have count
    EXPECT_EQ(funca1.eventCount_, 10u);
    EXPECT_EQ(funca1.subTreeEventCount_, 10u);
    EXPECT_EQ(funca2.eventCount_, 0u);
    EXPECT_EQ(funca2.subTreeEventCount_, 10u);
    EXPECT_EQ(thread.callNode.subTreeEventCount_, 0u);
    EXPECT_EQ(thread.callNodeReverse.subTreeEventCount_, 0u);

    json->UpdateCallNodeEventCount();
    EXPECT_EQ(thread.callNode.subTreeEventCount_, 10u);
    EXPECT_EQ(thread.callNodeReverse.subTreeEventCount_, 10u);
}

/**
 * @tc.name: ProcessSymbolsFiles
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, ProcessSymbolsFiles, TestSize.Level1)
{
    VirtualRuntime virtualRuntime;
    std::unique_ptr<ReportJsonFile> json =
        std::make_unique<ReportJsonFile>(nullptr, virtualRuntime);
    std::vector<std::unique_ptr<SymbolsFile>> symbolsFiles;

    std::string userSymbol = "user_symbol";
    std::unique_ptr<SymbolsFile> user = SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE);
    user->symbols_.emplace_back(0x1, 1u, "first_user_func", user->filePath_);
    user->symbols_.emplace_back(0x2, 1u, "second_user_func", user->filePath_);
    user->filePath_ = userSymbol;
    symbolsFiles.emplace_back(std::move(user));

    std::string userSymbol2 = "user_symbol2";
    std::unique_ptr<SymbolsFile> user2 = SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE);
    user2->symbols_.emplace_back(0x1, 1u, "first_user2_func", user2->filePath_);
    user2->symbols_.emplace_back(0x2, 1u, "second_user2_func", user2->filePath_);
    user2->symbols_.emplace_back(0x3, 1u, "third_user2_func", user2->filePath_);
    user2->filePath_ = userSymbol2;
    symbolsFiles.emplace_back(std::move(user2));

    json->ProcessSymbolsFiles(symbolsFiles);
    EXPECT_EQ(json->libList_.size(), 2u);
    EXPECT_EQ(json->functionList_.size(), 5u);
    EXPECT_EQ(json->functionMap_.size(), 5u);
}

/**
 * @tc.name: GetFuncionID
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, GetFuncionID, TestSize.Level1)
{
    StdoutRecord output;
    VirtualRuntime virtualRuntime;
    std::unique_ptr<ReportJsonFile> json = PrepairReportJson(virtualRuntime);
    /*
        3 lib : liba , libb and libc
        5 func :
            funca1 in liba
            funca2 in liba
            funcb1 in libb
            funcc1 in libc
    */
    EXPECT_EQ(json->GetFuncionID(0, "funca1"), 0);
    EXPECT_EQ(json->GetFuncionID(0, "funca2"), 1);
    EXPECT_EQ(json->GetFuncionID(0, "funca3"), 4);
    EXPECT_EQ(json->GetFuncionID(0, "funcb1"), 5);
    EXPECT_EQ(json->GetFuncionID(1, "funcb1"), 2);
    EXPECT_EQ(json->GetFuncionID(2, "funcc1"), 3);
}

/**
 * @tc.name: GetLibID
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, GetLibID, TestSize.Level1)
{
    StdoutRecord output;
    VirtualRuntime virtualRuntime;
    std::unique_ptr<ReportJsonFile> json = PrepairReportJson(virtualRuntime);
    /*
        3 lib : liba , libb and libc
        5 func :
            funca1 in liba
            funca2 in liba
            funcb1 in libb
            funcc1 in libc
    */
    EXPECT_EQ(json->GetLibID("liba"), 0);
    EXPECT_EQ(json->GetLibID("libb"), 1);
    EXPECT_EQ(json->GetLibID("libc"), 2);
    EXPECT_EQ(json->GetLibID("libd"), -1);
    EXPECT_EQ(json->GetLibID(""), -1);
}

/**
 * @tc.name: GetConfigIndex
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, GetConfigIndex, TestSize.Level1)
{
    StdoutRecord output;
    VirtualRuntime virtualRuntime;
    std::unique_ptr<ReportJsonFile> json = PrepairReportJson(virtualRuntime);

    std::vector<uint64_t> ids = {4, 5};
    json->reportConfigItems_.emplace(
        ids, ReportConfigItem(json->reportConfigItems_.size(), "eventName2"));

    EXPECT_EQ(json->GetConfigIndex(1), 0u);
    EXPECT_EQ(json->GetConfigIndex(2), 0u);
    EXPECT_EQ(json->GetConfigIndex(3), 0u);
    EXPECT_EQ(json->GetConfigIndex(4), 1u);
    EXPECT_EQ(json->GetConfigIndex(5), 1u);
    EXPECT_EQ(json->GetConfigIndex(6), 0u);
}

/**
 * @tc.name: GetConfigName
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, GetConfigName, TestSize.Level1)
{
    StdoutRecord output;
    VirtualRuntime virtualRuntime;
    std::unique_ptr<ReportJsonFile> json = PrepairReportJson(virtualRuntime);

    std::vector<uint64_t> ids = {4, 5};
    json->reportConfigItems_.emplace(
        ids, ReportConfigItem(json->reportConfigItems_.size(), "eventName2"));

    EXPECT_STREQ(json->GetConfigName(1).c_str(), "eventName");
    EXPECT_STREQ(json->GetConfigName(2).c_str(), "eventName");
    EXPECT_STREQ(json->GetConfigName(3).c_str(), "eventName");
    EXPECT_STREQ(json->GetConfigName(4).c_str(), "eventName2");
    EXPECT_STREQ(json->GetConfigName(5).c_str(), "eventName2");
    EXPECT_STREQ(json->GetConfigName(6).c_str(), "eventName");
}

/**
 * @tc.name: GetConfig
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportJsonFileTest, GetConfig, TestSize.Level1)
{
    StdoutRecord output;
    VirtualRuntime virtualRuntime;
    std::unique_ptr<ReportJsonFile> json = PrepairReportJson(virtualRuntime);

    std::vector<uint64_t> ids = {4, 5};
    json->reportConfigItems_.emplace(
        ids, ReportConfigItem(json->reportConfigItems_.size(), "eventName2"));

    EXPECT_EQ(json->GetConfig(1).index_, 0);
    EXPECT_EQ(json->GetConfig(2).index_, 0);
    EXPECT_EQ(json->GetConfig(3).index_, 0);
    EXPECT_EQ(json->GetConfig(4).index_, 1);
    EXPECT_EQ(json->GetConfig(5).index_, 1);
    EXPECT_EQ(json->GetConfig(6).index_, 0);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
