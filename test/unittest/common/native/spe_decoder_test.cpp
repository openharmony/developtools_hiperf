/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "spe_decoder_test.h"

#include <cstring>
#include "command.h"
#include "perf_events.h"
#include "subcommand_dump.h"
#include "subcommand_record.h"
#include "test_utilities.h"

using namespace testing::ext;
namespace OHOS {
namespace Developtools {
namespace HiPerf {

class SpeDecoderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SpeDecoderTest::SetUpTestCase()
{
    if (chmod("/data/test/hiperf_test_demo", 0755) == -1) { // 0755 : -rwxr-xr-x
        GTEST_LOG_(ERROR) << "hiperf_test_demo chmod failed.";
    }
    if (system("/data/test/hiperf_test_demo &") != 0) {
        GTEST_LOG_(ERROR) << "start hiperf_test_demo failed.";
    } else {
        GTEST_LOG_(INFO) << "start hiperf_test_demo success.";
    }
}

void SpeDecoderTest::TearDownTestCase()
{
    if (system("kill -9 `pidof hiperf_test_demo`") != 0) {
        GTEST_LOG_(ERROR) << "kill hiperf_test_demo failed.";
    } else {
        GTEST_LOG_(INFO) << "kill hiperf_test_demo success.";
    }
}

void SpeDecoderTest::SetUp()
{
    SubCommand::ClearSubCommands(); // clear the subCommands left from other UT
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
    SubCommand::RegisterSubCommand("record", std::make_unique<SubCommandRecord>());
    SubCommand::RegisterSubCommand("dump", std::make_unique<SubCommandDump>());
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 2u); // 2u: 2 size
}

void SpeDecoderTest::TearDown()
{
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 2u); // 2u: 2 size
    SubCommand::ClearSubCommands();
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
    MemoryHold::Get().Clean();
}

/**
 * @tc.name: TestGetSpeEventNameByType
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestGetSpeEventNameByType, TestSize.Level1)
{
    std::string eventName = "";
    GetSpeEventNameByType(PERF_SPE_L1D_ACCESS, eventName);
    ASSERT_EQ(eventName, "l1d-access");
    GetSpeEventNameByType(PERF_SPE_L1D_MISS, eventName);
    ASSERT_EQ(eventName, "l1d-miss");
    GetSpeEventNameByType(PERF_SPE_LLC_ACCESS, eventName);
    ASSERT_EQ(eventName, "llc-access");
    GetSpeEventNameByType(PERF_SPE_LLC_MISS, eventName);
    ASSERT_EQ(eventName, "llc-miss");
    GetSpeEventNameByType(PERF_SPE_TLB_ACCESS, eventName);
    ASSERT_EQ(eventName, "tlb-access");
    GetSpeEventNameByType(PERF_SPE_TLB_MISS, eventName);
    ASSERT_EQ(eventName, "tlb-miss");
    GetSpeEventNameByType(PERF_SPE_BRANCH_MISS, eventName);
    ASSERT_EQ(eventName, "branch-miss");
    GetSpeEventNameByType(PERF_SPE_REMOTE_ACCESS, eventName);
    ASSERT_EQ(eventName, "remote-access");
    GetSpeEventNameByType(PERF_SPE_SVE_PARTIAL_PRED, eventName);
    ASSERT_EQ(eventName, "paritial_read");
    GetSpeEventNameByType(PERF_SPE_SVE_EMPTY_PRED, eventName);
    ASSERT_EQ(eventName, "empty_read");
    GetSpeEventNameByType(1 << 10, eventName); // 10: displacement
    ASSERT_EQ(eventName, "unknow");
}

/**
 * @tc.name: TestRecord
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestRecord, TestSize.Level0)
{
    StdoutRecord stdoutRecord;
    std::string cmdString = "record -e arm_spe_0/load_filter=1,min_latency=100/ -d 10 --app hiperf_test_demo";
    printf("command : %s\n", cmdString.c_str());
    // it need load some symbols and much more log
    stdoutRecord.Start();
    const auto startTime = std::chrono::steady_clock::now();
    bool ret = Command::DispatchCommand(cmdString);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    std::string stringOut = stdoutRecord.Stop();
    printf("run %" PRId64 " ms return %d\n", (uint64_t)costMs.count(), static_cast<int>(ret));
    if (GetSpeType() == UINT_MAX) {
        EXPECT_EQ(false, ret);
    } else {
        EXPECT_EQ(true, ret);
    }
}

/**
 * @tc.name: TestDump
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestDump, TestSize.Level1)
{
    if (access("/data/test/resource/testdata/spe_perf.data", R_OK) == 0) {
        StdoutRecord stdoutRecord;

        std::string cmdString = "dump -i /data/test/resource/testdata/spe_perf.data";

        // it need load some symbols and much more log
        ScopeDebugLevel tempLogLevel {LEVEL_DEBUG};

        stdoutRecord.Start();
        const auto startTime = std::chrono::steady_clock::now();
        bool ret = Command::DispatchCommand(cmdString);
        const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime);
        std::string stringOut = stdoutRecord.Stop();

        printf("command : %s(run %" PRId64 " ms) return %d\n", cmdString.c_str(),
            static_cast<uint64_t>(costMs.count()), static_cast<int>(ret));
        EXPECT_EQ(true, ret);
    } else {
        printf("spe_perf.data not exist.\n");
    }
}

/**
 * @tc.name: TestSpeDecoder
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeDecoder, TestSize.Level1)
{
    const size_t dataDize = 192;
    const u8 rawData[dataDize] = {0xb0, 0x68, 0xe0, 0x20, 0x84, 0xc0, 0xff, 0xff,
        0xa0, 0x99, 0x06, 0x00, 0x98, 0x08, 0x00, 0x62,
        0x16, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x00,
        0xb2, 0xb0, 0x80, 0xad, 0xae, 0xe5, 0xff, 0xff,
        0x00, 0x9a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x46, 0xf9, 0xd5, 0x4a, 0x10, 0x62, 0x01, 0x00,
        0xb0, 0x0c, 0x27, 0xb9, 0xf2, 0x59, 0x00, 0x00,
        0x80, 0x99, 0x07, 0x00, 0x98, 0x0a, 0x00, 0x62,
        0x12, 0x00, 0x00, 0x00, 0x49, 0x01, 0x00, 0x00,
        0xb2, 0x60, 0x73, 0x2b, 0x81, 0x5a, 0x00, 0x00,
        0x00, 0x9a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x20, 0x43, 0xd6, 0x4a, 0x10, 0x62, 0x01, 0x00,
        0xb0, 0x68, 0x54, 0xf9, 0xf4, 0x59, 0x00, 0x00,
        0x80, 0x99, 0x02, 0x00, 0x98, 0x03, 0x00, 0x62,
        0x42, 0x00, 0x00, 0x00, 0x4a, 0x01, 0x00, 0x00,
        0xb1, 0x6c, 0x54, 0xf9, 0xf4, 0x59, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0xa1, 0x6c, 0xd6, 0x4a, 0x10, 0x62, 0x01, 0x00,
        0xb0, 0xb4, 0x2b, 0x20, 0x84, 0xc0, 0xff, 0xff,
        0xa0, 0x99, 0x02, 0x00, 0x98, 0x03, 0x00, 0x62,
        0x02, 0x00, 0x00, 0x00, 0x4a, 0x02, 0x00, 0x00,
        0xb1, 0xac, 0x5c, 0x35, 0x84, 0xc0, 0xff, 0xff,
        0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0xcc, 0x99, 0xd6, 0x4a, 0x10, 0x62, 0x01, 0x00};
    SpeDecoder *decoder = SpeDecoderDataNew(rawData, dataDize);
    EXPECT_EQ(decoder != nullptr, true);
    std::vector<SpeRecord> records;
    while (true) {
        int ret = SpeDecode(decoder);
        if (ret <= 0) {
            break;
        }
        struct SpeRecord record = SpeRecord(decoder->record);
        records.emplace_back(record);
    }
    EXPECT_EQ(records.empty(), false);
    std::vector<ReportItemAuxRawData> auxRawData;
    for (auto rec: records) {
        u64 pc = 0;
        if (rec.from_ip) {
            pc = rec.from_ip;
        } else if (rec.to_ip) {
            pc = rec.to_ip;
        } else {
            continue;
        }
        VirtualRuntime virtualRuntime;
        DfxSymbol symbol = virtualRuntime.GetSymbol(pc, 101, 102); // 101: pid, 102: tid
        struct ReportItemAuxRawData reportItem = {rec.type, 0.0f, 1, symbol.comm_.data(), pc,
                                                  symbol.module_.data(), symbol.GetName().data(),
                                                  symbol.fileVaddr_};
        auxRawData.emplace_back(reportItem);
    }
    AddReportItems(auxRawData);
    SpeDecoderFree(decoder);
}

/**
 * @tc.name: TestSpeDumpRawData1
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeDumpRawData1, TestSize.Level2)
{
    const size_t dataDize = 1624;
    u8 rawData[dataDize] = {0xb0, 0x9c, 0x87, 0xc1, 0x0a, 0x80, 0xff, 0xff,
        0xa0, 0x99, 0x08, 0x00, 0x98, 0x0a, 0x00, 0x62,
        0x16, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x00,
        0xb2, 0x70, 0xea, 0xab, 0xe6, 0xe4, 0xff, 0xff,
        0x00, 0x9a, 0x01, 0x00, 0x64, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x80, 0x46, 0x1d, 0x6d, 0x90, 0x80, 0x00, 0x00,
        0xb0, 0xc4, 0xe2, 0xad, 0x6c, 0x5a, 0x00, 0x00,
        0x80, 0x99, 0x06, 0x00, 0x98, 0x08, 0x00, 0x62,
        0x16, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x00,
        0xb2, 0x80, 0x26, 0xae, 0x6c, 0x5a, 0x00, 0x00,
        0x00, 0x9a, 0x01, 0x00, 0x64, 0xbb, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x82, 0xc8, 0x1d, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0xe4, 0xf4, 0xb5, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x99, 0x06, 0x00, 0x98, 0x08, 0x00, 0x62,
        0x16, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x00,
        0xb2, 0xb0, 0x23, 0xc8, 0x00, 0x64, 0xff, 0xff,
        0x00, 0x9a, 0x01, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x52, 0x04, 0x1e, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x84, 0x53, 0xb8, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x99, 0x02, 0x00, 0x98, 0x03, 0x00, 0x62,
        0x02, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00,
        0xb1, 0xe0, 0xf4, 0xb5, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0xa5, 0x0b, 0x1e, 0x6d, 0x90, 0x80, 0x00, 0x00,
        0xb0, 0x98, 0x59, 0xc3, 0x0a, 0x80, 0xff, 0xff,
        0xa0, 0x99, 0x05, 0x00, 0x98, 0x06, 0x00, 0x62,
        0x42, 0x00, 0x00, 0x00, 0x4a, 0x01, 0x00, 0x00,
        0xb1, 0x9c, 0x59, 0xc3, 0x0a, 0x80, 0xff, 0xff,
        0xa0, 0x00, 0x00, 0x00, 0x64, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x55, 0x28, 0x1e, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x10, 0xd3, 0xaa, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x99, 0x06, 0x00, 0x98, 0x08, 0x00, 0x62,
        0x16, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x00,
        0xb2, 0xa0, 0xfd, 0xc5, 0x7d, 0xb4, 0xff, 0xff,
        0x00, 0x9a, 0x01, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x08, 0x3a, 0x1e, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x34, 0xd2, 0x8c, 0x6f, 0x5a, 0x00, 0x00,
        0x80, 0x99, 0x06, 0x00, 0x98, 0x08, 0x00, 0x62,
        0x16, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x00,
        0xb2, 0x70, 0x16, 0x29, 0x7a, 0x5a, 0x00, 0x00,
        0x00, 0x9a, 0x01, 0x00, 0x64, 0xbb, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x51, 0x62, 0x1e, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0xe8, 0xa8, 0xe5, 0x6b, 0x5a, 0x00, 0x00,
        0x80, 0x99, 0x07, 0x00, 0x98, 0x0a, 0x00, 0x62,
        0x12, 0x00, 0x00, 0x00, 0x49, 0x01, 0x00, 0x00,
        0xb2, 0xa0, 0x02, 0x29, 0x7a, 0x5a, 0x00, 0x00,
        0x00, 0x9a, 0x01, 0x00, 0x64, 0xbb, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x8c, 0x87, 0x1e, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x9c, 0x1c, 0x12, 0x6b, 0x5a, 0x00, 0x00,
        0x80, 0x99, 0x08, 0x00, 0x98, 0x09, 0x00, 0x62,
        0x82, 0x00, 0x00, 0x00, 0x4a, 0x01, 0x00, 0x00,
        0xb1, 0x7c, 0x1c, 0x12, 0x6b, 0x5a, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x64, 0xbb, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x4c, 0x9c, 0x1e, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x44, 0x7e, 0xe5, 0x6b, 0x5a, 0x00, 0x00,
        0x80, 0x99, 0x03, 0x00, 0x98, 0x04, 0x00, 0x62,
        0x02, 0x00, 0x00, 0x00, 0x4a, 0x02, 0x00, 0x00,
        0xb1, 0x04, 0x65, 0xe5, 0x6b, 0x5a, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x64, 0xbb, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x44, 0x10, 0x1f, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x9c, 0x7b, 0xe5, 0x6b, 0x5a, 0x00, 0x00,
        0x80, 0x99, 0x06, 0x00, 0x98, 0x09, 0x00, 0x62,
        0x12, 0x08, 0x00, 0x00, 0x49, 0x01, 0x00, 0x00,
        0xb2, 0xe8, 0x0c, 0x29, 0x7a, 0x5a, 0x00, 0x00,
        0x00, 0x9a, 0x01, 0x00, 0x64, 0xbb, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0xc8, 0x2e, 0x1f, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x10, 0x9e, 0xe5, 0x6b, 0x5a, 0x00, 0x00,
        0x80, 0x99, 0xc5, 0x00, 0x98, 0xc6, 0x00, 0x62,
        0x02, 0x00, 0x00, 0x00, 0x4a, 0x02, 0x00, 0x00,
        0xb1, 0x0c, 0x73, 0xe5, 0x6b, 0x5a, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x64, 0xbb, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0xc1, 0x73, 0x1f, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x88, 0x43, 0xc4, 0x0a, 0x80, 0xff, 0xff,
        0xa0, 0x99, 0x0c, 0x00, 0x98, 0x0d, 0x00, 0x62,
        0x02, 0x00, 0x00, 0x00, 0x4a, 0x02, 0x00, 0x00,
        0xb1, 0xc4, 0x5b, 0xf0, 0x0a, 0x80, 0xff, 0xff,
        0xa0, 0x00, 0x00, 0x00, 0x64, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x34, 0x9a, 0x1f, 0x6d, 0x90, 0x80, 0x00, 0x00,
        0xb0, 0xa8, 0xcf, 0xef, 0x0a, 0x80, 0xff, 0xff,
        0xa0, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x62,
        0x16, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00,
        0xb2, 0xbc, 0x74, 0xfc, 0xc1, 0xe4, 0xff, 0xff,
        0x00, 0x9a, 0x01, 0x00, 0x64, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0xd7, 0xb3, 0x1f, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x9c, 0x53, 0xb8, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x99, 0x06, 0x00, 0x98, 0x08, 0x00, 0x62,
        0x16, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x00,
        0xb2, 0x08, 0x00, 0xc4, 0x7d, 0xb4, 0xff, 0xff,
        0x00, 0x9a, 0x01, 0x00, 0x64, 0xbb, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x0c, 0xc0, 0x1f, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x18, 0x3a, 0xa5, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x99, 0x07, 0x00, 0x98, 0x08, 0x00, 0x62,
        0x02, 0x00, 0x00, 0x00, 0x4a, 0x01, 0x00, 0x00,
        0xb1, 0x48, 0x3a, 0xa5, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x00, 0x00, 0x00, 0x64, 0xbb, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0xb2, 0xce, 0x1f, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x04, 0x0e, 0xb9, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x99, 0x06, 0x00, 0x98, 0x09, 0x00, 0x62,
        0x12, 0x00, 0x00, 0x00, 0x49, 0x01, 0x00, 0x00,
        0xb2, 0xa0, 0xfc, 0xc5, 0x7d, 0xb4, 0xff, 0xff,
        0x00, 0x9a, 0x01, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x9f, 0x63, 0x20, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x5c, 0x12, 0xb9, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x99, 0x06, 0x00, 0x98, 0x09, 0x00, 0x62,
        0x12, 0x00, 0x00, 0x00, 0x49, 0x01, 0x00, 0x00,
        0xb2, 0x60, 0xfc, 0xc5, 0x7d, 0xb4, 0xff, 0xff,
        0x00, 0x9a, 0x01, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x23, 0x82, 0x20, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x98, 0x0f, 0xb9, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x99, 0x0a, 0x00, 0x98, 0x0b, 0x00, 0x62,
        0x02, 0x00, 0x00, 0x00, 0x4a, 0x01, 0x00, 0x00,
        0xb1, 0xac, 0x0f, 0xb9, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0xaf, 0x8a, 0x20, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x14, 0xf3, 0xb1, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x99, 0x09, 0x00, 0x98, 0x0c, 0x00, 0x62,
        0x12, 0x08, 0x00, 0x00, 0x49, 0x01, 0x00, 0x00,
        0xb2, 0xd8, 0xfa, 0xc5, 0x7d, 0xb4, 0xff, 0xff,
        0x00, 0x9a, 0x01, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x48, 0x96, 0x20, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x64, 0x0e, 0xb0, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x99, 0x0f, 0x00, 0x98, 0x10, 0x00, 0x62,
        0x42, 0x00, 0x00, 0x00, 0x4a, 0x01, 0x00, 0x00,
        0xb1, 0x68, 0x0e, 0xb0, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x37, 0x9e, 0x20, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x74, 0x1f, 0xb3, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x99, 0x07, 0x00, 0x98, 0x08, 0x00, 0x00,
        0x12, 0x00, 0x00, 0x00, 0x49, 0x01, 0x00, 0x00,
        0xb2, 0xa0, 0xfc, 0xc5, 0x7d, 0xb4, 0xff, 0xff,
        0x00, 0x9a, 0x01, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0xd6, 0xc2, 0x20, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0xe8, 0xf4, 0xb5, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x99, 0x02, 0x00, 0x98, 0x03, 0x00, 0x62,
        0x02, 0x00, 0x00, 0x00, 0x4a, 0x02, 0x00, 0x00,
        0xb1, 0x7c, 0x95, 0xb5, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x29, 0xca, 0x20, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x78, 0x4d, 0xd2, 0x6a, 0x5a, 0x00, 0x00,
        0x80, 0x99, 0x07, 0x00, 0x98, 0x0a, 0x00, 0x62,
        0x12, 0x00, 0x00, 0x00, 0x4a, 0x01, 0x00, 0x00,
        0xb2, 0x50, 0x16, 0x29, 0x7a, 0x5a, 0x00, 0x00,
        0x00, 0x9a, 0x01, 0x00, 0x64, 0xbb, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x0a, 0xfe, 0x20, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x04, 0x27, 0xa9, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x99, 0x07, 0x00, 0x98, 0x09, 0x00, 0x62,
        0x16, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x00,
        0xb2, 0xb8, 0xd4, 0x29, 0xdd, 0xe5, 0xff, 0xff,
        0x00, 0x9a, 0x01, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x2e, 0x12, 0x21, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0xf8, 0xb4, 0xb6, 0x00, 0x64, 0xff, 0xff,
        0xa0, 0x99, 0x06, 0x00, 0x98, 0x08, 0x00, 0x62,
        0x16, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x00,
        0xb2, 0x40, 0xfd, 0xc5, 0x7d, 0xb4, 0xff, 0xff,
        0x00, 0x9a, 0x01, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x81, 0x19, 0x21, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0xb4, 0x1b, 0xa6, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x99, 0x02, 0x00, 0x98, 0x03, 0x00, 0x62,
        0x02, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00,
        0xb1, 0xe0, 0xf4, 0xb5, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0xc4, 0x28, 0x21, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x70, 0x2d, 0xd0, 0x0a, 0x80, 0x00, 0x00,
        0xa0, 0x99, 0x06, 0x00, 0x98, 0x08, 0x00, 0x62,
        0x16, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x00,
        0xb2, 0xd0, 0xc2, 0x8e, 0x01, 0x8c, 0xff, 0xff,
        0x00, 0x9a, 0x01, 0x00, 0x64, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0xa5, 0x5c, 0x21, 0x6d, 0x90, 0x08, 0x00, 0x00,
        0xb0, 0x34, 0xa0, 0xb8, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x99, 0x02, 0x00, 0x98, 0x03, 0x00, 0x62,
        0x02, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00,
        0xb1, 0xe8, 0x9f, 0xb8, 0x00, 0xb4, 0xff, 0xff,
        0xa0, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,
        0x0f, 0x75, 0x21, 0x6d, 0x90, 0x08, 0x00, 0x00};
    EXPECT_EQ(SpeDumpRawData(rawData, dataDize, 1, nullptr), true);
}

/**
 * @tc.name: TestSpeDumpRawData2
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeDumpRawData2, TestSize.Level1)
{
    const size_t dataDize = 112;
    u8 rawData[dataDize] = {0x00, 0x00, 0x00, 0x71, 0x32, 0x5a, 0x28, 0x6d,
        0x90, 0x08, 0x00, 0x00, 0x00, 0x90, 0x70, 0x0a,
        0x6b, 0x5a, 0x00, 0x00, 0x80, 0x99, 0x02, 0x00,
        0x98, 0x03, 0x00, 0x62, 0x02, 0x00, 0x00, 0x00,
        0x4a, 0x01, 0x00, 0x00, 0xb1, 0x0c, 0x71, 0x0a,
        0x6b, 0x5a, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
        0x64, 0xbb, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x71, 0x21, 0x62, 0x28, 0x6d,
        0x90, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    EXPECT_EQ(SpeDumpRawData(rawData, dataDize, 1, nullptr), true);
}

// ========== 新增测试用例：Packet解析（通过公共API间接测试） ==========

/**
 * @tc.name: TestSpePktDescEventAllBits
 * @tc.desc: Test SpePktDescEvent with all event bits
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpePktDescEventAllBits, TestSize.Level2)
{
    struct SpePkt packet = {};
    packet.type = PERF_SPE_EVENTS;
    char buf[256] = {};
    
    // Test each event bit individually
    packet.payload = BIT(EVENT_EXCEPTION_GEN);
    SpePktDesc(&packet, buf, 256);
    
    packet.payload = BIT(EVENT_RETIRED);
    SpePktDesc(&packet, buf, 256);
    
    packet.payload = BIT(EVENT_L1D_ACCESS);
    SpePktDesc(&packet, buf, 256);
    
    packet.payload = BIT(EVENT_L1D_REFILL);
    SpePktDesc(&packet, buf, 256);
    
    packet.payload = BIT(EVENT_TLB_ACCESS);
    SpePktDesc(&packet, buf, 256);
    
    packet.payload = BIT(EVENT_TLB_WALK);
    SpePktDesc(&packet, buf, 256);
    
    packet.payload = BIT(EVENT_NOT_TAKEN);
    SpePktDesc(&packet, buf, 256);
    
    packet.payload = BIT(EVENT_MISPRED);
    SpePktDesc(&packet, buf, 256);
    
    packet.payload = BIT(EVENT_LLC_ACCESS);
    SpePktDesc(&packet, buf, 256);
    
    packet.payload = BIT(EVENT_LLC_MISS);
    SpePktDesc(&packet, buf, 256);
    
    packet.payload = BIT(EVENT_REMOTE_ACCESS);
    SpePktDesc(&packet, buf, 256);
    
    packet.payload = BIT(EVENT_ALIGNMENT);
    SpePktDesc(&packet, buf, 256);
    
    packet.payload = BIT(EVENT_PARTIAL_PREDICATE);
    SpePktDesc(&packet, buf, 256);
    
    packet.payload = BIT(EVENT_EMPTY_PREDICATE);
    SpePktDesc(&packet, buf, 256);
    
    // Multiple events combined
    packet.payload = BIT(EVENT_L1D_ACCESS) | BIT(EVENT_L1D_REFILL) | BIT(EVENT_TLB_ACCESS);
    SpePktDesc(&packet, buf, 256);
    
    // Null pointer
    EXPECT_EQ(SpePktDesc(nullptr, buf, 256), -1);
    EXPECT_EQ(SpePktDesc(&packet, nullptr, 256), -1);
}

/**
 * @tc.name: TestSpePktDescOpTypeAllClasses
 * @tc.desc: Test SpePktDescOpType with all operation classes
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpePktDescOpTypeAllClasses, TestSize.Level2)
{
    struct SpePkt packet = {};
    packet.type = PERF_SPE_OP_TYPE;
    char buf[256] = {};
    
    // OTHER class
    packet.index = PERF_SPE_OP_PKT_HDR_CLASS_OTHER;
    packet.payload = 0x00; // Non-SVE
    SpePktDesc(&packet, buf, 256);
    
    packet.payload = 0x08; // SVE-OTHER
    SpePktDesc(&packet, buf, 256);
    
    // LD_ST_ATOMIC class
    packet.index = PERF_SPE_OP_PKT_HDR_CLASS_LD_ST_ATOMIC;
    packet.payload = 0x00; // LD
    SpePktDesc(&packet, buf, 256);
    
    packet.payload = 0x01; // ST
    SpePktDesc(&packet, buf, 256);
    
    // BR_ERET class
    packet.index = PERF_SPE_OP_PKT_HDR_CLASS_BR_ERET;
    packet.payload = 0x00; // B
    SpePktDesc(&packet, buf, 256);
    
    packet.payload = 0x01; // B COND
    SpePktDesc(&packet, buf, 256);
    
    packet.payload = 0x02; // B IND
    SpePktDesc(&packet, buf, 256);
    
    // Unknown index
    packet.index = 100;
    int ret = SpePktDesc(&packet, buf, 256);
    EXPECT_EQ(ret, 0); // SpePktDesc resets err to 0 after raw data output
}

/**
 * @tc.name: TestSpePktDescAddrAllIndices
 * @tc.desc: Test SpePktDescAddr with all address indices
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpePktDescAddrAllIndices, TestSize.Level2)
{
    struct SpePkt packet = {};
    packet.type = PERF_SPE_ADDRESS;
    char buf[256] = {};
    
    // INS index
    packet.index = PERF_SPE_ADDR_PKT_HDR_INDEX_INS;
    packet.payload = 0x123456789ABCDEF0ULL;
    SpePktDesc(&packet, buf, 256);
    
    // BRANCH index
    packet.index = PERF_SPE_ADDR_PKT_HDR_INDEX_BRANCH;
    SpePktDesc(&packet, buf, 256);
    
    // PREV_BRANCH index
    packet.index = PERF_SPE_ADDR_PKT_HDR_INDEX_PREV_BRANCH;
    SpePktDesc(&packet, buf, 256);
    
    // DATA_VIRT index
    packet.index = PERF_SPE_ADDR_PKT_HDR_INDEX_DATA_VIRT;
    packet.payload = 0x0000123456789ABCULL;
    SpePktDesc(&packet, buf, 256);
    
    // DATA_PHYS index
    packet.index = PERF_SPE_ADDR_PKT_HDR_INDEX_DATA_PHYS;
    packet.payload = 0xF000123456789ABCULL;
    SpePktDesc(&packet, buf, 256);
    
    // Unknown index
    packet.index = 100;
    int ret = SpePktDesc(&packet, buf, 256);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: TestSpePktDesContAllIndices
 * @tc.desc: Test SpePktDesCont with all counter indices
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpePktDesContAllIndices, TestSize.Level2)
{
    struct SpePkt packet = {};
    packet.type = PERF_SPE_COUNTER;
    char buf[256] = {};
    
    // TOTAL_LAT
    packet.index = PERF_SPE_CNT_PKT_HDR_INDEX_TOTAL_LAT;
    packet.payload = 100;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // ISSUE_LAT
    packet.index = PERF_SPE_CNT_PKT_HDR_INDEX_ISSUE_LAT;
    packet.payload = 50;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // TRANS_LAT
    packet.index = PERF_SPE_CNT_PKT_HDR_INDEX_TRANS_LAT;
    packet.payload = 25;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
}

/**
 * @tc.name: TestSpePktDescAllTypes
 * @tc.desc: Test SpePktDesc with all packet types
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpePktDescAllTypes, TestSize.Level2)
{
    struct SpePkt packet = {};
    char buf[256] = {};
    
    // BAD/PAD/END
    packet.type = PERF_SPE_BAD;
    SpePktDesc(&packet, buf, 256);
    
    packet.type = PERF_SPE_PAD;
    SpePktDesc(&packet, buf, 256);
    
    packet.type = PERF_SPE_END;
    SpePktDesc(&packet, buf, 256);
    
    // TIMESTAMP
    packet.type = PERF_SPE_TIMESTAMP;
    packet.payload = 1234567890ULL;
    SpePktDesc(&packet, buf, 256);
    
    // DATA_SOURCE
    packet.type = PERF_SPE_DATA_SOURCE;
    packet.payload = 0x0AULL;
    SpePktDesc(&packet, buf, 256);
    
    // CONTEXT
    packet.type = PERF_SPE_CONTEXT;
    packet.index = 2;
    packet.payload = 0x1234ULL;
    SpePktDesc(&packet, buf, 256);
    
    // Unknown type
    packet.type = static_cast<SpePktType>(100);
    int ret = SpePktDesc(&packet, buf, 256);
    EXPECT_EQ(ret, 0);
}

// ========== 新增测试用例：地址计算函数 ==========

/**
 * @tc.name: TestSpeCalcIpInsBranch
 * @tc.desc: Test SpeCalcIp with INS/BRANCH indices via packet decoding
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeCalcIpInsBranch, TestSize.Level2)
{
    // Test INS address (from_ip) via packet decoding
    // EL0 (ns=0, el=0)
    u8 bufIns[20] = {0x71, 0x00, 0x00, 0x00, 0x00,
                     0xb0, 0x00, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12,
                     0x01};
    SpeDecoder *decoder = SpeDecoderDataNew(bufIns, 20);
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        // decoder->record.from_ip processed by SpeCalcIp
        SpeDecoderFree(decoder);
    }
    
    // Test BRANCH address (to_ip)
    u8 bufBr[20] = {0x71, 0x00, 0x00, 0x00, 0x00,
                    0xb1, 0x00, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12,
                    0x01};
    decoder = SpeDecoderDataNew(bufBr, 20);
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        SpeDecoderFree(decoder);
    }
}

/**
 * @tc.name: TestSpeCalcIpDataPhys
 * @tc.desc: Test SpeCalcIp with DATA_PHYS index via packet decoding
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeCalcIpDataPhys, TestSize.Level2)
{
    // Test DATA_PHYS address calculation
    u8 buf[20] = {0x71, 0x00, 0x00, 0x00, 0x00,
                  0xb3, 0x00, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12,
                  0x01};
    SpeDecoder *decoder = SpeDecoderDataNew(buf, 20);
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        // decoder->record.phys_addr should be cleaned by SpeCalcIp
        SpeDecoderFree(decoder);
    }
}

/**
 * @tc.name: TestSpeCalcIpUnknownIndex
 * @tc.desc: Test address packet with unknown index via packet decoding
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeCalcIpUnknownIndex, TestSize.Level2)
{
    // PREV_BRANCH index (index=4)
    u8 buf[20] = {0x71, 0x00, 0x00, 0x00, 0x00,
                  0xb4, 0x00, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12,
                  0x01};
    SpeDecoder *decoder = SpeDecoderDataNew(buf, 20);
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        // PREV_BRANCH address handling
        SpeDecoderFree(decoder);
    }
}

/**
 * @tc.name: TestSpeCalcIpDataVirt
 * @tc.desc: Test SpeCalcIp with DATA_VIRT index via packet decoding
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeCalcIpDataVirt, TestSize.Level2)
{
    // Test DATA_VIRT address calculation via full packet decoding
    u8 buf[20] = {0x71, 0x00, 0x00, 0x00, 0x00, // Timestamp
                  0xb2, 0x00, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12, // DATA_VIRT address
                  0x01}; // END
    
    SpeDecoder *decoder = SpeDecoderDataNew(buf, 20);
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        // decoder->record.virt_addr should be processed by SpeCalcIp
        SpeDecoderFree(decoder);
    }
    
    // Test kernel space pattern (bits [55:52] = 0xf)
    u8 bufKernel[20] = {0x71, 0x00, 0x00, 0x00, 0x00,
                        0xb2, 0x00, 0x0B, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x90,
                        0x01};
    decoder = SpeDecoderDataNew(bufKernel, 20);
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        // Should fill 0xff in highest byte for kernel pattern
        SpeDecoderFree(decoder);
    }
}

// ========== 新增测试用例：公共API函数 ==========

/**
 * @tc.name: TestSpeDecoderDataNewNull
 * @tc.desc: Test SpeDecoderDataNew with null pointer
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeDecoderDataNewNull, TestSize.Level2)
{
    EXPECT_EQ(SpeDecoderDataNew(nullptr, 100), nullptr);
}

/**
 * @tc.name: TestSpeDecoderFreeNull
 * @tc.desc: Test SpeDecoderFree with null pointer
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeDecoderFreeNull, TestSize.Level2)
{
    u8 buf[20] = {0x01};
    SpeDecoder *d1 = SpeDecoderDataNew(buf, 20);
    ASSERT_NE(d1, nullptr);
    SpeDecoderFree(d1);
    SpeDecoderFree(nullptr); // null should be safe no-op
    SpeDecoder *d2 = SpeDecoderDataNew(buf, 20);
    EXPECT_NE(d2, nullptr); // heap not corrupted by null free
    SpeDecoderFree(d2);
}

/**
 * @tc.name: TestSpeDecodeNull
 * @tc.desc: Test SpeDecode with null pointer
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeDecodeNull, TestSize.Level2)
{
    EXPECT_EQ(SpeDecode(nullptr), -1);
}

/**
 * @tc.name: TestSpeDumpRawDataNull
 * @tc.desc: Test SpeDumpRawData with null pointer
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeDumpRawDataNull, TestSize.Level2)
{
    EXPECT_EQ(SpeDumpRawData(nullptr, 100, 1, nullptr), false);
}

// ========== 新增测试用例：Record处理函数 ==========

/**
 * @tc.name: TestSpeReadRecordOpTypeAllClasses
 * @tc.desc: Test SpeReadRecordOpType indirectly via SpeDecode
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeReadRecordOpTypeAllClasses, TestSize.Level2)
{
    // Test via SpeDecode with constructed data
    // LD_ST_ATOMIC class
    u8 bufLdSt[20] = {0x71, 0x00, 0x00, 0x00, 0x00, // Timestamp
                      0x48, 0x01,                   // Op-Type LD_ST_ATOMIC
                      0x01};                        // END
    SpeDecoder *decoder = SpeDecoderDataNew(bufLdSt, 20);
    EXPECT_NE(decoder, nullptr);
    
    if (decoder) {
        while (SpeDecode(decoder) > 0) {
            // Process record
        }
        SpeDecoderFree(decoder);
    }
}

/**
 * @tc.name: TestSpeReadRecordEventsAll
 * @tc.desc: Test SpeReadRecordEvents with all event types
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeReadRecordEventsAll, TestSize.Level2)
{
    // Construct packet data with events
    u8 buf[30] = {0x71, 0x00, 0x00, 0x00, 0x00, // Timestamp
                  0x42, 0xFF, 0x03,             // Events with multiple bits
                  0x01};                        // END
    SpeDecoder *decoder = SpeDecoderDataNew(buf, 30);
    EXPECT_NE(decoder, nullptr);
    
    if (decoder) {
        while (SpeDecode(decoder) > 0) {
            // Check record.type for event flags
        }
        SpeDecoderFree(decoder);
    }
}

/**
 * @tc.name: TestSpeReadRecordAddressAllIndices
 * @tc.desc: Test SpeReadRecordAddress with all address indices
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeReadRecordAddressAllIndices, TestSize.Level2)
{
    // Test INS address (from_ip)
    u8 bufIns[30] = {0x71, 0x00, 0x00, 0x00, 0x00,
                     0xb0, 0x00, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12, // Address INS
                     0x01};
    SpeDecoder *decoder = SpeDecoderDataNew(bufIns, 30);
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        // Check decoder->record.from_ip
        SpeDecoderFree(decoder);
    }
    
    // Test BRANCH address (to_ip)
    u8 bufBr[30] = {0x71, 0x00, 0x00, 0x00, 0x00,
                    0xb1, 0x00, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12, // Address BRANCH
                    0x01};
    decoder = SpeDecoderDataNew(bufBr, 30);
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        // Check decoder->record.to_ip
        SpeDecoderFree(decoder);
    }
}

/**
 * @tc.name: TestAddReportItemsAndUpdateHeating
 * @tc.desc: Test AddReportItems and UpdateHeating functions
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestAddReportItemsAndUpdateHeating, TestSize.Level2)
{
    std::vector<ReportItemAuxRawData> testData;
    
    // Add test report items
    testData.push_back({PERF_SPE_L1D_ACCESS, 0.0f, 1, "test", 0x1000, "lib.so", "func", 0x100});
    testData.push_back({PERF_SPE_L1D_ACCESS, 0.0f, 1, "test", 0x2000, "lib.so", "func2", 0x200});
    testData.push_back({PERF_SPE_L1D_MISS, 0.0f, 1, "test", 0x1000, "lib.so", "func", 0x100});
    
    AddReportItems(testData);
    UpdateHeating();

    // Verify report data was added by dumping to temp file
    FILE *fp = tmpfile();
    ASSERT_NE(fp, nullptr);
    DumpSpeReportData(0, fp);
    EXPECT_GT(ftell(fp), 0);
    fclose(fp);
    
    // Test duplicate pc (should increment count)
    testData.push_back({PERF_SPE_L1D_ACCESS, 0.0f, 1, "test", 0x1000, "lib.so", "func", 0x100});
    AddReportItems(testData);
}

/**
 * @tc.name: TestDumpSpeReportData
 * @tc.desc: Test DumpSpeReportData function
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestDumpSpeReportData, TestSize.Level2)
{
    // Add test data first
    std::vector<ReportItemAuxRawData> testData;
    testData.push_back({PERF_SPE_L1D_ACCESS, 50.0f, 10, "test", 0x1000, "lib.so", "func", 0x100});
    AddReportItems(testData);
    UpdateHeating();

    // Dump report to temp file and verify output
    FILE *fp = tmpfile();
    ASSERT_NE(fp, nullptr);
    DumpSpeReportData(0, fp);
    long pos = ftell(fp);
    EXPECT_GT(pos, 0);
    fclose(fp);
}

/**
 * @tc.name: TestSpeAlignmentCalculation
 * @tc.desc: Test alignment packet via full decode
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeAlignmentCalculation, TestSize.Level2)
{
    // Alignment header 0x20, 0x00 (extended + alignment)
    u8 buf[20] = {0x20, 0x00, 0x01}; // Extended header + alignment + END
    SpeDecoder *decoder = SpeDecoderDataNew(buf, 20);
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        // Should handle alignment packet
        SpeDecoderFree(decoder);
    }
}

/**
 * @tc.name: TestSpeGetNextPacketPadSkip
 * @tc.desc: Test SpeGetNextPacket PAD skipping logic
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeGetNextPacketPadSkip, TestSize.Level2)
{
    // Multiple PADs followed by END
    u8 buf[20] = {0x00, 0x00, 0x00, 0x01}; // 3 PADs + END
    SpeDecoder *decoder = SpeDecoderDataNew(buf, 20);
    EXPECT_NE(decoder, nullptr);
    
    if (decoder) {
        SpeDecode(decoder);
        // Should skip PADs and return END record
        SpeDecoderFree(decoder);
    }
}

/**
 * @tc.name: TestSpeGetNextPacketErrorHandling
 * @tc.desc: Test SpeGetNextPacket error handling
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeGetNextPacketErrorHandling, TestSize.Level2)
{
    // Bad packet followed by good packet
    u8 buf[20] = {0xFF, 0x71, 0x00, 0x00, 0x00, 0x00, 0x01}; // BAD + Timestamp + END
    SpeDecoder *decoder = SpeDecoderDataNew(buf, 20);
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        // Bad packet should cause SpeDecode to return negative error code
        EXPECT_LT(SpeDecode(decoder), 0);
        SpeDecoderFree(decoder);
    }
}

/**
 * @tc.name: TestSpeReadRecordCounter
 * @tc.desc: Test SpeReadRecord with COUNTER packet
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeReadRecordCounter, TestSize.Level2)
{
    u8 buf[30] = {0x71, 0x00, 0x00, 0x00, 0x00, // Timestamp
                  0x98, 0x00, 0x64,             // Counter TOTAL_LAT = 100
                  0x01};                        // END
    SpeDecoder *decoder = SpeDecoderDataNew(buf, 30);
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        // Check decoder->record.latency
        SpeDecoderFree(decoder);
    }
}

/**
 * @tc.name: TestSpeReadRecordContext
 * @tc.desc: Test SpeReadRecord with CONTEXT packet
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeReadRecordContext, TestSize.Level2)
{
    u8 buf[30] = {0x71, 0x00, 0x00, 0x00, 0x00, // Timestamp
                  0x64, 0x00, 0x12, 0x34,       // Context
                  0x01};                        // END
    SpeDecoder *decoder = SpeDecoderDataNew(buf, 30);
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        // Check decoder->record.context_id
        SpeDecoderFree(decoder);
    }
}

/**
 * @tc.name: TestSpeReadRecordDataSource
 * @tc.desc: Test SpeReadRecord with DATA_SOURCE packet
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeReadRecordDataSource, TestSize.Level2)
{
    u8 buf[30] = {0x71, 0x00, 0x00, 0x00, 0x00, // Timestamp
                  0x43, 0x00, 0x0A,             // Data source
                  0x01};                        // END
    SpeDecoder *decoder = SpeDecoderDataNew(buf, 30);
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        // Check decoder->record.source
        SpeDecoderFree(decoder);
    }
}

/**
 * @tc.name: TestSpePktDescStatAtomicOpTypeAllFlags
 * @tc.desc: Test SpePktDescStatAtomicOpType with all flags
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpePktDescStatAtomicOpTypeAllFlags, TestSize.Level2)
{
    struct SpePkt packet = {};
    packet.type = PERF_SPE_OP_TYPE;
    packet.index = PERF_SPE_OP_PKT_HDR_CLASS_LD_ST_ATOMIC;
    char buf[256] = {};
    
    // Test AT flag
    packet.payload = PERF_SPE_OP_PKT_AT;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // Test EXCL flag
    packet.payload = PERF_SPE_OP_PKT_EXCL;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // Test AR flag
    packet.payload = PERF_SPE_OP_PKT_AR;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // Test LDST + SVE
    packet.payload = 0x08; // SVE LDST
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // Test SVE EVL
    packet.payload = 0x18; // EVL bits set
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // Test SVE PRED
    packet.payload = PERF_SPE_OP_PKT_SVE_PRED;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // Test SVE SG
    packet.payload = PERF_SPE_OP_PKT_SVE_SG;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
}

/**
 * @tc.name: TestSpePktDescStatAtomicOpTypeAllSubclass
 * @tc.desc: Test SpePktDescStatAtomicOpType with all subclass
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpePktDescStatAtomicOpTypeAllSubclass, TestSize.Level2)
{
    struct SpePkt packet = {};
    packet.type = PERF_SPE_OP_TYPE;
    packet.index = PERF_SPE_OP_PKT_HDR_CLASS_LD_ST_ATOMIC;
    char buf[256] = {};
    
    // SIMD-FP
    packet.payload = PERF_SPE_OP_PKT_LDST_SUBCLASS_SIMD_FP;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // GP-REG
    packet.payload = PERF_SPE_OP_PKT_LDST_SUBCLASS_GP_REG;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // UNSPEC-REG
    packet.payload = PERF_SPE_OP_PKT_LDST_SUBCLASS_UNSPEC_REG;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // NV-SYSREG
    packet.payload = PERF_SPE_OP_PKT_LDST_SUBCLASS_NV_SYSREG;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // MTE-TAG
    packet.payload = PERF_SPE_OP_PKT_LDST_SUBCLASS_MTE_TAG;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // MEMCPY
    packet.payload = PERF_SPE_OP_PKT_LDST_SUBCLASS_MEMCPY;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // MEMSET
    packet.payload = PERF_SPE_OP_PKT_LDST_SUBCLASS_MEMSET;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
}

/**
 * @tc.name: TestSpePktDescOpTypeOtherSve
 * @tc.desc: Test SpePktDescOpType OTHER SVE-OTHER
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpePktDescOpTypeOtherSve, TestSize.Level2)
{
    struct SpePkt packet = {};
    packet.type = PERF_SPE_OP_TYPE;
    packet.index = PERF_SPE_OP_PKT_HDR_CLASS_OTHER;
    char buf[256] = {};
    
    // SVE-OTHER
    packet.payload = 0x08; // SVE pattern
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // SVE-OTHER with FP
    packet.payload = 0x08 | PERF_SPE_OP_PKT_SVE_FP;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // SVE-OTHER with PRED
    packet.payload = 0x08 | PERF_SPE_OP_PKT_SVE_PRED;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // OTHER non-SVE with COND
    packet.payload = PERF_SPE_OP_PKT_COND;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
}

/**
 * @tc.name: TestSpePktDescOpTypeBrEretAllFlags
 * @tc.desc: Test SpePktDescOpType BR_ERET with all flags
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpePktDescOpTypeBrEretAllFlags, TestSize.Level2)
{
    struct SpePkt packet = {};
    packet.type = PERF_SPE_OP_TYPE;
    packet.index = PERF_SPE_OP_PKT_HDR_CLASS_BR_ERET;
    char buf[256] = {};
    
    // B
    packet.payload = 0x00;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // B COND
    packet.payload = PERF_SPE_OP_PKT_COND;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // B IND
    packet.payload = 0x02;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // B COND IND
    packet.payload = PERF_SPE_OP_PKT_COND | 0x02;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
}

/**
 * @tc.name: TestSpePktDescAddrPhysWithFlags
 * @tc.desc: Test SpePktDescAddr DATA_PHYS with ns/ch/pat flags
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpePktDescAddrPhysWithFlags, TestSize.Level2)
{
    struct SpePkt packet = {};
    packet.type = PERF_SPE_ADDRESS;
    packet.index = PERF_SPE_ADDR_PKT_HDR_INDEX_DATA_PHYS;
    char buf[256] = {};
    
    // With ns=1, ch=1, pat=0xF
    packet.payload = 0xF000123456789ABCULL; // pat=0xF in bits 59:56
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
    
    // With ns=0, ch=0
    packet.payload = 0x0000123456789ABCULL;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
}

/**
 * @tc.name: TestSpePayloadShortBuffer
 * @tc.desc: Test SpeGetPayload with insufficient buffer and extended header edge cases
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpePayloadShortBuffer, TestSize.Level1)
{
    u8 bufShortTs[2] = {0x71, 0x00};
    EXPECT_EQ(SpeDumpRawData(bufShortTs, sizeof(bufShortTs), 1, stderr), true);

    u8 bufExtOne[1] = {0x20};
    EXPECT_EQ(SpeDumpRawData(bufExtOne, sizeof(bufExtOne), 1, stderr), true);

    u8 bufAlignShort[2] = {0x21, 0x00};
    EXPECT_EQ(SpeDumpRawData(bufAlignShort, sizeof(bufAlignShort), 1, stderr), true);

    u8 bufAlignOk[8] = {0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    EXPECT_EQ(SpeDumpRawData(bufAlignOk, sizeof(bufAlignOk), 1, stderr), true);
}

/**
 * @tc.name: TestSpeExtendedCounterAndAddr
 * @tc.desc: Test extended header counter and address packets with extHdr=1
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeExtendedCounterAndAddr, TestSize.Level1)
{
    u8 bufExtCounter[6] = {0x20, 0x98, 0x64, 0x00, 0x00, 0x00};
    EXPECT_EQ(SpeDumpRawData(bufExtCounter, sizeof(bufExtCounter), 1, stderr), true);

    u8 bufExtAddr[11] = {0x20, 0xb0, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00};
    EXPECT_EQ(SpeDumpRawData(bufExtAddr, sizeof(bufExtAddr), 1, stderr), true);
}

/**
 * @tc.name: TestSpeDataSourceBranch
 * @tc.desc: Test SpeGetDataSource, DATA_SOURCE desc and record paths
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeDataSourceBranch, TestSize.Level1)
{
    u8 bufDs[3] = {0x43, 0x0A, 0x01};
    EXPECT_EQ(SpeDumpRawData(bufDs, sizeof(bufDs), 1, stderr), true);

    struct SpePkt packet = {};
    char buf[256] = {};
    packet.type = PERF_SPE_DATA_SOURCE;
    packet.payload = 0x0A;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);

    packet.type = PERF_SPE_TIMESTAMP;
    packet.payload = 1234567890ULL;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);

    u8 bufRec[3] = {0x43, 0x0A, 0x01};
    SpeDecoder *decoder = SpeDecoderDataNew(bufRec, sizeof(bufRec));
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        SpeDecoderFree(decoder);
    }
}

/**
 * @tc.name: TestSpePktOutStringTruncation
 * @tc.desc: Test SpePktOutString truncation and zero bufLen paths
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpePktOutStringTruncation, TestSize.Level1)
{
    struct SpePkt packet = {};
    char buf[256] = {};

    packet.type = PERF_SPE_EVENTS;
    packet.payload = BIT(EVENT_L1D_ACCESS) | BIT(EVENT_L1D_REFILL);
    char bufSmall[1] = {0};
    int ret1 = SpePktDesc(&packet, bufSmall, 1);
    EXPECT_EQ(ret1, -1);

    packet.type = PERF_SPE_EVENTS;
    packet.payload = BIT(EVENT_L1D_ACCESS) | BIT(EVENT_LLC_MISS);
    int ret2 = SpePktDesc(&packet, buf, 0);
    EXPECT_EQ(ret2, 0);
}

/**
 * @tc.name: TestSpeOpTypeDescAtomicFlags
 * @tc.desc: Test SpePktDescStatAtomicOpType with IS_LDST_ATOMIC and AT/EXCL/AR flags
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeOpTypeDescAtomicFlags, TestSize.Level1)
{
    struct SpePkt packet = {};
    packet.type = PERF_SPE_OP_TYPE;
    packet.index = PERF_SPE_OP_PKT_HDR_CLASS_LD_ST_ATOMIC;
    char buf[256] = {};
    packet.payload = 0x02 | PERF_SPE_OP_PKT_AT | PERF_SPE_OP_PKT_EXCL | PERF_SPE_OP_PKT_AR;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
}

/**
 * @tc.name: TestSpeOpTypeDescSvePredSg
 * @tc.desc: Test SpePktDescStatAtomicOpType with SVE PRED and SG flags
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeOpTypeDescSvePredSg, TestSize.Level1)
{
    struct SpePkt packet = {};
    packet.type = PERF_SPE_OP_TYPE;
    packet.index = PERF_SPE_OP_PKT_HDR_CLASS_LD_ST_ATOMIC;
    char buf[256] = {};
    packet.payload = 0x08 | PERF_SPE_OP_PKT_SVE_PRED | PERF_SPE_OP_PKT_SVE_SG;
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
}

/**
 * @tc.name: TestSpeCounterDescDefaultIndex
 * @tc.desc: Test SpePktDesCont switch default case with counter index not 0/1/2
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeCounterDescDefaultIndex, TestSize.Level1)
{
    struct SpePkt packet = {};
    packet.type = PERF_SPE_COUNTER;
    packet.index = 5;
    packet.payload = 42;
    char buf[256] = {};
    EXPECT_GE(SpePktDesc(&packet, buf, 256), 0);
    EXPECT_GT(strlen(buf), 0u);
}

/**
 * @tc.name: TestSpeCalcIpEl1El2PhysPrevBranch
 * @tc.desc: Test SpeCalcIp with ns=1 EL1/EL2, DATA_PHYS and PREV_BRANCH indices
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeCalcIpEl1El2PhysPrevBranch, TestSize.Level1)
{
    u8 bufEl1[10] = {0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x01};
    SpeDecoder *decoder = SpeDecoderDataNew(bufEl1, sizeof(bufEl1));
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        SpeDecoderFree(decoder);
    }

    u8 bufEl2[10] = {0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x01};
    decoder = SpeDecoderDataNew(bufEl2, sizeof(bufEl2));
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        SpeDecoderFree(decoder);
    }

    u8 bufPhys[10] = {0xb3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    decoder = SpeDecoderDataNew(bufPhys, sizeof(bufPhys));
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        SpeDecoderFree(decoder);
    }

    u8 bufPrev[10] = {0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    decoder = SpeDecoderDataNew(bufPrev, sizeof(bufPrev));
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        SpeDecoderFree(decoder);
    }
}

/**
 * @tc.name: TestSpeReadRecordOpTypeBranches
 * @tc.desc: Test SpeReadRecordOpType with LD_ST_ATOMIC, OTHER, BR_ERET and default classes
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeReadRecordOpTypeBranches, TestSize.Level1)
{
    u8 bufLdSt[3] = {0x49, 0x01, 0x01};
    SpeDecoder *decoder = SpeDecoderDataNew(bufLdSt, sizeof(bufLdSt));
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        SpeDecoderFree(decoder);
    }

    u8 bufSve[3] = {0x49, 0x08, 0x01};
    decoder = SpeDecoderDataNew(bufSve, sizeof(bufSve));
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        SpeDecoderFree(decoder);
    }

    u8 bufBr[3] = {0x4A, 0x01, 0x01};
    decoder = SpeDecoderDataNew(bufBr, sizeof(bufBr));
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        SpeDecoderFree(decoder);
    }

    u8 bufOther[3] = {0x48, 0x08, 0x01};
    decoder = SpeDecoderDataNew(bufOther, sizeof(bufOther));
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        SpeDecoderFree(decoder);
    }

    u8 bufDef[3] = {0x4B, 0x01, 0x01};
    decoder = SpeDecoderDataNew(bufDef, sizeof(bufDef));
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        SpeDecoderFree(decoder);
    }
}

/**
 * @tc.name: TestSpeReadRecordEventsZeroPayload
 * @tc.desc: Test SpeReadRecordEvents with payload=0
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeReadRecordEventsZeroPayload, TestSize.Level1)
{
    u8 buf[3] = {0x42, 0x00, 0x01};
    SpeDecoder *decoder = SpeDecoderDataNew(buf, sizeof(buf));
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        SpeDecoderFree(decoder);
    }
}

/**
 * @tc.name: TestSpeReadRecordContextPacket
 * @tc.desc: Test SpeReadRecord with CONTEXT packet
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeReadRecordContextPacket, TestSize.Level1)
{
    u8 buf[6] = {0x64, 0x12, 0x34, 0x56, 0x78, 0x01};
    SpeDecoder *decoder = SpeDecoderDataNew(buf, sizeof(buf));
    EXPECT_NE(decoder, nullptr);
    if (decoder) {
        EXPECT_GE(SpeDecode(decoder), 0);
        SpeDecoderFree(decoder);
    }
}

/**
 * @tc.name: TestSpeDumpAndReportWithFile
 * @tc.desc: Test SpeDumpRawData and DumpSpeReportData with non-null FILE*
 * @tc.type: FUNC
 */
HWTEST_F(SpeDecoderTest, TestSpeDumpAndReportWithFile, TestSize.Level1)
{
    u8 buf[2] = {0x00, 0x01};
    EXPECT_EQ(SpeDumpRawData(buf, sizeof(buf), 1, stderr), true);

    DumpSpeReportData(0, stderr);
}

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS