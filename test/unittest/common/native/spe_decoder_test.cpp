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

#include "command.h"
#include "subcommand_dump.h"
#include "subcommand_record.h"
#include "test_utilities.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
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

void SpeDecoderTest::SetUpTestCase() {}

void SpeDecoderTest::TearDownTestCase() {}

void SpeDecoderTest::SetUp()
{
    SubCommand::ClearSubCommands(); // clear the subCommands left from other UT
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
    SubCommandRecord::RegisterSubCommandRecord();
    SubCommandDump::RegisterSubCommandDump();
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
HWTEST_F(SpeDecoderTest, TestRecord, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    std::string testProcesses = "com.ohos.sceneboard";
    if (!CheckTestApp()) {
        testProcesses = "com.ohos.launcher";
    }
    std::string cmdString = "record -e arm_spe_0/load_filter=1,min_latency=100/ -d 10 --app ";
    cmdString += " " + testProcesses;
    printf("command : %s\n", cmdString.c_str());

    // it need load some symbols and much more log
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    bool ret = Command::DispatchCommand(cmdString);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    std::string stringOut = stdoutRecord.Stop();
    printf("run %" PRId64 " ms return %d\n", (uint64_t)costMs.count(), static_cast<int>(ret));
    EXPECT_EQ(true, ret);
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
        const auto startTime = chrono::steady_clock::now();
        bool ret = Command::DispatchCommand(cmdString);
        const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            chrono::steady_clock::now() - startTime);
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
    SpeDecoderFree(decoder);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS