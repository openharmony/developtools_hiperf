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
#include "utilities_test.h"

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

    std::string cmdString = "record -e arm_spe_0/load_filter=1,min_latency=100/ -d 10 --app ";
    cmdString += " " + TEST_PROCESSES;
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
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS