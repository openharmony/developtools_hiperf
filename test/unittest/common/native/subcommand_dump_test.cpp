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

#include "subcommand_dump_test.h"

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
class SubCommandDumpTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    void TestDumpCommand(const std::string &option, bool expect = true) const;
};

void SubCommandDumpTest::SetUpTestCase()
{
    SubCommand::ClearSubCommands();
}

void SubCommandDumpTest::TearDownTestCase() {}

void SubCommandDumpTest::SetUp()
{
    // clear the subCommands left from other UT
    SubCommand::ClearSubCommands();
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
    SubCommandDump::RegisterSubCommandDump();
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 1u);
}

void SubCommandDumpTest::TearDown()
{
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 1u);
    SubCommand::ClearSubCommands();
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
}

void SubCommandDumpTest::TestDumpCommand(const std::string &option, bool expect) const
{
    StdoutRecord stdoutRecord;

    std::string cmdString = "dump";
    cmdString += " " + option + " ";

    // it need load some symbols and much more log

    ScopeDebugLevel tempLogLevel {LEVEL_DEBUG};

    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    bool ret = Command::DispatchCommand(cmdString);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    std::string stringOut = stdoutRecord.Stop();

    printf("command : %s(run %" PRId64 " ms) return %s(expect %s)\n", cmdString.c_str(),
           (uint64_t)costMs.count(), ret ? "true" : "false", expect ? "true" : "false");
    EXPECT_EQ(expect, ret);
    if (expect) {
        EXPECT_EQ(SubStringCount(stringOut, "HILOG/E"), 0u);
    }
}

/**
 * @tc.name:
 * @tc.desc: record
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandDumpTest, DumpInputFilename, TestSize.Level1)
{
    TestDumpCommand("/data/test/resource/testdata/perf.data ");
}

HWTEST_F(SubCommandDumpTest, DumpInputFilenamErr, TestSize.Level1)
{
    TestDumpCommand("whatfile ", false);
}

HWTEST_F(SubCommandDumpTest, DumpHeaderAttrs, TestSize.Level1)
{
    TestDumpCommand("/data/test/resource/testdata/perf.data --head ");
}

HWTEST_F(SubCommandDumpTest, DumpData, TestSize.Level1)
{
    TestDumpCommand("/data/test/resource/testdata/perf.data -d ");
}

HWTEST_F(SubCommandDumpTest, DumpFeatures, TestSize.Level1)
{
    TestDumpCommand("/data/test/resource/testdata/perf.data -f ");
}

HWTEST_F(SubCommandDumpTest, DumpSympath, TestSize.Level1)
{
    TestDumpCommand("/data/test/resource/testdata/perf.data --sympath ./ ");
}

HWTEST_F(SubCommandDumpTest, DumpSympathErr, TestSize.Level1)
{
    TestDumpCommand("/data/test/resource/testdata/perf.data --sympath where ", false);
}

HWTEST_F(SubCommandDumpTest, DumpExportUserdata0, TestSize.Level1)
{
    TestDumpCommand("/data/test/resource/testdata/perf.data --export 0");
}

HWTEST_F(SubCommandDumpTest, DumpExportUserdata1, TestSize.Level1)
{
    TestDumpCommand("/data/test/resource/testdata/perf.data --export 1");
}

HWTEST_F(SubCommandDumpTest, DumpElffile, TestSize.Level1)
{
    TestDumpCommand("--elf /data/test/resource/testdata/elf_test ");
}

HWTEST_F(SubCommandDumpTest, DumpElffileErr, TestSize.Level1)
{
    TestDumpCommand("--elf whatfile ", false);
}

HWTEST_F(SubCommandDumpTest, DumpInputElfConflict, TestSize.Level1)
{
    TestDumpCommand("perf.data --elf elffile ", false);
}

#if HAVE_PROTOBUF
HWTEST_F(SubCommandDumpTest, DumpProtofile, TestSize.Level1)
{
    TestDumpCommand("--proto /data/test/resource/testdata/proto_test ");
}

HWTEST_F(SubCommandDumpTest, DumpProtofileErr, TestSize.Level1)
{
    TestDumpCommand("--proto whatfile ", false);
}

HWTEST_F(SubCommandDumpTest, DumpInputProtoConflict, TestSize.Level1)
{
    TestDumpCommand("perf.data --proto ptotofile ", false);
}

HWTEST_F(SubCommandDumpTest, DumpElfProtoConflict, TestSize.Level1)
{
    TestDumpCommand("--elf elffile --proto ptotofile ", false);
}
#endif
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
