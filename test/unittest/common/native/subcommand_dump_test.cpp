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

HWTEST_F(SubCommandDumpTest, Test_LibReport_Success, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/report/perf.data.libreport";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    size_t symbolsCount = 39;
    size_t buildIdCount = 32;
    size_t sampleCount = 1000;
    size_t featureCount = 10;

    EXPECT_EQ(stringOut.find("magic: PERFILE2") != std::string::npos, true);
    EXPECT_EQ(SubStringCount(stringOut, "fileid:"), symbolsCount);
    EXPECT_EQ(SubStringCount(stringOut, "buildId:"), buildIdCount);
    EXPECT_EQ(SubStringCount(stringOut, "record sample:"), sampleCount);
    EXPECT_EQ(SubStringCount(stringOut, "feature:"), featureCount);
}

HWTEST_F(SubCommandDumpTest, DumpInputFilename1, TestSize.Level1)
{
    TestDumpCommand("/data/test/resource/testdata/perf.data ", false);
}

HWTEST_F(SubCommandDumpTest, DumpInputFilename2, TestSize.Level1)
{
    TestDumpCommand("-i /data/test/resource/testdata/perf.data ");
}

HWTEST_F(SubCommandDumpTest, DumpInputFilenamErr, TestSize.Level1)
{
    TestDumpCommand("-i whatfile ", false);
}

HWTEST_F(SubCommandDumpTest, DumpHeaderAttrs, TestSize.Level1)
{
    TestDumpCommand("-i /data/test/resource/testdata/perf.data --head ");
}

HWTEST_F(SubCommandDumpTest, DumpData, TestSize.Level1)
{
    TestDumpCommand("-i /data/test/resource/testdata/perf.data -d ");
}

HWTEST_F(SubCommandDumpTest, DumpFeatures, TestSize.Level1)
{
    TestDumpCommand("-i /data/test/resource/testdata/perf.data -f ");
}

HWTEST_F(SubCommandDumpTest, DumpSympath, TestSize.Level1)
{
    TestDumpCommand("-i /data/test/resource/testdata/perf.data --sympath ./ ");
}

HWTEST_F(SubCommandDumpTest, DumpSympathErr, TestSize.Level1)
{
    TestDumpCommand("-i /data/test/resource/testdata/perf.data --sympath where ", false);
}

HWTEST_F(SubCommandDumpTest, DumpExportUserdata0, TestSize.Level1)
{
    TestDumpCommand("-i /data/test/resource/testdata/perf.data --export 0");
}

HWTEST_F(SubCommandDumpTest, DumpExportUserdata1, TestSize.Level1)
{
    TestDumpCommand("-i /data/test/resource/testdata/perf.data --export 1");
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

HWTEST_F(SubCommandDumpTest, DumpCompressDwarfStackTable, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("hiperf_stack_table") != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressDwarfStackid, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("stackid") != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressDwarfTableNums, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("TableNums") != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressDwarfNumNodes, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("numNodes") != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressDwarfStackTableContent, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("hiperf_stack_table content") != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressDwarfTableid, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("tableid") != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressDwarfTableSize, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("tableSize") != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressDwarfKernelUpperBoundary, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string kernelUpperBoundary = "0xffffffffffffff80";
    EXPECT_EQ(stringOut.find(kernelUpperBoundary) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressDwarfKernelLowerBoundary, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string kernelLowerBoundary = "0xfffffffffffffe00";
    EXPECT_EQ(stringOut.find(kernelLowerBoundary) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressDwarfKernelIp, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string kernelIp = "0xffffffc011605050";
    EXPECT_EQ(stringOut.find(kernelIp) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressDwarfUerIpFixZero, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string userIpFixZero = "0xffffffc0100fa3b0";
    EXPECT_EQ(stringOut.find(userIpFixZero) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressDwarfUserIp, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string userIp = "0xf7b43f50";
    EXPECT_EQ(stringOut.find(userIp) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressDwarfCallchain, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string callchain = "callchain nr=25";
    EXPECT_EQ(stringOut.find(callchain) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressDwarfSymbol, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string symbol = "0xffffffc01160072c : __schedule";
    EXPECT_EQ(stringOut.find(symbol) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressFpStackTable, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("hiperf_stack_table") != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressFpStackid, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("stackid") != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressFpTableNums, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("TableNums") != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressFpNumNodes, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("numNodes") != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressFpStackTableContent, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("hiperf_stack_table content") != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressFpTableid, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("tableid") != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressFpTableSize, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("tableSize") != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressFpKernelUpperBoundary, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string kernelUpperBoundary = "0xffffffffffffff80";
    EXPECT_EQ(stringOut.find(kernelUpperBoundary) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressFpKernelLowerBoundary, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string kernelLowerBoundary = "0xfffffffffffffe00";
    EXPECT_EQ(stringOut.find(kernelLowerBoundary) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressFpKernelIp, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string kernelIp = "0xffffffc011605050";
    EXPECT_EQ(stringOut.find(kernelIp) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressFpUerIpFixZero, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string userIpFixZero = "0xffffffc0100fa3b0";
    EXPECT_EQ(stringOut.find(userIpFixZero) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressFpUserIp, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string userIp = "0xf7b43f50";
    EXPECT_EQ(stringOut.find(userIp) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressFpCallchain, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string callchain = "callchain nr=21";
    EXPECT_EQ(stringOut.find(callchain) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpCompressFpSymbol, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.compress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string symbol = "0xffffffc011600984 : schedule";
    EXPECT_EQ(stringOut.find(symbol) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressDwarfStackTable, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("hiperf_stack_table") != std::string::npos, false);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressDwarfStackid, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("stackid") != std::string::npos, false);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressDwarfTableNums, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("TableNums") != std::string::npos, false);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressDwarfNumNodes, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("numNodes") != std::string::npos, false);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressDwarfStackTableContent, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("hiperf_stack_table content") != std::string::npos, false);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressDwarfTableid, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("tableid") != std::string::npos, false);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressDwarfTableSize, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("tableSize") != std::string::npos, false);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressDwarfKernelUpperBoundary, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string kernelUpperBoundary = "0xffffffffffffff80";
    EXPECT_EQ(stringOut.find(kernelUpperBoundary) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressDwarfKernelLowerBoundary, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string kernelLowerBoundary = "0xfffffffffffffe00";
    EXPECT_EQ(stringOut.find(kernelLowerBoundary) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressDwarfKernelIp, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string kernelIp = "0xffffffc011605050";
    EXPECT_EQ(stringOut.find(kernelIp) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressDwarfUerIpFixZero, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string userIpFixZero = "0x00000000f7a70f67";
    EXPECT_EQ(stringOut.find(userIpFixZero) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressDwarfUserIp, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string userIp = "0xf7a70f67";
    EXPECT_EQ(stringOut.find(userIp) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressDwarfCallchain, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string callchain = "callchain nr=20";
    EXPECT_EQ(stringOut.find(callchain) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressDwarfSymbol, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/dwarf.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string symbol = "0xffffffc0102fafa0 : ksys_read";
    EXPECT_EQ(stringOut.find(symbol) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressFpStackTable, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("hiperf_stack_table") != std::string::npos, false);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressFpStackid, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("stackid") != std::string::npos, false);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressFpTableNums, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("TableNums") != std::string::npos, false);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressFpNumNodes, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("numNodes") != std::string::npos, false);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressFpStackTableContent, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("hiperf_stack_table content") != std::string::npos, false);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressFpTableid, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("tableid") != std::string::npos, false);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressFpTableSize, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();

    EXPECT_EQ(stringOut.find("tableSize") != std::string::npos, false);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressFpKernelUpperBoundary, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string kernelUpperBoundary = "0xffffffffffffff80";
    EXPECT_EQ(stringOut.find(kernelUpperBoundary) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressFpKernelLowerBoundary, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string kernelLowerBoundary = "0xfffffffffffffe00";
    EXPECT_EQ(stringOut.find(kernelLowerBoundary) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressFpKernelIp, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string kernelIp = "0xffffffc011605050";
    EXPECT_EQ(stringOut.find(kernelIp) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressFpUerIpFixZero, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string userIpFixZero = "0x00000000f6ebfd24";
    EXPECT_EQ(stringOut.find(userIpFixZero) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressFpUserIp, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string userIp = "0xf6ebfd24";
    EXPECT_EQ(stringOut.find(userIp) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressFpCallchain, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string callchain = "callchain nr=16";
    EXPECT_EQ(stringOut.find(callchain) != std::string::npos, true);
}

HWTEST_F(SubCommandDumpTest, DumpUncompressFpSymbol, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    std::string cmdString = "dump -i /data/test/resource/testdata/fp.uncompress.data";
    EXPECT_EQ(Command::DispatchCommand(cmdString), true);
    std::string stringOut = stdoutRecord.Stop();
    std::string symbol = "0xffffffc0100030c4 : el0_sync_compat";
    EXPECT_EQ(stringOut.find(symbol) != std::string::npos, true);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
