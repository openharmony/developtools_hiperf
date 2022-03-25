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

#include "subcommand_report_test.h"

#include "subcommand.h"
#include "subcommand_report.h"
#include "subcommand_test.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class SubCommandReportTest : public testing::Test {
public:
    const int DEFAULT_RUN_TIMEOUT_MS = 10000;
#if is_ohos
    const std::string RESOURCE_PATH = "/data/test/resource/testdata/";
#else
    const std::string RESOURCE_PATH = "./resource/testdata/";
#endif
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    bool FindExpectStr(const std::string &stringOut, const std::string &counterNames) const;
    bool FindExpectStrList(const std::string &stringOut,
                           const std::vector<std::string> &counterNames) const;
    bool FileCompare(const std::string &stringOut, const std::string &targetFile) const;
    const std::vector<std::string> expectStr_ = {
        "Heating", "count", "comm", "pid", "tid", "dso", "func",
    };
};
void SubCommandReportTest::SetUpTestCase() {}

void SubCommandReportTest::TearDownTestCase() {
}

void SubCommandReportTest::SetUp()
{
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
    ASSERT_EQ(SubCommandReport::RegisterSubCommandReport(), true);
    SubCommand::RegisterSubCommand("TEST_CMD_1", std::make_unique<SubCommandTest>("TEST_CMD_1"));
}

void SubCommandReportTest::TearDown()
{
    SubCommand::ClearSubCommands();
    ASSERT_EQ(SubCommand::GetSubCommands().size(), 0u);
    MemoryHold::Get().Clean();
}

bool SubCommandReportTest::FindExpectStr(const std::string &stringOut,
                                         const std::string &counterNames) const
{
    auto lines = StringSplit(stringOut, "\n");
    for (auto line : lines) {
        if (line.find(counterNames.c_str()) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool SubCommandReportTest::FindExpectStrList(const std::string &stringOut,
                                             const std::vector<std::string> &counterNames) const
{
    for (auto name : counterNames) {
        if (stringOut.find(name) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool SubCommandReportTest::FileCompare(const std::string &stringOut,
                                       const std::string &targetFile) const
{
    std::vector<std::string> actualLines = StringSplit(stringOut, "\n");
    std::vector<std::string> expectLines = StringSplit(ReadFileToString(targetFile), "\n");

    for (int i = 0; i < (int)actualLines.size(); i++) {
        actualLines[i].erase(actualLines[i].find_last_not_of(" ") + 1);
    }

    for (int y = 0; y < (int)expectLines.size(); y++) {
        expectLines[y].erase(expectLines[y].find_last_not_of(" ") + 1);
    }
    auto actual = actualLines.begin();
    auto expect = expectLines.begin();
    EXPECT_EQ(actualLines.size(), expectLines.size());

    while (actual != actualLines.end() and expect != expectLines.end() and !HasFailure()) {
        EXPECT_STREQ(actual->c_str(), expect->c_str());
        actual++;
        expect++;
    }
    return !HasFailure();
}

/**
 * @tc.name: TestParseOption
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestParseOption, TestSize.Level1)
{
    SubCommandReport mSubCommandReport;
    std::vector<std::string> args;
    args = {"-i"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), false);
    args = {"-o"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), false);
    args = {"--diff"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), false);
    args = {"--sort"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), false);
    args = {"--symbol-dir"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), false);
    args = {"--limit-percent"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), false);
    args = {"-s"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), true);
    args = {"--call-stack"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), true);
    args = {"--call-stack-limit-percent"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), false);
    args = {"--comms"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), false);
    args = {"--pids"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), false);
    args = {"--tids"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), false);
    args = {"--dsos"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), false);
    args = {"--funcs"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), false);
    args = {"--from-dsos"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), true);
    args = {"--from-funcs"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), true);
    args = {"--proto"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), true);
    args = {"--json"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), true);
    args = {"--branch"};
    EXPECT_EQ(mSubCommandReport.ParseOption(args), true);
    args.clear();
}

/**
 * @tc.name: TestDumpOptions
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestDumpOptions, TestSize.Level1)
{
    SubCommandReport mSubCommandReport;
    mSubCommandReport.DumpOptions();
    EXPECT_EQ(1, 1);
}

/**
 * @tc.name: TestOnSubCommand_i
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_i, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data"), true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string targetFile = RESOURCE_PATH + "report_test_i.txt";
    EXPECT_EQ(FileCompare(stringOut, targetFile), true);
}

/**
 * @tc.name: TestOnSubCommand_i1
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_i1, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH + "perf1.data"), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::string expectStr =
        "Can not access data file /data/test/resource/testdata/perf1.data";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestOnSubCommand_i2
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_i2, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report " + RESOURCE_PATH + "report_test.data -i"), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::string expectStr = "option -i value missed";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestOnSubCommand_diff
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_diff, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH + "perf1.data --diff " +
                                       RESOURCE_PATH + "report_test.data"),
              false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::string expectStr =
        "Can not access data file /data/test/resource/testdata/perf1.data";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestOnSubCommand_Diff_Same
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_Diff_Same, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();

    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --diff " +
                                       RESOURCE_PATH + "report_test.data"),
              true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string targetFile = RESOURCE_PATH + "report_test_diff.txt";
    EXPECT_EQ(FileCompare(stringOut, targetFile), true);
}

/**
 * @tc.name: TestOnSubCommand_sort
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_sort, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(
        Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --sort pid"),
        true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::string expectStr = "100.00%  271445 1204";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestOnSubCommand_sort1
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_sort1, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(
        Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --sort pid,tid"),
        true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string targetFile = RESOURCE_PATH + "report_test_sort1.txt";
    EXPECT_EQ(FileCompare(stringOut, targetFile), true);
}

/**
 * @tc.name: TestOnSubCommand_sort2
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_sort2, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(
        Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --sort func"),
        true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string targetFile = RESOURCE_PATH + "report_test_sort2.txt";
    EXPECT_EQ(FileCompare(stringOut, targetFile), true);
}

/**
 * @tc.name: TestOnSubCommand_sort3
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_sort3, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH + "perf1.data --sort pid"),
              false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::string expectStr =
        "Can not access data file /data/test/resource/testdata/perf1.data";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestOnSubCommand_sort4
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_sort4, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(
        Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --sort pids"),
        false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::string expectStr = "unknown sort key name 'pids'";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestOnSubCommand_symbol
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_symbol, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(
        Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --symbol-dir ./"),
        true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string targetFile = RESOURCE_PATH + "report_test_symbol.txt";
    EXPECT_EQ(FileCompare(stringOut, targetFile), true);
}

/**
 * @tc.name: TestOnSubCommand_limit
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_limit, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH +
                                       "report_test.data --limit-percent 5"),
              true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string targetFile = RESOURCE_PATH + "report_test_limit.txt";
    EXPECT_EQ(FileCompare(stringOut, targetFile), true);
}

/**
 * @tc.name: TestOnSubCommand_limit1
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_limit1, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH +
                                       "report_test.data --limit-percent 1"),
              true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string targetFile = RESOURCE_PATH + "report_test_limit1.txt";
    EXPECT_EQ(FileCompare(stringOut, targetFile), true);
}

/**
 * @tc.name: TestOnSubCommand_limit2
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_limit2, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH +
                                       "report_test.data --limit-percent 99"),
              true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::string expectStr = "kernel.kallsyms";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), false);
}

/**
 * @tc.name: TestOnSubCommand_limit3
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_limit3, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH +
                                       "report_test.data --limit-percent -1"),
              false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::string expectStr = "head limit error. must in (0 <= limit < 100)";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestOnSubCommand_limit4
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_limit4, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH +
                                       "report_test.data --limit-percent 101"),
              false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::string expectStr = "head limit error. must in (0 <= limit < 100)";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestOnSubCommand_callstack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_callstack, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(
        Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --call-stack"),
        true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string targetFile = RESOURCE_PATH + "report_test_callstack.txt";
    EXPECT_EQ(FileCompare(stringOut, targetFile), true);
}

/**
 * @tc.name: TestOnSubCommand_comms
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_comms, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(
        Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --comms hiperf"),
        true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string targetFile = RESOURCE_PATH + "report_test_i.txt";
    EXPECT_EQ(FileCompare(stringOut, targetFile), true);
}

/**
 * @tc.name: TestOnSubCommand_pids
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_pids, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(
        Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --pids 1204"),
        true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string targetFile = RESOURCE_PATH + "report_test_i.txt";
    EXPECT_EQ(FileCompare(stringOut, targetFile), true);
}

/**
 * @tc.name: TestOnSubCommand_pids1
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_pids1, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(
        Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --pids 485"),
        true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string targetFile = RESOURCE_PATH + "report_test_tids1.txt";
    EXPECT_EQ(FileCompare(stringOut, targetFile), true);
}

/**
 * @tc.name: TestOnSubCommand_pids2
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_pids2, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(
        Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --pids 11111"),
        true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string targetFile = RESOURCE_PATH + "report_test_tids1.txt";
    EXPECT_EQ(FileCompare(stringOut, targetFile), true);
}

/**
 * @tc.name: TestOnSubCommand_pids3
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_pids3, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(
        Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --pids -106"),
        false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::string expectStr = "error number for pid";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestOnSubCommand_tids
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_tids, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(
        Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --tids 1205"),
        true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string targetFile = RESOURCE_PATH + "report_test_tids.txt";
    EXPECT_EQ(FileCompare(stringOut, targetFile), true);
}

/**
 * @tc.name: TestOnSubCommand_tids1
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_tids1, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(
        Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --tids 905"),
        true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string targetFile = RESOURCE_PATH + "report_test_tids1.txt";
    EXPECT_EQ(FileCompare(stringOut, targetFile), true);
}

/**
 * @tc.name: TestOnSubCommand_tids2
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_tids2, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(
        Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --tids 11111"),
        true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string targetFile = RESOURCE_PATH + "report_test_tids1.txt";
    EXPECT_EQ(FileCompare(stringOut, targetFile), true);
}

/**
 * @tc.name: TestOnSubCommand_tids3
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_tids3, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(
        Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --tids -109"),
        false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::string expectStr = "error number for tid";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestOnSubCommand_dsos
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_dsos, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH +
                                       "report_test.data --dsos [kernel.kallsyms]"),
              true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string targetFile = RESOURCE_PATH + "report_test_dsos.txt";
    EXPECT_EQ(FileCompare(stringOut, targetFile), true);
}

/**
 * @tc.name: TestOnSubCommand_dsos1
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_dsos1, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH +
                                       "report_test.data --dsos /system/lib/libcamera.so"),
              true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string targetFile = RESOURCE_PATH + "report_test_tids1.txt";
    EXPECT_EQ(FileCompare(stringOut, targetFile), true);
}

/**
 * @tc.name: TestOnSubCommand_dsos2
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_dsos2, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --dso"),
              false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::string expectStr = "unknown option";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestOnSubCommand_funcs
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_funcs, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH +
                                       "report_test.data --funcs finish_task_switch"),
              true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    std::string targetFile = RESOURCE_PATH + "report_test_funcs.txt";
    EXPECT_EQ(FileCompare(stringOut, targetFile), true);
}

/**
 * @tc.name: TestOnSubCommand_funcs1
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_funcs1, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --func"),
              false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::string expectStr = "unknown option";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestOnSubCommand_json
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_json, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --json"),
              true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::string expectStr = "report will save at 'perf.json'";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestOnSubCommand_json1
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_json1, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH + "perf1.data --json"), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::string expectStr =
        "Can not access data file /data/test/resource/testdata/perf1.data";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestOnSubCommand_proto
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_proto, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data --proto"),
              true);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::string expectStr = "create proto buf file succeed";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestOnSubCommand_proto1
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOnSubCommand_proto1, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    const auto startTime = chrono::steady_clock::now();
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH + "perf1.data --proto"), false);
    const auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        chrono::steady_clock::now() - startTime);
    EXPECT_LE(costMs.count(), DEFAULT_RUN_TIMEOUT_MS);

    std::string stringOut = stdoutRecord.Stop();
    if (HasFailure()) {
        printf("output:\n%s", stringOut.c_str());
    }
    const std::string expectStr =
        "Can not access data file /data/test/resource/testdata/perf1.data";
    EXPECT_EQ(FindExpectStr(stringOut, expectStr), true);
}

/**
 * @tc.name: TestLoadPerfData
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestLoadPerfData, TestSize.Level1)
{
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data -o " +
                                       RESOURCE_PATH + "perfnew2.data"),
              true);
    EXPECT_EQ(IsPath(RESOURCE_PATH + "report_test.data"), true);
}

/**
 * @tc.name: TestOutputReport
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestOutputReport, TestSize.Level1)
{
    EXPECT_EQ(Command::DispatchCommand("report -i " + RESOURCE_PATH + "report_test.data -o " +
                                       RESOURCE_PATH + "perfnew2.data"),
              true);
    EXPECT_EQ(IsPath(RESOURCE_PATH + "perfnew2.data"), true);
}

/**
 * @tc.name: TestVerifyOption
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestVerifyOption, TestSize.Level1)
{
    SubCommandReport mSubCommandReport;
    std::string recordFile;
    std::vector<std::string> args;
    args = {"report", "-i", RESOURCE_PATH + "/report_test.data", "--limit-percent", "60"};
    ASSERT_EQ(
        Option::GetOptionValue(args, "--limit-percent", mSubCommandReport.reportOption_.heatLimit_),
        true);
    ASSERT_EQ(Option::GetOptionValue(args, "-i", recordFile), true);

    EXPECT_EQ(mSubCommandReport.VerifyOption(), true);

    mSubCommandReport.reportOption_.heatLimit_ = 101.0;
    EXPECT_EQ(mSubCommandReport.VerifyOption(), false);
}

/**
 * @tc.name: TestVerifyDisplayOption
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(SubCommandReportTest, TestVerifyDisplayOption, TestSize.Level1)
{
    SubCommandReport mSubCommandReport;
    std::string recordFile;
    std::vector<std::string> args;
    args = {"report", "-i", RESOURCE_PATH + "report_test.data ", "--pids", "-1"};
    ASSERT_EQ(Option::GetOptionValue(args, "--pids", mSubCommandReport.reportOption_.displayPids_),
              true);
    ASSERT_EQ(Option::GetOptionValue(args, "-i", recordFile), true);
    EXPECT_EQ(mSubCommandReport.VerifyDisplayOption(), false);

    mSubCommandReport.reportOption_.displayPids_.clear();
    args = {"report -i " + RESOURCE_PATH + "report_test.data --pids "};
    EXPECT_EQ(mSubCommandReport.VerifyDisplayOption(), true);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
