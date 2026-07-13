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

#include "utilities_test.h"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <thread>
#include <unistd.h>
#include "cJSON.h"
#include "ipc_utilities.h"
#include "test_utilities.h"
#include "utilities.h"

using namespace testing::ext;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class UtilitiesTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void TestThread();
    void StartThreads(const size_t count);
    void ExitThreads();
    bool exitThreads_ = true;
    std::vector<pid_t> tids_;
    std::vector<std::thread> threads_;
    const int sleepTime_ = {500};
};

void UtilitiesTest::SetUpTestCase()
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

void UtilitiesTest::TearDownTestCase()
{
    if (system("kill -9 `pidof hiperf_test_demo`") != 0) {
        GTEST_LOG_(ERROR) << "kill hiperf_test_demo failed.";
    } else {
        GTEST_LOG_(INFO) << "kill hiperf_test_demo success.";
    }
}

void UtilitiesTest::SetUp() {}

void UtilitiesTest::TearDown() {}

void UtilitiesTest::TestThread()
{
    printf("threads %ld create\n", gettid());
    int ret = fflush(nullptr);
    if (ret == EOF) {
        printf("fflush() error\n");
    }

    tids_.emplace_back(gettid());
    while (!exitThreads_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime_));
    }
    printf("threads %ld exited\n", gettid());
    ret = fflush(nullptr);
    if (ret == EOF) {
        printf("fflush() error\n");
    }
}

void UtilitiesTest::StartThreads(const size_t count)
{
    printf("create %zu threads\n", count);
    int ret = fflush(nullptr);
    if (ret == EOF) {
        printf("fflush() error\n");
    }

    exitThreads_ = false;
    size_t created = 0;
    while (created < count) {
        threads_.emplace_back(std::thread(&UtilitiesTest::TestThread, this));
        created++;
    }
    while (tids_.size() < count) {
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime_));
    }
    printf("all threads created\n");
    ret = fflush(nullptr);
    if (ret == EOF) {
        printf("fflush() error\n");
    }
}

void UtilitiesTest::ExitThreads()
{
    printf("wait all threads exit\n");
    exitThreads_ = true;
    for (std::thread &t : this->threads_) {
        t.join();
    }
    tids_.clear();
    printf("all threads exited\n");
}

pid_t GetPidFromApp(const std::string appPackage)
{
    pid_t res {-1};
    const std::string basePath {"/proc/"};
    const std::string cmdline {"/cmdline"};
    std::vector<std::string> subDirs = GetSubDirs(basePath);
    for (const auto &subDir : subDirs) {
        if (!IsDigits(subDir)) {
            continue;
        }
        std::string fileName {basePath + subDir + cmdline};
        if (IsSameCommand(ReadFileToString(fileName), appPackage)) {
            res = std::stoul(subDir, nullptr);
            return res;
        }
    }
    return res;
}

/**
 * @tc.name: StringReplace
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringReplace, TestSize.Level2)
{
    const std::string testString = "1234567890";
    EXPECT_EQ(StringReplace(testString, "1", ""), "234567890");
    EXPECT_EQ(StringReplace(testString, "2", ""), "134567890");
    EXPECT_EQ(StringReplace(testString, "0", ""), "123456789");
    EXPECT_EQ(StringReplace(testString, "1", "0"), "0234567890");
    EXPECT_EQ(StringReplace(testString, "0", "1"), "1234567891");
    EXPECT_EQ(StringReplace(testString, "123", "1"), "14567890");
    EXPECT_EQ(StringReplace(testString, "890", "1"), "12345671");
    EXPECT_EQ(StringReplace(testString, "456", "1"), "12317890");
    EXPECT_EQ(StringReplace(testString, "123", "321"), "3214567890");
    EXPECT_EQ(StringReplace(testString, "890", "098"), "1234567098");
}

/**
 * @tc.name: StringSplit
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringSplit, TestSize.Level0)
{
    std::string testString = "1,23,456,7890,";
    EXPECT_EQ(StringSplit(testString, "1").size(), 1u);
    EXPECT_EQ(StringSplit(testString, "2").size(), 2u);
    EXPECT_EQ(StringSplit(testString, ",").size(), 4u);
    EXPECT_EQ(StringSplit(testString, "456").size(), 2u);
    EXPECT_EQ(StringSplit(testString, "000").size(), 1u);
    EXPECT_EQ(StringSplit(testString, "").size(), 1u);

    EXPECT_EQ(StringSplit(testString = "").size(), 0u);
    EXPECT_EQ(StringSplit(testString = "1,2,3").size(), 3u);
    EXPECT_EQ(StringSplit(testString = "1,2,3,,,").size(), 3u);
}

/**
 * @tc.name: SubStringCount
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, SubStringCount, TestSize.Level2)
{
    std::string testString = "1,22,333,4444,";
    EXPECT_EQ(SubStringCount(testString, ""), testString.size());
    EXPECT_EQ(SubStringCount(testString, "1"), 1u);
    EXPECT_EQ(SubStringCount(testString, "2"), 2u);
    EXPECT_EQ(SubStringCount(testString, "3"), 3u);
    EXPECT_EQ(SubStringCount(testString, "4"), 4u);

    EXPECT_EQ(SubStringCount(testString, "22"), 1u);
    EXPECT_EQ(SubStringCount(testString, "33"), 1u);
    EXPECT_EQ(SubStringCount(testString, "333"), 1u);
    EXPECT_EQ(SubStringCount(testString, "4444"), 1u);
    EXPECT_EQ(SubStringCount(testString, "444"), 1u);
    EXPECT_EQ(SubStringCount(testString, "44"), 2u);
}

/**
 * @tc.name: StringEndsWith
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringEndsWith, TestSize.Level2)
{
    std::string testString = "1,22,333,4444,";
    EXPECT_EQ(StringEndsWith(testString, ""), true);
    EXPECT_EQ(StringEndsWith(testString, "1"), false);
    EXPECT_EQ(StringEndsWith(testString, ","), true);

    EXPECT_EQ(StringEndsWith("", ""), true);
    EXPECT_EQ(StringEndsWith("", "1"), false);
    EXPECT_EQ(StringEndsWith("", ","), false);
}

/**
 * @tc.name: StringStartsWith
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringStartsWith, TestSize.Level3)
{
    std::string testString = "1,22,333,4444,";
    EXPECT_EQ(StringStartsWith(testString, ""), true);
    EXPECT_EQ(StringStartsWith(testString, "1"), true);
    EXPECT_EQ(StringStartsWith(testString, ","), false);
    EXPECT_EQ(StringStartsWith(testString, testString + "1"), false);

    EXPECT_EQ(StringStartsWith("", ""), true);
    EXPECT_EQ(StringStartsWith("", "1"), false);
    EXPECT_EQ(StringStartsWith("", ","), false);
}

/**
 * @tc.name: VectorToString
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, VectorToString, TestSize.Level1)
{
    EXPECT_EQ(VectorToString<std::string>({}), "<empty>");
    EXPECT_EQ(VectorToString<std::string>({"a", "b", "c"}), "a,b,c");
    EXPECT_EQ(VectorToString<std::string>({"a"}), "a");
    EXPECT_EQ(VectorToString<std::vector<std::string>>({
                  {},
              }),
              "[<empty>]");
    EXPECT_EQ(VectorToString<std::vector<std::string>>({
                  {"a", "b", "c"},
              }),
              "[a,b,c]");
    EXPECT_EQ(VectorToString<std::vector<std::string>>({
                  {"a", "b", "c"},
                  {"a", "b", "c"},
                  {"a", "b", "c"},
              }),
              "[a,b,c],[a,b,c],[a,b,c]");

    EXPECT_EQ(VectorToString<int>({}), "<empty>");
    EXPECT_EQ(VectorToString<int>({1}), "1");
    EXPECT_EQ(VectorToString<int>({1, 2, 3}), "1,2,3");

    EXPECT_EQ(VectorToString<float>({}), "<empty>");
    EXPECT_EQ(VectorToString<float>({1.0, 2.0, 3.0}), "1.000000,2.000000,3.000000");
}

/**
 * @tc.name: SetToString
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, SetToString, TestSize.Level2)
{
    EXPECT_EQ(SetToString<std::string>({}), "<empty>");
    EXPECT_EQ(SetToString<std::string>({"a"}), "a");

    EXPECT_EQ(SetToString<int>({}), "<empty>");
    EXPECT_EQ(SetToString<int>({1}), "1");
    EXPECT_EQ(SetToString<int>({1, 2, 3}).size(), 5);
    EXPECT_EQ(SetToString<std::string>({"a", "b", "c"}).size(), 5);

    EXPECT_EQ(SetToString<float>({}), "<empty>");
}

/**
 * @tc.name: BufferToHexString
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, BufferToHexString, TestSize.Level2)
{
    const unsigned char buf[] = "12345678";

    EXPECT_STREQ(BufferToHexString(buf, 0).c_str(), "0:");
    EXPECT_STREQ(BufferToHexString(buf, 1).c_str(), "1: 0x31");
    EXPECT_STREQ(BufferToHexString(buf, 4).c_str(), "4: 0x31 0x32 0x33 0x34");
    EXPECT_STREQ(BufferToHexString(buf, 5).c_str(), "5: 0x31 0x32 0x33 0x34 0x35");
    EXPECT_STREQ(BufferToHexString(buf, 8).c_str(), "8: 0x31 0x32 0x33 0x34 0x35 0x36 0x37 0x38");

    const std::vector<unsigned char> vbuf(buf, buf + sizeof(buf) - 1u);

    EXPECT_STREQ(BufferToHexString(vbuf).c_str(), "8: 0x31 0x32 0x33 0x34 0x35 0x36 0x37 0x38");

    const unsigned char buf2[] = "1234567812345678";
    EXPECT_STREQ(BufferToHexString(buf2, 0).c_str(), "0:");
    EXPECT_STREQ(BufferToHexString(buf2, 1).c_str(), "1: 0x31");
    EXPECT_STREQ(BufferToHexString(buf2, 4).c_str(), "4: 0x31 0x32 0x33 0x34");
    EXPECT_STREQ(BufferToHexString(buf2, 5).c_str(), "5: 0x31 0x32 0x33 0x34 0x35");
    EXPECT_STREQ(BufferToHexString(buf2, 8).c_str(), "8: 0x31 0x32 0x33 0x34 0x35 0x36 0x37 0x38");
    EXPECT_STREQ(BufferToHexString(buf2, 9).c_str(),
                 "9: 0x31 0x32 0x33 0x34 0x35 0x36 0x37 0x38 0x31");
    EXPECT_STREQ(
        BufferToHexString(buf2, 16).c_str(),
        "16: 0x31 0x32 0x33 0x34 0x35 0x36 0x37 0x38 0x31 0x32 0x33 0x34 0x35 0x36 0x37 0x38");

    const std::vector<unsigned char> vbuf2(buf2, buf2 + sizeof(buf2) - 1u);
    EXPECT_STREQ(
        BufferToHexString(vbuf2).c_str(),
        "16: 0x31 0x32 0x33 0x34 0x35 0x36 0x37 0x38 0x31 0x32 0x33 0x34 0x35 0x36 0x37 0x38");
}

/**
 * @tc.name: HexDump
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, HexDump, TestSize.Level2)
{
    const unsigned char buf[] = "12345678";
    const void *vbuf = static_cast<const void *>(buf);
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH, true);

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    EXPECT_EQ(HexDump(vbuf, 0), true);
    EXPECT_EQ(HexDump(vbuf, 1), true);
    EXPECT_EQ(HexDump(vbuf, 4), true);
    EXPECT_EQ(HexDump(vbuf, 5), true);
    EXPECT_EQ(HexDump(vbuf, 8), true);
    stdoutRecord.Stop();
}

/**
 * @tc.name: StringTrim
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringTrim, TestSize.Level3)
{
    std::string test;
    EXPECT_STREQ(StringTrim(test = " a ").c_str(), "a");
    EXPECT_STREQ(StringTrim(test = " a").c_str(), "a");
    EXPECT_STREQ(StringTrim(test = "a ").c_str(), "a");
    EXPECT_STREQ(StringTrim(test = " a1a ").c_str(), "a1a");
    EXPECT_STREQ(StringTrim(test = " a1a").c_str(), "a1a");
    EXPECT_STREQ(StringTrim(test = "a1a ").c_str(), "a1a");
    EXPECT_STREQ(StringTrim(test = "   a1a   ").c_str(), "a1a");
    EXPECT_STREQ(StringTrim(test = "   a1a").c_str(), "a1a");
    EXPECT_STREQ(StringTrim(test = "a1a   ").c_str(), "a1a");
}

/**
 * @tc.name: RecordStdout
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, RecordStdout, TestSize.Level2)
{
    StdoutRecord stdoutRecord;

    ASSERT_EQ(stdoutRecord.Start(), true);
    printf("line1: abc\n");
    printf("line2: def\n");
    printf("line3: ghi\n");
    printf("\n");
    std::string out = stdoutRecord.Stop();

    printf("stdoutRecord:\n%s", out.c_str());
    EXPECT_EQ(out.empty(), false);
    EXPECT_NE(out.find("line1:"), std::string::npos);
    EXPECT_NE(out.find("line2:"), std::string::npos);
    EXPECT_NE(out.find("line3:"), std::string::npos);
    EXPECT_EQ(out.find("line4:"), std::string::npos);
}

/**
 * @tc.name: IsDigits
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsDigits, TestSize.Level1)
{
    EXPECT_EQ(IsDigits(""), false);
    EXPECT_EQ(IsDigits("1"), true);
    EXPECT_EQ(IsDigits("12"), true);
    EXPECT_EQ(IsDigits("1a"), false);
    EXPECT_EQ(IsDigits("a1"), false);
    EXPECT_EQ(IsDigits("1a2"), false);
    EXPECT_EQ(IsDigits("a1b"), false);
    EXPECT_EQ(IsDigits("_1"), false);
    EXPECT_EQ(IsDigits("1_"), false);
}

/**
 * @tc.name: IsHexxDigits
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsHexxDigits, TestSize.Level2)
{
    EXPECT_EQ(IsHexDigits(""), false);
    EXPECT_EQ(IsHexDigits("1"), true);
    EXPECT_EQ(IsHexDigits("12"), true);
    EXPECT_EQ(IsHexDigits("1a"), true);
    EXPECT_EQ(IsHexDigits("f1"), true);
    EXPECT_EQ(IsHexDigits("1f2"), true);
    EXPECT_EQ(IsHexDigits("a1f"), true);
    EXPECT_EQ(IsHexDigits("g1"), false);
    EXPECT_EQ(IsHexDigits("1g"), false);
    EXPECT_EQ(IsHexDigits("_1"), false);
    EXPECT_EQ(IsHexDigits("1_"), false);
}

/**
 * @tc.name: IsSameCommand
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsSameCommand, TestSize.Level2)
{
    EXPECT_EQ(IsSameCommand("", ""), false);
    EXPECT_EQ(IsSameCommand("a", ""), false);
    EXPECT_EQ(IsSameCommand("", "b"), false);
    EXPECT_EQ(IsSameCommand("1", "2"), false);
    EXPECT_EQ(IsSameCommand("2", "1"), false);
    EXPECT_EQ(IsSameCommand("1", "1"), true);
    EXPECT_EQ(IsSameCommand("a", "a"), true);
    EXPECT_EQ(IsSameCommand("a:1", "a:2"), false);
}

/**
 * @tc.name: CompressFile
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CompressFile, TestSize.Level1)
{
    std::string srcPath = "./resource/testdata/elf_test_stripped_broken";
    std::string destPath = "./test.gz";
    EXPECT_EQ(CompressFile(srcPath, destPath), true);
    srcPath = "";
    EXPECT_EQ(CompressFile(srcPath, destPath), false);
    srcPath = "./resource/testdata/elf_test_stripped_broken";
    destPath = "";
    EXPECT_EQ(CompressFile(srcPath, destPath), false);
}

/**
 * @tc.name: UncompressFile
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, UncompressFile, TestSize.Level2)
{
    std::string gzipPath = "./test.gz";
    std::string dataPath = "./test";
    EXPECT_EQ(UncompressFile(gzipPath, dataPath), true);
    gzipPath = "./test.gz";
    dataPath = "";
    EXPECT_EQ(UncompressFile(gzipPath, dataPath), false);
    gzipPath = "";
    dataPath = "./resource/testdata/elf_test_stripped_broken";
    EXPECT_EQ(UncompressFile(gzipPath, dataPath), false);
}

/**
 * @tc.name: StringPrintf
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringPrintf, TestSize.Level1)
{
    EXPECT_STREQ(StringPrintf("").c_str(), "");
    EXPECT_STREQ(StringPrintf("123").c_str(), "123");
    EXPECT_STREQ(StringPrintf("%d%s%c", 1, "2", 'c').c_str(), "12c");
    EXPECT_STREQ(StringPrintf("%d%s%c\t\n", 1, "2", 'c').c_str(), "12c\t\n");

    char format[PATH_MAX + 1];
    std::fill(format, format + PATH_MAX, ' ');
    format[PATH_MAX] = 0;
    EXPECT_STRNE(StringPrintf(format).c_str(), format);
    format[PATH_MAX - 1] = 0;
    EXPECT_STREQ(StringPrintf(format).c_str(), format);
    EXPECT_STREQ(StringPrintf(nullptr).c_str(), "");
}

/**
 * @tc.name: GetEntriesInDir
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetEntriesInDir, TestSize.Level1)
{
    std::vector<std::string> dirFileInfo;
    dirFileInfo = GetEntriesInDir("./");
    EXPECT_GE(dirFileInfo.size(), 0u);
}

/**
 * @tc.name: GetSubDirs
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetSubDirs, TestSize.Level1)
{
    std::vector<std::string> subDirFileInfo;
    subDirFileInfo = GetSubDirs("../");
    EXPECT_GE(subDirFileInfo.size(), 0u);
}

/**
 * @tc.name: IsDir
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsDir, TestSize.Level1)
{
    bool ret = IsDir("../");
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: IsPath
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsPath, TestSize.Level1)
{
    bool ret = IsPath("./");
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: PlatformPathConvert
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, PlatformPathConvert, TestSize.Level1)
{
    EXPECT_GE(PlatformPathConvert("./").length(), 0u);
}

/**
 * @tc.name: ToHex
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, ToHex, TestSize.Level2)
{
    unsigned char hVal = 'G';
    EXPECT_STREQ(ToHex(hVal, 1, true).c_str(), "0x47");
}

/**
 * @tc.name: ToHex
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CopyFromBufferAndMove, TestSize.Level1)
{
    unsigned char *buffer = new unsigned char[4];
    buffer[0] = '1';
    buffer[1] = '2';
    buffer[2] = '3';
    buffer[3] = '4';
    int *dest = new int;
    const unsigned char *srcStr = buffer;
    EXPECT_EQ(CopyFromBufferAndMove(srcStr, dest, 4), 4u);
}

/**
 * @tc.name: ReadIntFromProcFile01
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, ReadIntFromProcFile01, TestSize.Level1)
{
    std::string strPath = "/proc/sys/kernel/perf_cpu_time_max_percent";
    int strLen = 0;
    EXPECT_EQ(ReadIntFromProcFile(strPath, strLen), true);
    ASSERT_GT(strLen, 0);
}

/**
 * @tc.name: ReadIntFromProcFile02
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, ReadIntFromProcFile02, TestSize.Level1)
{
    std::string strPath = "/proc/sys/kernel/perf_event_max_sample_rate";
    int strLen = 0;
    EXPECT_EQ(ReadIntFromProcFile(strPath, strLen), true);
    ASSERT_GT(strLen, 0);
}

/**
 * @tc.name: ReadIntFromProcFile03
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, ReadIntFromProcFile03, TestSize.Level2)
{
    std::string strPath = "/sys/kernel/tracing/saved_cmdlines_size";
    int strLen = 0;
    EXPECT_EQ(ReadIntFromProcFile(strPath, strLen), true);
    ASSERT_GT(strLen, 0);
}

/**
 * @tc.name: WriteIntToProcFile
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, WriteIntToProcFile, TestSize.Level2)
{
    std::string strPath = "./hiperf_log.txt";
    int strVal = 0;
    EXPECT_EQ(WriteIntToProcFile(strPath, strVal), true);
}

/**
 * @tc.name: ReadFileToString
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, ReadFileToString, TestSize.Level1)
{
    std::string strPath = "./hiperf_log.txt";
    EXPECT_NE(ReadFileToString(strPath).length(), 0u);
}

/**
 * @tc.name: WriteStringToFile
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, WriteStringToFile, TestSize.Level1)
{
    std::string strPath = "./hiperf_log.txt";
    std::string content = "0";
    EXPECT_EQ(WriteStringToFile(strPath, content), true);
}

/**
 * @tc.name: Percentage
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, Percentage, TestSize.Level2)
{
    EXPECT_EQ(Percentage(99, 100), 99);
}

/**
 * @tc.name: IsRoot
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsRoot, TestSize.Level1)
{
    bool isRoot = true;
#if is_linux || is_ohos
    isRoot = (getuid() == 0);
#endif
    EXPECT_EQ(IsRoot(), isRoot);
}

/**
 * @tc.name: PowerOfTwo
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, PowerOfTwo, TestSize.Level1)
{
    EXPECT_EQ(PowerOfTwo(1), true);
}

/**
 * @tc.name: GetSubthreadIDs
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetSubthreadIDs, TestSize.Level1)
{
    StartThreads(1);
    std::vector<pid_t> tids = GetSubthreadIDs(getpid());
    if (!HasFailure()) {
        for (pid_t tid : tids_) {
            EXPECT_NE(find(tids.begin(), tids.end(), tid), tids.end());
        }
    }
    ExitThreads();
}

/**
 * @tc.name: IsBeta
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsBeta, TestSize.Level2)
{
    EXPECT_EQ(IsBeta(), true);
}

/**
 * @tc.name: CanonicalizeSpecPath
 * @tc.desc: Test CanonicalizeSpecPath function with various path patterns
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CanonicalizeSpecPath, TestSize.Level0)
{
    EXPECT_EQ(CanonicalizeSpecPath(nullptr), "");
    EXPECT_EQ(CanonicalizeSpecPath(""), "");
    EXPECT_EQ(CanonicalizeSpecPath("/data/local/tmp/test/../test.txt"), "");
    EXPECT_EQ(CanonicalizeSpecPath("/data/local/tmp/nonexistent.txt"), "/data/local/tmp/nonexistent.txt");
    const char* sandboxPath = "/proc/123/data/storage/el2/base/test.txt";
    EXPECT_EQ(CanonicalizeSpecPath(sandboxPath), sandboxPath);
    string largePath = "./";
    for (int i = 0; i < 512; i++) { // 512: loop size
        largePath += "testpath";
    }
    largePath += ".txt";
    EXPECT_EQ(CanonicalizeSpecPath(largePath.c_str()), "");
}

/**
 * @tc.name: RecordStdoutInit
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, RecordStdoutInit, TestSize.Level1)
{
    StdoutRecord stdnormaloutRecord("/data/local/tmp/hiperf_log.txt", "rw");
    (void)stdnormaloutRecord.Stop();
    StdoutRecord stdexceptoutRecord("/data/local/tmp/../hiperf_log.txt");
    EXPECT_EQ(stdexceptoutRecord.Stop().empty(), true);
}

/**
 * @tc.name: CollectPidsByAppname1
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CollectPidsByAppname1, TestSize.Level1)
{
    pid_t pid = getpid();
    std::string name = GetProcessName(pid);
    size_t pos = name.find_last_of("/");
    if (pos != std::string::npos) {
        name = name.substr(pos + 1);
    }
    std::set<pid_t> pids = {};
    CollectPidsByAppname(pids, name);
    ASSERT_GE(pids.size(), 1u);
    bool get = false;
    for (pid_t id : pids) {
        if (pid == id) {
            get = true;
            break;
        }
    }
    EXPECT_EQ(get, true);
}

/**
 * @tc.name: CollectPidsByAppname2
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CollectPidsByAppname2, TestSize.Level1)
{
    pid_t pid = getpid();
    std::string name = GetProcessName(pid);
    size_t pos = name.find_last_of("/");
    if (pos != std::string::npos) {
        name = name.substr(pos + 1);
    }
    std::vector<std::string> names = { name };
    std::set<pid_t> pids = {};
    CollectPidsByAppname(pids, names);
    ASSERT_GE(pids.size(), 1u);
    bool get = false;
    for (pid_t id : pids) {
        if (pid == id) {
            get = true;
            break;
        }
    }
    EXPECT_EQ(get, true);
}

/**
 * @tc.name: CheckOutOfRange1
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CheckOutOfRange1, TestSize.Level0)
{
    static constexpr int min = 10;
    static constexpr int max = 20;
    static constexpr int val = 8;
    EXPECT_EQ(CheckOutOfRange<int>(val, min, max), true);
}

/**
 * @tc.name: CheckOutOfRange2
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CheckOutOfRange2, TestSize.Level3)
{
    static constexpr int min = 10;
    static constexpr int max = 20;
    static constexpr int val = 10;
    EXPECT_EQ(CheckOutOfRange<int>(val, min, max), false);
}

/**
 * @tc.name: CheckOutOfRange3
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CheckOutOfRange3, TestSize.Level3)
{
    static constexpr int min = 10;
    static constexpr int max = 20;
    static constexpr int val = 15;
    EXPECT_EQ(CheckOutOfRange<int>(val, min, max), false);
}

/**
 * @tc.name: CheckOutOfRange4
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CheckOutOfRange4, TestSize.Level3)
{
    static constexpr int min = 10;
    static constexpr int max = 20;
    static constexpr int val = 20;
    EXPECT_EQ(CheckOutOfRange<int>(val, min, max), false);
}

/**
 * @tc.name: CheckOutOfRange5
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CheckOutOfRange5, TestSize.Level1)
{
    static constexpr int min = 10;
    static constexpr int max = 20;
    static constexpr int val = 25;
    EXPECT_EQ(CheckOutOfRange<int>(val, min, max), true);
}

/**
 * @tc.name: IsSameCommand
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsSameCommand2, TestSize.Level2)
{
    std::vector<std::string> v = {""};
    EXPECT_EQ(IsSameCommand("", v), false);
    EXPECT_EQ(IsSameCommand("a", v), false);

    v = {"", "a"};
    EXPECT_EQ(IsSameCommand("a", v), true);
}

/**
 * @tc.name: IsArkJsFile
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsArkJsFile, TestSize.Level2)
{
    EXPECT_EQ(IsArkJsFile("test.hap"), true);
    EXPECT_EQ(IsArkJsFile("[anon:ArkTS Code:test.so/buffer.js]"), true);
    EXPECT_EQ(IsArkJsFile("test.hsp"), true);
    EXPECT_EQ(IsArkJsFile("test.abc"), true);
    EXPECT_EQ(IsArkJsFile("test.hqf"), true);
    EXPECT_EQ(IsArkJsFile("test.so"), false);
}

/**
 * @tc.name: IsDirectoryExists
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsDirectoryExists, TestSize.Level1)
{
    EXPECT_EQ(IsDirectoryExists("/data/local/tmp"), true);
}

/**
 * @tc.name: CreateDirectory
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CreateDirectory, TestSize.Level1)
{
    std::string file = "/data/local/tmp/hiperf_test";
    EXPECT_TRUE(CreateDirectory(file, HIPERF_FILE_PERM_770));
    rmdir(file.c_str());
}

/**
 * @tc.name: IsValidOutPath
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsValidOutPath, TestSize.Level1)
{
    std::string file = "/data/local/tmp/perf.data";
    EXPECT_TRUE(IsValidOutPath(file));
}

/**
 * @tc.name: IsValidOutPathErr
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsValidOutPathErr, TestSize.Level2)
{
    std::string file = "/data/log/hiperflog/perf.data";
    EXPECT_FALSE(IsValidOutPath(file));
}

/**
 * @tc.name: CheckHiperflogGroup
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CheckHiperflogGroup, TestSize.Level2)
{
    std::string filePath = "/data/log/hiperflog";
    struct stat statbuf;
    EXPECT_EQ(stat(filePath.c_str(), &statbuf), 0);
    gid_t logGid = 1007;
    EXPECT_EQ(statbuf.st_gid, logGid);
}

/**
 * @tc.name: StringToIntTest
 * @tc.desc: Test StringToUint64 function.
 * @tc.type: FUNC
*/
HWTEST_F(UtilitiesTest, StringToIntTest, TestSize.Level2)
{
    std::string traceParamsStr = "1234567890";
    uint64_t paramsUint64 = 0;
    EXPECT_TRUE(StringToUint64(traceParamsStr, paramsUint64));
    EXPECT_EQ(paramsUint64, 1234567890); // 1234567890: test value
    traceParamsStr = "18446744073709551615";
    EXPECT_TRUE(StringToUint64(traceParamsStr, paramsUint64));
    EXPECT_EQ(paramsUint64, ULLONG_MAX);
}

/**
 * @tc.name: StringToUint64ErrorTest
 * @tc.desc: Test StringToUint64 function.
 * @tc.type: FUNC
*/
HWTEST_F(UtilitiesTest, StringToUint64ErrorTest, TestSize.Level2)
{
    std::string traceParamsStr = "-1234567890";
    uint64_t paramsUint64 = 0;
    EXPECT_FALSE(StringToUint64(traceParamsStr, paramsUint64));
    traceParamsStr = "a123";
    EXPECT_FALSE(StringToUint64(traceParamsStr, paramsUint64));
    traceParamsStr = "";
    EXPECT_FALSE(StringToUint64(traceParamsStr, paramsUint64));
    traceParamsStr = "12a3";
    EXPECT_FALSE(StringToUint64(traceParamsStr, paramsUint64));
    traceParamsStr = "abc";
    EXPECT_FALSE(StringToUint64(traceParamsStr, paramsUint64));
    traceParamsStr = ".1";
    EXPECT_FALSE(StringToUint64(traceParamsStr, paramsUint64));
    traceParamsStr = "1.1";
    EXPECT_FALSE(StringToUint64(traceParamsStr, paramsUint64));
    traceParamsStr = "18446744073709551616";
    EXPECT_FALSE(StringToUint64(traceParamsStr, paramsUint64));
}

/**
 * @tc.name: IsJsvmV8File
 * @tc.desc: Test IsJsvmV8File function.
 * @tc.type: FUNC
*/
HWTEST_F(UtilitiesTest, IsJsvmV8File, TestSize.Level2)
{
    std::string filepath = "[anon:JSVM_JIT]";
    EXPECT_TRUE(IsJsvmV8File(filepath));
    filepath = "/system/lib64/libv8_shared.so";
    EXPECT_FALSE(IsJsvmV8File(filepath));
}

/**
 * @tc.name: IsArkwebV8File
 * @tc.desc: Test IsArkwebV8File function.
 * @tc.type: FUNC
*/
HWTEST_F(UtilitiesTest, IsArkwebV8File, TestSize.Level2)
{
    std::string filepath = "[anon:JSVM_JIT]";
    EXPECT_FALSE(IsArkwebV8File(filepath));
    filepath = "[anon:ARKWEB_JIT]";
    EXPECT_FALSE(IsArkwebV8File(filepath));
    filepath = "[anon:v8]";
    EXPECT_TRUE(IsArkwebV8File(filepath));
    filepath = "[anon:JS_V8]";
    EXPECT_TRUE(IsArkwebV8File(filepath));
    filepath = "[anon:test]";
    EXPECT_FALSE(IsArkwebV8File(filepath));
}

/**
 * @tc.name: IscontainDigits_NoDigits_PureAlpha
 * @tc.desc: Test string without digits (pure alphabet)
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IscontainDigitsNoDigitsPureAlpha, TestSize.Level1)
{
    std::string str = "abcdefg";
    bool result = IscontainDigits(str);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsExistDebugByPid_InvalidPid_Negative
 * @tc.desc: Test negative PID (e.g., -1)
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsExistDebugByPidInvalidPidNegative, TestSize.Level2)
{
    std::vector<pid_t> pids = {-1};
    std::string err;

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();

    bool result = IsExistDebugByPid(pids, err);
    std::string output = stdoutRecord.Stop();

    EXPECT_FALSE(result);
    EXPECT_EQ(err, "Invalid -p value '-1', the pid should be larger than 0\n");
    EXPECT_NE(output.find("Invalid -p value '-1', the pid should be larger than 0"), std::string::npos);
}

/**
 * @tc.name: IsNumeric_Invalid_WithAlpha
 * @tc.desc: Test string with numbers and alphabet (invalid)
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsNumericInvalidWithAlpha, TestSize.Level1)
{
    std::string str = "123a";
    EXPECT_FALSE(IsNumeric(str));
}

/**
 * @tc.name: IsDebugableApp
 * @tc.desc: Test IsDebugableApp fun
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsDebugableApp, TestSize.Level1)
{
    EXPECT_FALSE(IsDebugableApp("hiperf_test_demo"));
}

/**
 * @tc.name: IsProfileableApp
 * @tc.desc: Test IsProfileableApp fun
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsProfileableApp, TestSize.Level1)
{
    const std::string hiviewName = "hiview";
    EXPECT_FALSE(IsProfileableApp(hiviewName));
}

/**
 * @tc.name: IsApplicationEncryped
 * @tc.desc: Test IsApplicationEncryped fun
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsApplicationEncryped, TestSize.Level1)
{
#if defined(is_ohos) && is_ohos && defined(BUNDLE_FRAMEWORK_ENABLE)
    EXPECT_TRUE(IsApplicationEncryped(1));
#else
    EXPECT_FALSE(IsApplicationEncryped(1));
#endif
}

/**
 * @tc.name: IsApplicationEncrypedCache
 * @tc.desc: Test IsApplicationEncryped cache returns consistent result
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsApplicationEncrypedCache, TestSize.Level1)
{
#if defined(is_ohos) && is_ohos && defined(BUNDLE_FRAMEWORK_ENABLE)
    bool first = IsApplicationEncryped(999999);
    bool second = IsApplicationEncryped(999999);
    EXPECT_EQ(first, second);
    EXPECT_TRUE(first);
#else
    EXPECT_FALSE(IsApplicationEncryped(999999));
    EXPECT_FALSE(IsApplicationEncryped(999999));
#endif
}

/**
 * @tc.name: IsApplicationEncrypedInvalidPid
 * @tc.desc: Test IsApplicationEncryped with invalid pid
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsApplicationEncrypedInvalidPid, TestSize.Level1)
{
#if defined(is_ohos) && is_ohos && defined(BUNDLE_FRAMEWORK_ENABLE)
    EXPECT_TRUE(IsApplicationEncryped(0));
    EXPECT_TRUE(IsApplicationEncryped(-1));
#else
    EXPECT_FALSE(IsApplicationEncryped(0));
    EXPECT_FALSE(IsApplicationEncryped(-1));
#endif
}

/**
 * @tc.name: GetUidFromPid
 * @tc.desc: Test GetUidFromPid fun
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetUidFromPid, TestSize.Level1)
{
    const std::string hiviewName = "hiview";
    pid_t pid = GetPidFromApp(hiviewName);
    EXPECT_NE(pid, -1);
    uint32_t uid = 0;
    EXPECT_TRUE(GetUidFromPid(pid, uid));
    EXPECT_NE(uid, 0);
}

/**
 * @tc.name: GetStatusLineId_ValidLine
 * @tc.desc: Test GetStatusLineId with valid line containing numeric ID
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetStatusLineId_ValidLine, TestSize.Level1)
{
    std::string line = "Uid:\t1000\t2000\t3000\t4000";
    uint32_t target = 0;
    EXPECT_TRUE(GetStatusLineId(line, target));
    EXPECT_EQ(target, 1000);
}

/**
 * @tc.name: GetStatusLineId_InvalidLine_NoTabs
 * @tc.desc: Test GetStatusLineId with line missing tabs
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetStatusLineId_InvalidLine_NoTabs, TestSize.Level2)
{
    std::string line = "Uid:1000 2000 3000 4000";
    uint32_t target = 0;
    EXPECT_FALSE(GetStatusLineId(line, target));
}

/**
 * @tc.name: GetStatusLineId_InvalidLine_NonNumeric
 * @tc.desc: Test GetStatusLineId with non-numeric ID
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetStatusLineId_InvalidLine_NonNumeric, TestSize.Level2)
{
    std::string line = "Uid:\tabc\t2000\t3000\t4000";
    uint32_t target = 0;
    EXPECT_FALSE(GetStatusLineId(line, target));
}

/**
 * @tc.name: IsRootThread
 * @tc.desc: Test IsRootThread with init process (PID 1, typically root)
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsRootThread_InitProcess, TestSize.Level2)
{
    pid_t initPid = 1;
    EXPECT_TRUE(IsRootThread(initPid));
}

/**
 * @tc.name: StringToUnsignedLong_AllCases
 * @tc.desc: Test various cases for StringToUnsignedLong, covering valid and invalid scenarios
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringToUnsignedLong_AllCases, TestSize.Level2)
{
    unsigned long val;
    // Valid cases (5)
    EXPECT_TRUE(StringToUnsignedLong("0", val));
    EXPECT_EQ(val, 0UL);

    EXPECT_TRUE(StringToUnsignedLong("+12345", val));
    EXPECT_EQ(val, 12345UL);

    EXPECT_TRUE(StringToUnsignedLong("0x1a", val, 16));
    EXPECT_EQ(val, 26UL);

    EXPECT_TRUE(StringToUnsignedLong("1010", val, 2));
    EXPECT_EQ(val, 10UL);

    // Invalid cases (5)
    EXPECT_FALSE(StringToUnsignedLong("", val));

    EXPECT_FALSE(StringToUnsignedLong("123 ", val));

    EXPECT_FALSE(StringToUnsignedLong("-456", val));

    EXPECT_FALSE(StringToUnsignedLong("102", val, 2));
}

/**
 * @tc.name: StringToLongLong_AllCases
 * @tc.desc: Test various cases for StringToLongLong, covering valid and invalid scenarios
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringToLongLong_AllCases, TestSize.Level2)
{
    long long val;
    // Valid cases (6)
    EXPECT_TRUE(StringToLongLong("0", val));
    EXPECT_EQ(val, 0LL);

    EXPECT_TRUE(StringToLongLong("123456789012", val));
    EXPECT_EQ(val, 123456789012LL);

    EXPECT_TRUE(StringToLongLong("-9876543210", val));
    EXPECT_EQ(val, -9876543210LL);

    EXPECT_TRUE(StringToLongLong("0x1a3f", val, 16));
    EXPECT_EQ(val, 6719LL);

    EXPECT_TRUE(StringToLongLong("-10110", val, 2));
    EXPECT_EQ(val, -22LL);

    // Invalid cases (4)
    EXPECT_FALSE(StringToLongLong("", val));

    EXPECT_FALSE(StringToLongLong("123xyz", val));

    EXPECT_FALSE(StringToLongLong("103", val, 2));
}

/**
 * @tc.name: ExtractNumericPrefix_AllCases
 * @tc.desc: Test various cases for ExtractNumericPrefix, covering valid and invalid scenarios
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, ExtractNumericPrefix_AllCases, TestSize.Level2)
{
    EXPECT_EQ(ExtractNumericPrefix(""), "");

    EXPECT_EQ(ExtractNumericPrefix(" 123456"), "123456");

    EXPECT_EQ(ExtractNumericPrefix("123456 "), "123456");

    EXPECT_EQ(ExtractNumericPrefix("123456  000"), "123456");

    EXPECT_EQ(ExtractNumericPrefix("123456abc"), "123456");
}

/**
 * @tc.name: FindMatchingPidInProc
 * @tc.desc: Test cases for FindMatchingPidInProc to get init process pid
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, FindMatchingPidInProc, TestSize.Level2)
{
    std::string basePath {"/proc/"};
    std::string cmdline {"/cmdline"};
    std::string appPackageName {"init"};
    EXPECT_EQ(FindMatchingPidInProc(basePath, cmdline, appPackageName), 1);
}

/**
 * @tc.name: IsTaskManagerUid
 * @tc.desc: Test IsTaskManagerUid returns false
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsTaskManagerUid, TestSize.Level1)
{
    EXPECT_FALSE(IsTaskManagerUid());
}

/**
 * @tc.name: IsTaskManagerLabel
 * @tc.desc: Test IsTaskManagerLabel returns false
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsTaskManagerLabel, TestSize.Level1)
{
    EXPECT_FALSE(IsTaskManagerLabel());
}

/**
 * @tc.name: IsHiShellLabel
 * @tc.desc: Test IsHiShellLabel returns false
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsHiShellLabel, TestSize.Level1)
{
    EXPECT_FALSE(IsHiShellLabel());
}

/**
 * @tc.name: IsAllowReleaseApp_NotRunning
 * @tc.desc: Test IsAllowReleaseApp returns false when app is not running
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsAllowReleaseApp_NotRunning, TestSize.Level1)
{
    EXPECT_FALSE(IsAllowReleaseApp("hiperf_test_demo"));
}

/**
 * @tc.name: IsAllowSkipDeveloperMode_NotHiShellNotTaskManager
 * @tc.desc: Test IsAllowSkipDeveloperMode returns false when caller is neither hishell nor taskmanager
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsAllowSkipDeveloperMode_NotHiShellNotTaskManager, TestSize.Level2)
{
    EXPECT_FALSE(IsAllowSkipDeveloperMode());
}

/**
 * @tc.name: IsExistDebugByApp_EmptyBundleName
 * @tc.desc: Test IsExistDebugByApp returns true when bundleName is empty (no check needed)
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsExistDebugByApp_EmptyBundleName, TestSize.Level2)
{
    std::string err;
    EXPECT_TRUE(IsExistDebugByApp("", err));
    EXPECT_TRUE(err.empty());
}

/**
 * @tc.name: IsUnlockedDevice_ReturnsExpectedByDeviceType
 * @tc.desc: Test IsUnlockedDevice matches the current device type value
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsUnlockedDevice_ReturnsExpectedByDeviceType, TestSize.Level1)
{
    const std::string deviceType = GetDeviceType();
    const std::string unlockedDevicePerfValue = GetEnableUnlockDevicePerfParam();
    EXPECT_EQ(IsUnlockedDevice() && IsEnableUnlockedDevicePerf(),
              deviceType == "orange" && unlockedDevicePerfValue == "true");
}

/**
 * @tc.name: IsContainerProcess_InvalidPid
 * @tc.desc: Test IsContainerProcess with invalid PID (cannot read status)
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsContainerProcess_InvalidPid, TestSize.Level2)
{
    EXPECT_FALSE(IsContainerProcess(-1));
    EXPECT_FALSE(IsContainerProcess(9999999));
}

/**
 * @tc.name: IsContainerProcess_CurrentProcess
 * @tc.desc: Test IsContainerProcess with current process PID
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsContainerProcess_CurrentProcess, TestSize.Level2)
{
    pid_t currentPid = getpid();
    bool result = IsContainerProcess(currentPid);
    std::string statusPath = StringPrintf("/proc/%d/status", currentPid);
    std::string content = ReadFileToString(statusPath);
    
    if (content.find("NSpid:") == std::string::npos) {
        EXPECT_FALSE(result);
    } else {
        size_t pos = content.find("NSpid:");
        size_t endPos = content.find('\n', pos);
        if (endPos == std::string::npos) {
            endPos = content.size();
        }
        std::string nspidLine = content.substr(pos + 6, endPos - pos - 6);
        auto parts = StringSplit(StringTrim(nspidLine), "\t");
        int pidCount = 0;
        for (const auto& part : parts) {
            if (!part.empty()) {
                pidCount++;
            }
        }
        EXPECT_EQ(result, pidCount >= 2);
    }
}

/**
 * @tc.name: TestRoundUpBasic
 * @tc.desc: Test RoundUp function with basic alignment values
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, TestRoundUpBasic, TestSize.Level2)
{
    // Test alignment with 4
    EXPECT_EQ(RoundUp(0, 4), 0u);
    EXPECT_EQ(RoundUp(1, 4), 4u);
    EXPECT_EQ(RoundUp(2, 4), 4u);
    EXPECT_EQ(RoundUp(3, 4), 4u);
    EXPECT_EQ(RoundUp(4, 4), 4u);
    EXPECT_EQ(RoundUp(5, 4), 8u);
    
    // Test alignment with 8
    EXPECT_EQ(RoundUp(0, 8), 0u);
    EXPECT_EQ(RoundUp(7, 8), 8u);
    EXPECT_EQ(RoundUp(8, 8), 8u);
    EXPECT_EQ(RoundUp(9, 8), 16u);
    
    // Test alignment with 16
    EXPECT_EQ(RoundUp(15, 16), 16u);
    EXPECT_EQ(RoundUp(16, 16), 16u);
    EXPECT_EQ(RoundUp(17, 16), 32u);
}

/**
 * @tc.name: TestRoundUpLargeValues
 * @tc.desc: Test RoundUp function with large values
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, TestRoundUpLargeValues, TestSize.Level2)
{
    // Test large values
    EXPECT_EQ(RoundUp(1000, 4), 1000u);
    EXPECT_EQ(RoundUp(1001, 4), 1004u);
    EXPECT_EQ(RoundUp(1000000, 8), 1000000u);
    EXPECT_EQ(RoundUp(1000001, 8), 1000008u);
}

/**
 * @tc.name: TestIsStringToIntSuccessValid
 * @tc.desc: Test IsStringToIntSuccess with valid integer strings
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, TestIsStringToIntSuccessValid, TestSize.Level2)
{
    int num = 0;
    
    // Test positive integers
    EXPECT_TRUE(IsStringToIntSuccess("123", num));
    EXPECT_EQ(num, 123);
    
    EXPECT_TRUE(IsStringToIntSuccess("0", num));
    EXPECT_EQ(num, 0);
    
    // Test negative integers
    EXPECT_TRUE(IsStringToIntSuccess("-45", num));
    EXPECT_EQ(num, -45);
    
    // Test larger numbers
    EXPECT_TRUE(IsStringToIntSuccess("10000", num));
    EXPECT_EQ(num, 10000);
}

/**
 * @tc.name: TestIsStringToIntSuccessInvalid
 * @tc.desc: Test IsStringToIntSuccess with invalid strings
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, TestIsStringToIntSuccessInvalid, TestSize.Level2)
{
    int num = 0;
    
    // Test non-numeric strings
    EXPECT_FALSE(IsStringToIntSuccess("abc", num));
    EXPECT_FALSE(IsStringToIntSuccess("", num));
    EXPECT_FALSE(IsStringToIntSuccess("12a3", num));
    EXPECT_FALSE(IsStringToIntSuccess("a123", num));
}

/**
 * @tc.name: TestIsStringToIntSuccessEdgeCases
 * @tc.desc: Test IsStringToIntSuccess with edge case values
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, TestIsStringToIntSuccessEdgeCases, TestSize.Level2)
{
    int num = 0;
    
    // Test single digit
    EXPECT_TRUE(IsStringToIntSuccess("9", num));
    EXPECT_EQ(num, 9);
    
    // Test single negative digit
    EXPECT_TRUE(IsStringToIntSuccess("-1", num));
    EXPECT_EQ(num, -1);
    
    // Test leading zeros (should be valid)
    EXPECT_TRUE(IsStringToIntSuccess("007", num));
    EXPECT_EQ(num, 7);
}

/**
 * @tc.name: IscontainDigits_HasDigits
 * @tc.desc: Test IscontainDigits returns true when string contains digits
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IscontainDigits_HasDigits, TestSize.Level2)
{
    EXPECT_TRUE(IscontainDigits("abc123def"));
    EXPECT_TRUE(IscontainDigits("1"));
    EXPECT_TRUE(IscontainDigits("a1b"));
    EXPECT_TRUE(IscontainDigits("0"));
}

/**
 * @tc.name: IsNumeric_ValidNumber
 * @tc.desc: Test IsNumeric returns true for valid integer strings
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsNumeric_ValidNumber, TestSize.Level2)
{
    EXPECT_TRUE(IsNumeric("123"));
    EXPECT_TRUE(IsNumeric("0"));
    EXPECT_TRUE(IsNumeric("-456"));
    EXPECT_FALSE(IsNumeric(""));
}

/**
 * @tc.name: StringToUint64_ZeroAndHexBase
 * @tc.desc: Test StringToUint64 with zero value and hex base
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringToUint64_ZeroAndHexBase, TestSize.Level2)
{
    uint64_t val = 1;
    EXPECT_TRUE(StringToUint64("0", val));
    EXPECT_EQ(val, 0u);
    EXPECT_TRUE(StringToUint64("ff", val, 16));
    EXPECT_EQ(val, 255u);
}

/**
 * @tc.name: ReadFileToString_WithFileSize
 * @tc.desc: Test ReadFileToString 3-arg overload with fileSize parameter
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, ReadFileToString_WithFileSize, TestSize.Level2)
{
    std::string content;
    EXPECT_TRUE(ReadFileToString("/proc/self/comm", content, 0));
    EXPECT_FALSE(content.empty());
    std::string content2;
    EXPECT_TRUE(ReadFileToString("/proc/self/comm", content2, 64));
    EXPECT_FALSE(content2.empty());
    std::string content3;
    EXPECT_FALSE(ReadFileToString("/nonexistent/file/path", content3, 0));
}

/**
 * @tc.name: WriteStringToFile_NonexistentDir
 * @tc.desc: Test WriteStringToFile fails when directory does not exist
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, WriteStringToFile_NonexistentDir, TestSize.Level2)
{
    EXPECT_FALSE(WriteStringToFile("/nonexistent_dir_xyz/test.txt", "data"));
}

/**
 * @tc.name: CompressFile_NonexistentSource
 * @tc.desc: Test CompressFile returns false when source file does not exist
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CompressFile_NonexistentSource, TestSize.Level2)
{
    EXPECT_FALSE(CompressFile("/nonexistent_source_file.data", "/data/local/tmp/test_out.gz"));
}

/**
 * @tc.name: UncompressFile_NonexistentGzip
 * @tc.desc: Test UncompressFile returns false when gzip file does not exist
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, UncompressFile_NonexistentGzip, TestSize.Level2)
{
    EXPECT_FALSE(UncompressFile("/nonexistent_file.gz", "/data/local/tmp/test_out.data"));
}

/**
 * @tc.name: GetSubthreadIDs_WithThreadMap
 * @tc.desc: Test GetSubthreadIDs overload with thread_map parameter
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetSubthreadIDs_WithThreadMap, TestSize.Level1)
{
    std::map<pid_t, ThreadInfos> threadMap;
    std::vector<pid_t> tids = GetSubthreadIDs(getpid(), threadMap);
    EXPECT_GE(threadMap.size(), 0u);
}

/**
 * @tc.name: HandleAppInfo_EmptyAppPackage
 * @tc.desc: Test HandleAppInfo with empty appPackage exercises pid branch
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, HandleAppInfo_EmptyAppPackage, TestSize.Level2)
{
    std::string err = HandleAppInfo("", {});
    EXPECT_EQ(err, "");
}

/**
 * @tc.name: IsSupportNonDebuggableApp_RootMode
 * @tc.desc: Test IsSupportNonDebuggableApp returns true in root mode, false otherwise
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsSupportNonDebuggableApp_RootMode, TestSize.Level2)
{
    if (IsRoot()) {
        EXPECT_TRUE(IsSupportNonDebuggableApp());
    } else {
        EXPECT_EQ(IsSupportNonDebuggableApp(), IsBeta() && IsAllowProfilingUid());
    }
}

/**
 * @tc.name: LittleMemory_Test
 * @tc.desc: Test LittleMemory reads /proc/meminfo and returns result
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, LittleMemory_Test, TestSize.Level2)
{
    // Compute expected result from /proc/meminfo independently
    std::ifstream file("/proc/meminfo");
    std::string line;
    long memTotalKB = -1;
    while (getline(file, line)) {
        if (line.find("MemTotal:") != std::string::npos) {
            std::istringstream iss(line.substr(line.find(":") + 1));
            iss >> memTotalKB;
            break;
        }
    }
    ASSERT_GE(memTotalKB, 0);
    EXPECT_EQ(LittleMemory(),
              memTotalKB < (LITTLE_MEMORY_SIZE * MULTIPLE_SIZE * MULTIPLE_SIZE));
}

/**
 * @tc.name: GetProcessName_CurrentProcess
 * @tc.desc: Test GetProcessName returns non-empty for current process
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetProcessName_CurrentProcess, TestSize.Level2)
{
    std::string name = GetProcessName(getpid());
    EXPECT_FALSE(name.empty());
}

/**
 * @tc.name: IsHiviewCall_NotHiview
 * @tc.desc: Test IsHiviewCall returns false when parent is not hiview
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsHiviewCall_NotHiview, TestSize.Level2)
{
    EXPECT_FALSE(IsHiviewCall());
}

/**
 * @tc.name: IsHM_Test
 * @tc.desc: Test IsHM matches uname release against HMKERNEL
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsHM_Test, TestSize.Level2)
{
    utsname unameBuf;
    bool expected = false;
    if (uname(&unameBuf) == 0) {
        expected = std::string(unameBuf.release).find(HMKERNEL) != std::string::npos;
    }
    EXPECT_EQ(IsHM(), expected);
}

/**
 * @tc.name: IsAllowProfilingUid_Test
 * @tc.desc: Test IsAllowProfilingUid matches current uid against allow list
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsAllowProfilingUid_Test, TestSize.Level2)
{
    bool expected = (ALLOW_UIDS.find(getuid()) != ALLOW_UIDS.end());
    EXPECT_EQ(IsAllowProfilingUid(), expected);
}

/**
 * @tc.name: NeedAdaptSandboxPath_AdaptsPath
 * @tc.desc: Test NeedAdaptSandboxPath adapts /data/storage path when file not exist
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, NeedAdaptSandboxPath_AdaptsPath, TestSize.Level2)
{
    char filename[1024] = "/data/storage/nonexistent_test_file.txt";
    u16 headerSize = 0;
    EXPECT_TRUE(NeedAdaptSandboxPath(filename, getpid(), headerSize));
    EXPECT_EQ(std::string(filename).find("/proc/"), 0u);
}

/**
 * @tc.name: NeedAdaptSandboxPath_NoPrefix
 * @tc.desc: Test NeedAdaptSandboxPath returns false when path has no /data/storage prefix
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, NeedAdaptSandboxPath_NoPrefix, TestSize.Level2)
{
    char filename[1024] = "/data/local/tmp/test.txt";
    u16 headerSize = 0;
    EXPECT_FALSE(NeedAdaptSandboxPath(filename, getpid(), headerSize));
}

/**
 * @tc.name: GetDefaultPathByEnv_Default
 * @tc.desc: Test GetDefaultPathByEnv returns default path containing file type
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetDefaultPathByEnv_Default, TestSize.Level2)
{
    std::string path = GetDefaultPathByEnv("perf.data");
    EXPECT_FALSE(path.empty());
    EXPECT_NE(path.find("perf.data"), std::string::npos);
}

/**
 * @tc.name: CheckAppIsRunning_EmptyAppPackage
 * @tc.desc: Test CheckAppIsRunning returns true when appPackage is empty
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CheckAppIsRunning_EmptyAppPackage, TestSize.Level2)
{
    std::vector<pid_t> pids;
    EXPECT_TRUE(CheckAppIsRunning(pids, "", 100));
}

/**
 * @tc.name: StringEndsWith_NotAtEnd
 * @tc.desc: Test StringEndsWith returns false when substring found but not at end
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringEndsWith_NotAtEnd, TestSize.Level2)
{
    EXPECT_FALSE(StringEndsWith("test1test2", "test"));
    EXPECT_FALSE(StringEndsWith("abcdef", "abc"));
    EXPECT_TRUE(StringEndsWith("test1test2", "test2"));
}

/**
 * @tc.name: StringReplace_MultipleOccurrences
 * @tc.desc: Test StringReplace replaces multiple occurrences and handles no match
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringReplace_MultipleOccurrences, TestSize.Level2)
{
    EXPECT_EQ(StringReplace("a,b,c,d", ",", "-"), "a-b-c-d");
    EXPECT_EQ(StringReplace("no match here", "xyz", "123"), "no match here");
    EXPECT_EQ(StringReplace("", "a", "b"), "");
}

/**
 * @tc.name: CanonicalizeSpecPath_RealProcFile
 * @tc.desc: Test CanonicalizeSpecPath with an existing /proc path
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CanonicalizeSpecPath_RealProcFile, TestSize.Level2)
{
    std::string result = CanonicalizeSpecPath("/proc/self/comm");
    EXPECT_NE(result, "");
    EXPECT_EQ(result.find("/proc/"), 0u);
    EXPECT_NE(result.find("comm"), std::string::npos);
    EXPECT_NE(CanonicalizeSpecPath("/data/local/tmp"), "");
}

/**
 * @tc.name: IsHexDigits_HexPrefixAndZeros
 * @tc.desc: Test IsHexDigits with 0x prefix, leading zeros and all-zero strings
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsHexDigits_HexPrefixAndZeros, TestSize.Level2)
{
    EXPECT_TRUE(IsHexDigits("0xabc"));
    EXPECT_TRUE(IsHexDigits("0x0"));
    EXPECT_TRUE(IsHexDigits("0x000"));
    EXPECT_TRUE(IsHexDigits("0"));
    EXPECT_TRUE(IsHexDigits("000"));
    EXPECT_FALSE(IsHexDigits("0x"));
}

/**
 * @tc.name: ReadFileToString_NonexistentFile
 * @tc.desc: Test ReadFileToString returns empty when file open fails
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, ReadFileToString_NonexistentFile, TestSize.Level2)
{
    EXPECT_EQ(ReadFileToString("/nonexistent/path/to/file.txt"), "");
}

/**
 * @tc.name: ReadFileToString_3Arg_ZeroSizeFile
 * @tc.desc: Test ReadFileToString 3-arg overload with /dev/null
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, ReadFileToString_3Arg_ZeroSizeFile, TestSize.Level2)
{
    std::string content;
    EXPECT_TRUE(ReadFileToString("/dev/null", content, 0));
    EXPECT_TRUE(content.empty());
}

/**
 * @tc.name: StringTrim_EmptyString
 * @tc.desc: Test StringTrim with empty string
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringTrim_EmptyString, TestSize.Level3)
{
    std::string empty;
    EXPECT_EQ(StringTrim(empty), "");
}

/**
 * @tc.name: GetEntriesInDir_EmptyDir
 * @tc.desc: Test GetEntriesInDir with an empty directory (only . and ..)
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetEntriesInDir_EmptyDir, TestSize.Level2)
{
    std::string emptyDir = "/data/local/tmp/hiperf_empty_dir_test";
    rmdir(emptyDir.c_str());
    ASSERT_EQ(mkdir(emptyDir.c_str(), 0755), 0);
    auto result = GetEntriesInDir(emptyDir);
    EXPECT_TRUE(result.empty());
    rmdir(emptyDir.c_str());
}

/**
 * @tc.name: GetEntriesInDir_WithFiles
 * @tc.desc: Test GetEntriesInDir with a directory containing real files
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetEntriesInDir_WithFiles, TestSize.Level2)
{
    std::string dir = "/data/local/tmp/hiperf_dir_test";
    rmdir(dir.c_str());
    ASSERT_EQ(mkdir(dir.c_str(), 0755), 0);
    FILE* f = fopen((dir + "/testfile.txt").c_str(), "w");
    ASSERT_NE(f, nullptr);
    fclose(f);
    auto result = GetEntriesInDir(dir);
    auto it = std::find(result.begin(), result.end(), "testfile.txt");
    EXPECT_NE(it, result.end());
    remove((dir + "/testfile.txt").c_str());
    rmdir(dir.c_str());
}

/**
 * @tc.name: GetSubDirs_MixedFileAndDir
 * @tc.desc: Test GetSubDirs filters out non-directory entries
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetSubDirs_MixedFileAndDir, TestSize.Level2)
{
    std::string dir = "/data/local/tmp/hiperf_subdir_test";
    rmdir((dir + "/sub").c_str());
    rmdir(dir.c_str());
    ASSERT_EQ(mkdir(dir.c_str(), 0755), 0);
    ASSERT_EQ(mkdir((dir + "/sub").c_str(), 0755), 0);
    FILE* f = fopen((dir + "/file.txt").c_str(), "w");
    ASSERT_NE(f, nullptr);
    fclose(f);
    auto result = GetSubDirs(dir);
    auto it = std::find(result.begin(), result.end(), "sub");
    EXPECT_NE(it, result.end());
    EXPECT_EQ(std::find(result.begin(), result.end(), "file.txt"), result.end());
    remove((dir + "/file.txt").c_str());
    rmdir((dir + "/sub").c_str());
    rmdir(dir.c_str());
}

/**
 * @tc.name: IsSameCommand_PathMatch
 * @tc.desc: Test IsSameCommand matches the last path component
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsSameCommand_PathMatch, TestSize.Level2)
{
    EXPECT_TRUE(IsSameCommand("/system/bin/init", "init"));
    EXPECT_TRUE(IsSameCommand("a/b/c", "c"));
}

/**
 * @tc.name: IsSameCommand_VectorMultiMatch
 * @tc.desc: Test IsSameCommand vector overload with multiple names and no match
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsSameCommand_VectorMultiMatch, TestSize.Level2)
{
    std::vector<std::string> v = {"foo", "bar", "init"};
    EXPECT_TRUE(IsSameCommand("/system/bin/init", v));
    std::vector<std::string> v2 = {"foo", "bar"};
    EXPECT_FALSE(IsSameCommand("/system/bin/init", v2));
}

/**
 * @tc.name: HexDump_WithMaxSize
 * @tc.desc: Test HexDump with non-zero maxSize
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, HexDump_WithMaxSize, TestSize.Level2)
{
    const unsigned char buf[] = "12345678";
    const void *vbuf = static_cast<const void *>(buf);
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH, true);
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    EXPECT_EQ(HexDump(vbuf, 8, 4), true);
    EXPECT_EQ(HexDump(vbuf, 4, 8), true);
    stdoutRecord.Stop();
}

/**
 * @tc.name: ReadIntFromProcFile_NoDigits
 * @tc.desc: Test ReadIntFromProcFile returns false when content has no digits
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, ReadIntFromProcFile_NoDigits, TestSize.Level2)
{
    std::string path = "/data/local/tmp/hiperf_nodigits.txt";
    ASSERT_TRUE(WriteStringToFile(path, "abcdef\n"));
    int val = 0;
    EXPECT_FALSE(ReadIntFromProcFile(path, val));
    remove(path.c_str());
}

/**
 * @tc.name: ReadIntFromProcFile_ShortNoNewline
 * @tc.desc: Test ReadIntFromProcFile with single-char content without newline
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, ReadIntFromProcFile_ShortNoNewline, TestSize.Level2)
{
    std::string path = "/data/local/tmp/hiperf_short.txt";
    ASSERT_TRUE(WriteStringToFile(path, "5"));
    int val = 0;
    EXPECT_TRUE(ReadIntFromProcFile(path, val));
    EXPECT_EQ(val, 5);
    remove(path.c_str());
}

/**
 * @tc.name: ReadIntFromProcFile_Overflow
 * @tc.desc: Test ReadIntFromProcFile returns false on integer overflow
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, ReadIntFromProcFile_Overflow, TestSize.Level2)
{
    std::string path = "/data/local/tmp/hiperf_overflow.txt";
    ASSERT_TRUE(WriteStringToFile(path, "99999999999999999999\n"));
    int val = 0;
    EXPECT_FALSE(ReadIntFromProcFile(path, val));
    remove(path.c_str());
}

/**
 * @tc.name: CompressFile_GzopenFail
 * @tc.desc: Test CompressFile returns false when gzopen fails on bad dest path
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CompressFile_GzopenFail, TestSize.Level2)
{
    std::string src = "./resource/testdata/elf_test_stripped_broken";
    std::string dest = "/nonexistent_dir_xyz/out.gz";
    EXPECT_FALSE(CompressFile(src, dest));
}

/**
 * @tc.name: UncompressFile_CorruptGzip
 * @tc.desc: Test UncompressFile returns false on corrupt gzip content
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, UncompressFile_CorruptGzip, TestSize.Level2)
{
    std::string gzipPath = "/data/local/tmp/hiperf_corrupt.gz";
    std::string dataPath = "/data/local/tmp/hiperf_corrupt_out";
    std::ofstream gz(gzipPath, std::ios::binary);
    ASSERT_TRUE(gz.is_open());
    const unsigned char header[] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff};
    gz.write(reinterpret_cast<const char *>(header), sizeof(header));
    const std::string garbage(100, 'x');
    gz.write(garbage.data(), garbage.size());
    gz.close();
    EXPECT_FALSE(UncompressFile(gzipPath, dataPath));
    remove(gzipPath.c_str());
    remove(dataPath.c_str());
}

/**
 * @tc.name: FindMatchingPidInProc_NotFound
 * @tc.desc: Test FindMatchingPidInProc returns -1 when no process matches
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, FindMatchingPidInProc_NotFound, TestSize.Level2)
{
    std::string basePath {"/proc/"};
    std::string cmdline {"/cmdline"};
    EXPECT_EQ(FindMatchingPidInProc(basePath, cmdline, "nonexistent_app_xyz"), -1);
}

/**
 * @tc.name: GetAppPackagePid_NotFound
 * @tc.desc: Test GetAppPackagePid returns -1 for a non-running app
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetAppPackagePid_NotFound, TestSize.Level2)
{
    EXPECT_EQ(GetAppPackagePid("nonexistent_app_xyz", -1, 100, 1), -1);
}

/**
 * @tc.name: IsEnableUnlockedDevicePerf_Call
 * @tc.desc: Test IsEnableUnlockedDevicePerf executes and matches param value
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsEnableUnlockedDevicePerf_Call, TestSize.Level2)
{
    bool result = IsEnableUnlockedDevicePerf();
    EXPECT_EQ(result, GetEnableUnlockDevicePerfParam() == "true");
}

/**
 * @tc.name: GetDeveloperMode_Call
 * @tc.desc: Test GetDeveloperMode executes the param read path
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetDeveloperMode_Call, TestSize.Level2)
{
    bool result1 = GetDeveloperMode();
    bool result2 = GetDeveloperMode();
    EXPECT_EQ(result1, result2);
}

/**
 * @tc.name: IsUnlockedDevice_MatchParam
 * @tc.desc: Test IsUnlockedDevice matches the device type param value
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsUnlockedDevice_MatchParam, TestSize.Level2)
{
    EXPECT_EQ(IsUnlockedDevice(), GetDeviceType() == "orange");
}

/**
 * @tc.name: NeedAdaptHMBundlePath_NoBundlePath
 * @tc.desc: Test NeedAdaptHMBundlePath returns false when path has no bundle prefix
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, NeedAdaptHMBundlePath_NoBundlePath, TestSize.Level2)
{
    std::string filename = "/data/local/tmp/test.so";
    EXPECT_FALSE(NeedAdaptHMBundlePath(filename, "threadname"));
    EXPECT_EQ(filename, "/data/local/tmp/test.so");
}

/**
 * @tc.name: NeedAdaptHMBundlePath_NotExistBoth
 * @tc.desc: Test NeedAdaptHMBundlePath returns false when neither old nor new path exists
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, NeedAdaptHMBundlePath_NotExistBoth, TestSize.Level2)
{
    std::string filename = "/data/storage/el1/bundle/libs/arm64/libentry.so";
    EXPECT_FALSE(NeedAdaptHMBundlePath(filename, "nonexistent_proc"));
    EXPECT_EQ(filename, "/data/storage/el1/bundle/libs/arm64/libentry.so");
}

/**
 * @tc.name: IsNumeric_Comprehensive
 * @tc.desc: Test IsNumeric with valid, invalid and trailing-character inputs
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsNumeric_Comprehensive, TestSize.Level2)
{
    EXPECT_TRUE(IsNumeric("0"));
    EXPECT_TRUE(IsNumeric("123"));
    EXPECT_TRUE(IsNumeric("-456"));
    EXPECT_FALSE(IsNumeric(""));
    EXPECT_FALSE(IsNumeric("abc"));
    EXPECT_FALSE(IsNumeric("12a"));
    EXPECT_FALSE(IsNumeric("1.5"));
}

/**
 * @tc.name: ParseJson_Nonexistent
 * @tc.desc: Test ParseJson returns nullptr when file cannot be opened
 * @tc.type: FUNC
 */
#ifdef CONFIG_HAS_CCM
HWTEST_F(UtilitiesTest, ParseJson_Nonexistent, TestSize.Level2)
{
    cJSON* root = ParseJson("/nonexistent/json/file.json");
    EXPECT_EQ(root, nullptr);
}

/**
 * @tc.name: ParseJson_ValidJson
 * @tc.desc: Test ParseJson parses a valid JSON file successfully
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, ParseJson_ValidJson, TestSize.Level2)
{
    std::string path = "/data/local/tmp/hiperf_test.json";
    ASSERT_TRUE(WriteStringToFile(path, "{\"key\": 42}"));
    cJSON* root = ParseJson(path);
    ASSERT_NE(root, nullptr);
    cJSON_Delete(root);
    remove(path.c_str());
}

/**
 * @tc.name: GetJsonNum_ValidAndInvalid
 * @tc.desc: Test GetJsonNum with valid number, missing key and non-number node
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetJsonNum_ValidAndInvalid, TestSize.Level2)
{
    cJSON* root = cJSON_CreateObject();
    ASSERT_NE(root, nullptr);
    cJSON_AddNumberToObject(root, "num", 100);
    size_t val = 0;
    EXPECT_TRUE(GetJsonNum(root, "num", val));
    EXPECT_EQ(val, 100u);
    EXPECT_FALSE(GetJsonNum(root, "missing", val));
    cJSON_AddItemToObject(root, "str", cJSON_CreateString("abc"));
    EXPECT_FALSE(GetJsonNum(root, "str", val));
    cJSON_Delete(root);
}

/**
 * @tc.name: GetCfgValue_InvalidConfig
 * @tc.desc: Test GetCfgValue returns false when config root is null
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetCfgValue_InvalidConfig, TestSize.Level2)
{
    size_t value = 0;
    EXPECT_FALSE(GetCfgValue("nonexistent/cfg.json", "key", value));
}
#endif

/**
 * @tc.name: IsDirectoryExists_Nonexistent
 * @tc.desc: Test IsDirectoryExists returns false for nonexistent path
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsDirectoryExists_Nonexistent, TestSize.Level2)
{
    EXPECT_FALSE(IsDirectoryExists("/nonexistent/dir/xyz"));
}

/**
 * @tc.name: CreateDirectory_ExistingDir
 * @tc.desc: Test CreateDirectory on an already existing directory (skip mkdir)
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CreateDirectory_ExistingDir, TestSize.Level2)
{
    std::string dir = "/data/local/tmp/hiperf_exist_dir";
    rmdir(dir.c_str());
    ASSERT_EQ(mkdir(dir.c_str(), 0755), 0);
    EXPECT_TRUE(CreateDirectory(dir, 0755));
    rmdir(dir.c_str());
}

/**
 * @tc.name: CreateDirectory_Nested
 * @tc.desc: Test CreateDirectory creates nested directories recursively
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CreateDirectory_Nested, TestSize.Level2)
{
    std::string dir = "/data/local/tmp/hiperf_nested/a/b/c";
    EXPECT_TRUE(CreateDirectory(dir, 0755));
    rmdir("/data/local/tmp/hiperf_nested/a/b/c");
    rmdir("/data/local/tmp/hiperf_nested/a/b");
    rmdir("/data/local/tmp/hiperf_nested/a");
    rmdir("/data/local/tmp/hiperf_nested");
}

/**
 * @tc.name: CreateDirectory_MkdirFail
 * @tc.desc: Test CreateDirectory returns false when mkdir fails (read-only location)
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, CreateDirectory_MkdirFail, TestSize.Level2)
{
    EXPECT_FALSE(CreateDirectory("/proc/hiperf_cannot_create_dir", 0755));
}

/**
 * @tc.name: GetStatusLineId_TrailingChars
 * @tc.desc: Test GetStatusLineId fails when id has trailing non-numeric chars
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetStatusLineId_TrailingChars, TestSize.Level2)
{
    std::string line = "Uid:\t100abc\t200";
    uint32_t target = 0;
    EXPECT_FALSE(GetStatusLineId(line, target));
}

/**
 * @tc.name: GetUidFromPid_Nonexistent
 * @tc.desc: Test GetUidFromPid returns false for nonexistent pid
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetUidFromPid_Nonexistent, TestSize.Level2)
{
    uint32_t uid = 0;
    EXPECT_FALSE(GetUidFromPid(9999999, uid));
}

/**
 * @tc.name: IsRootThread_NonexistentPid
 * @tc.desc: Test IsRootThread returns false for nonexistent pid
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsRootThread_NonexistentPid, TestSize.Level2)
{
    EXPECT_FALSE(IsRootThread(9999999));
}

/**
 * @tc.name: IsAllowReleaseApp_NonexistentApp
 * @tc.desc: Test IsAllowReleaseApp returns false for a non-running app
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsAllowReleaseApp_NonexistentApp, TestSize.Level2)
{
    EXPECT_FALSE(IsAllowReleaseApp("nonexistent_app_xyz"));
}

/**
 * @tc.name: GetEntriesInDir_NonexistentDir
 * @tc.desc: Test GetEntriesInDir returns empty for a nonexistent directory
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, GetEntriesInDir_NonexistentDir, TestSize.Level2)
{
    auto result = GetEntriesInDir("/nonexistent_dir_xyz_dir");
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: WriteStringToFile_ReadOnlyPath
 * @tc.desc: Test WriteStringToFile returns false when output open fails
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, WriteStringToFile_ReadOnlyPath, TestSize.Level2)
{
    EXPECT_FALSE(WriteStringToFile("/proc/hiperf_cannot_write.txt", "data"));
}

/**
 * @tc.name: ReadFileToString_3Arg_Directory
 * @tc.desc: Test ReadFileToString 3-arg returns false when reading a directory fd
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, ReadFileToString_3Arg_Directory, TestSize.Level2)
{
    std::string content;
    EXPECT_FALSE(ReadFileToString("/data/local/tmp", content, 0));
}

/**
 * @tc.name: IsRootThread_NonRootPid
 * @tc.desc: Test IsRootThread returns false for a non-root pid found in /proc
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsRootThread_NonRootPid, TestSize.Level2)
{
    DIR *dir = opendir("/proc");
    ASSERT_NE(dir, nullptr);
    bool found = false;
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        int pid = atoi(entry->d_name);
        if (pid <= 1) {
            continue;
        }
        uint32_t uid = 0;
        if (GetUidFromPid(pid, uid) && uid != 0) {
            EXPECT_FALSE(IsRootThread(pid));
            found = true;
            break;
        }
    }
    closedir(dir);
    if (!found) {
        GTEST_LOG_(INFO) << "No non-root pid found in /proc";
    }
}

/**
 * @tc.name: AgeHiperflogFiles_RemovesTempFile
 * @tc.desc: Test AgeHiperflogFiles removes non-whitelist temp files
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, AgeHiperflogFiles_RemovesTempFile, TestSize.Level2)
{
    std::string tempFile = "/data/log/hiperflog/hiperf_age_test_temp.txt";
    FILE *f = fopen(tempFile.c_str(), "w");
    if (f == nullptr) {
        GTEST_LOG_(INFO) << "Cannot create file in hiperflog, skip";
        SUCCEED();
        return;
    }
    fclose(f);
    ASSERT_EQ(access(tempFile.c_str(), F_OK), 0);
    AgeHiperflogFiles();
    EXPECT_EQ(access(tempFile.c_str(), F_OK), -1);
}

/**
 * @tc.name: IsContainDigits_Various
 * @tc.desc: Test IscontainDigits with empty, numeric and mixed strings
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsContainDigits_Various, TestSize.Level2)
{
    EXPECT_FALSE(IscontainDigits(""));
    EXPECT_FALSE(IscontainDigits("   "));
    EXPECT_TRUE(IscontainDigits("0"));
    EXPECT_TRUE(IscontainDigits(" 9 "));
}

/**
 * @tc.name: StringToUnsignedLong_EdgeCases
 * @tc.desc: Test StringToUnsignedLong with hex, octal and overflow inputs
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringToUnsignedLong_EdgeCases, TestSize.Level2)
{
    unsigned long val = 0;
    EXPECT_TRUE(StringToUnsignedLong("0777", val));
    EXPECT_TRUE(StringToUnsignedLong("0xFFFFFFFF", val, 16));
    EXPECT_FALSE(StringToUnsignedLong("0xFFFFFFFFFFFFFFFFFF", val, 16));
    EXPECT_FALSE(StringToUnsignedLong("12 34", val));
}

/**
 * @tc.name: StringToLongLong_EdgeCases
 * @tc.desc: Test StringToLongLong with octal, overflow and whitespace inputs
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringToLongLong_EdgeCases, TestSize.Level2)
{
    long long val = 0;
    EXPECT_TRUE(StringToLongLong("0777", val));
    EXPECT_TRUE(StringToLongLong("0x7FFFFFFFFFFFFFFF", val, 16));
    EXPECT_FALSE(StringToLongLong("0x8000000000000000", val, 16));
    EXPECT_FALSE(StringToLongLong("12 34", val));
}

/**
 * @tc.name: StringToUint64_EdgeCases
 * @tc.desc: Test StringToUint64 with hex, plus sign and boundary values
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringToUint64_EdgeCases, TestSize.Level2)
{
    uint64_t val = 1;
    EXPECT_TRUE(StringToUint64("+123", val));
    EXPECT_EQ(val, 123u);
    EXPECT_TRUE(StringToUint64("0xFF", val, 16));
    EXPECT_EQ(val, 255u);
    EXPECT_TRUE(StringToUint64("0777", val));
    EXPECT_EQ(val, 511u);
    EXPECT_FALSE(StringToUint64("123 456", val));
    EXPECT_FALSE(StringToUint64("+", val));
}

/**
 * @tc.name: IsStringToIntSuccess_Boundary
 * @tc.desc: Test IsStringToIntSuccess with INT_MAX, INT_MIN and overflow values
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsStringToIntSuccess_Boundary, TestSize.Level2)
{
    int num = 0;
    EXPECT_TRUE(IsStringToIntSuccess("2147483647", num));
    EXPECT_EQ(num, 2147483647);
    EXPECT_TRUE(IsStringToIntSuccess("-2147483648", num));
    EXPECT_EQ(num, -2147483648);
    EXPECT_FALSE(IsStringToIntSuccess("2147483648", num));
    EXPECT_FALSE(IsStringToIntSuccess("-2147483649", num));
    EXPECT_FALSE(IsStringToIntSuccess("9999999999999999999", num));
}

/**
 * @tc.name: StringEndsWith_SuffixVariations
 * @tc.desc: Test StringEndsWith with longer suffix, partial and exact matches
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringEndsWith_SuffixVariations, TestSize.Level2)
{
    EXPECT_FALSE(StringEndsWith("ab", "abc"));
    EXPECT_TRUE(StringEndsWith("abc", "abc"));
    EXPECT_TRUE(StringEndsWith("abc", "c"));
    EXPECT_TRUE(StringEndsWith("abc", ""));
    EXPECT_FALSE(StringEndsWith("abc", "b"));
    EXPECT_FALSE(StringEndsWith("a", "abc"));
}

/**
 * @tc.name: StringStartsWith_PrefixVariations
 * @tc.desc: Test StringStartsWith with longer prefix, partial and exact matches
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringStartsWith_PrefixVariations, TestSize.Level2)
{
    EXPECT_FALSE(StringStartsWith("ab", "abc"));
    EXPECT_TRUE(StringStartsWith("abc", "abc"));
    EXPECT_TRUE(StringStartsWith("abc", "a"));
    EXPECT_TRUE(StringStartsWith("abc", ""));
    EXPECT_FALSE(StringStartsWith("abc", "bc"));
}

/**
 * @tc.name: IsPath_RelativeAndAbsolute
 * @tc.desc: Test IsPath with absolute, relative and plain name inputs
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsPath_RelativeAndAbsolute, TestSize.Level2)
{
    EXPECT_TRUE(IsPath("/data/local/tmp"));
    EXPECT_TRUE(IsPath("./test"));
    EXPECT_FALSE(IsPath("test"));
    EXPECT_FALSE(IsPath("abc/def"));
}

/**
 * @tc.name: IsDir_FileAndNonexistent
 * @tc.desc: Test IsDir returns false for a file and nonexistent path
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, IsDir_FileAndNonexistent, TestSize.Level2)
{
    EXPECT_FALSE(IsDir("/proc/self/comm"));
    EXPECT_FALSE(IsDir("/nonexistent_dir_xyz"));
    EXPECT_TRUE(IsDir("/data"));
}

/**
 * @tc.name: PowerOfTwo_Various
 * @tc.desc: Test PowerOfTwo with zero, one and non-power values
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, PowerOfTwo_Various, TestSize.Level2)
{
    EXPECT_FALSE(PowerOfTwo(0));
    EXPECT_TRUE(PowerOfTwo(1));
    EXPECT_TRUE(PowerOfTwo(2));
    EXPECT_TRUE(PowerOfTwo(1024));
    EXPECT_FALSE(PowerOfTwo(3));
    EXPECT_FALSE(PowerOfTwo(1023));
}

/**
 * @tc.name: SubStringCount_EdgeCases
 * @tc.desc: Test SubStringCount with empty source, empty sub and no match
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, SubStringCount_EdgeCases, TestSize.Level2)
{
    EXPECT_EQ(SubStringCount("", "a"), 0u);
    EXPECT_EQ(SubStringCount("aaa", ""), 3u);
    EXPECT_EQ(SubStringCount("abc", "d"), 0u);
    EXPECT_EQ(SubStringCount("aaaa", "aa"), 2u);
}

/**
 * @tc.name: StringSplit_EdgeCases
 * @tc.desc: Test StringSplit with only separator, leading/trailing separators
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringSplit_EdgeCases, TestSize.Level2)
{
    EXPECT_EQ(StringSplit(",", ",").size(), 0u);
    EXPECT_EQ(StringSplit(",a,b,", ",").size(), 2u);
    EXPECT_EQ(StringSplit("a,,b", ",").size(), 2u);
    EXPECT_EQ(StringSplit("abc", "abc").size(), 0u);
}

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
