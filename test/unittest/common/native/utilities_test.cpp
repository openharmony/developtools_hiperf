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
#include <chrono>
#include <thread>
#include "utilities.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
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

void UtilitiesTest::SetUpTestCase() {}

void UtilitiesTest::TearDownTestCase() {}

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

/**
 * @tc.name: StringReplace
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringReplace, TestSize.Level1)
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
HWTEST_F(UtilitiesTest, StringSplit, TestSize.Level1)
{
    std::string testString = "1,23,456,7890,";
    size_t testSize = testString.size();
    EXPECT_EQ(StringSplit(testString, "1").size(), 1u);
    EXPECT_EQ(StringSplit(testString, "2").size(), 2u);
    EXPECT_EQ(StringSplit(testString, ",").size(), 4u);
    EXPECT_EQ(StringSplit(testString, "456").size(), 2u);
    EXPECT_EQ(StringSplit(testString, "000").size(), 1u);
    EXPECT_EQ(StringSplit(testString, "").size(), 1u);
    // dont change the input string
    EXPECT_EQ(testString.size(), testSize);

    EXPECT_EQ(StringSplit(testString = "").size(), 0u);
    EXPECT_EQ(StringSplit(testString = "1,2,3").size(), 3u);
    EXPECT_EQ(StringSplit(testString = "1,2,3,,,").size(), 3u);
}

/**
 * @tc.name: SubStringCount
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, SubStringCount, TestSize.Level1)
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
HWTEST_F(UtilitiesTest, StringEndsWith, TestSize.Level1)
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
HWTEST_F(UtilitiesTest, StringStartsWith, TestSize.Level1)
{
    std::string testString = "1,22,333,4444,";
    EXPECT_EQ(StringStartsWith(testString, ""), true);
    EXPECT_EQ(StringStartsWith(testString, "1"), true);
    EXPECT_EQ(StringStartsWith(testString, ","), false);

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
 * @tc.name: BufferToHexString
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, BufferToHexString, TestSize.Level1)
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
HWTEST_F(UtilitiesTest, HexDump, TestSize.Level1)
{
    const unsigned char buf[] = "12345678";
    const void *vbuf = static_cast<const void *>(buf);
    ScopeDebugLevel tempLogLevel(LEVEL_MUCH, true);

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    HexDump(vbuf, 0);
    HexDump(vbuf, 1);
    HexDump(vbuf, 4);
    HexDump(vbuf, 5);
    HexDump(vbuf, 8);
    stdoutRecord.Stop();
}

/**
 * @tc.name: StringTrim
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, StringTrim, TestSize.Level1)
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
HWTEST_F(UtilitiesTest, RecordStdout, TestSize.Level1)
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
HWTEST_F(UtilitiesTest, IsHexxDigits, TestSize.Level1)
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
HWTEST_F(UtilitiesTest, IsSameCommand, TestSize.Level1)
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
HWTEST_F(UtilitiesTest, UncompressFile, TestSize.Level1)
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
HWTEST_F(UtilitiesTest, ToHex, TestSize.Level1)
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
 * @tc.name: ReadIntFromProcFile
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, ReadIntFromProcFile, TestSize.Level1)
{
    std::string strPath = "/proc/sys/kernel/perf_cpu_time_max_percent";
    int strLen = 0;
    EXPECT_EQ(ReadIntFromProcFile(strPath, strLen), true);
}

/**
 * @tc.name: WriteIntToProcFile
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(UtilitiesTest, WriteIntToProcFile, TestSize.Level1)
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
HWTEST_F(UtilitiesTest, Percentage, TestSize.Level1)
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
    EXPECT_EQ(tids.size(), tids_.size());
    if (!HasFailure()) {
        for (pid_t tid : tids) {
            EXPECT_NE(find(tids_.begin(), tids_.end(), tid), tids_.end());
        }
    }
    ExitThreads();
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
