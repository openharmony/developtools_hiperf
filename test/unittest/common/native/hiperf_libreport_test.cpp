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

#include "hiperf_libreport_test.h"
#include "debug_logger.h"
#include "hiperf_libreport.h"
#include "subcommand_dump.h"
#include "subcommand_report.h"
#include "utilities.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;

namespace OHOS {
namespace Developtools {
namespace HiPerf {
constexpr const char *PERF_DATA_INPUT_PATH =
    "/data/test/resource/testdata/report/perf.data.libreport";
#ifdef __arm__
constexpr const char *PERF_DISABLE_UNWIND_DATA_INPUT_PATH =
    "/data/test/resource/testdata/report/perf.disable.unwind.hiperf_example_cmd.data";
#else
constexpr const char *PERF_DISABLE_UNWIND_DATA_INPUT_PATH =
    "/data/test/resource/testdata/report/perf.disable.unwind.hiperf_example_cmd_64.data";
#endif
constexpr const char *PERF_DISABLE_UNWIND_SYMBOL_INPUT_PATH = "/data/test/resource/testdata/report";
constexpr const char *PERF_DATA_ERROR_FORMAT_INPUT_PATH =
    "/data/test/resource/testdata/report/perf.data.error.format.libreport";
constexpr const char *REPORT_OUTPUT_PATH = "./report.txt";
constexpr const char *REPORT_JSON_OUTPUT_PATH = "./perf.json";
constexpr const char *REPORT_PROTO_OUTPUT_PATH = "./perf.proto";
constexpr const char *ILLEGAL_PATH = "/proc/illegal";

constexpr const char *TEST_ELF32 = "/data/test/resource/testdata/report/buildid_test_elf_32";
constexpr const char *BUILDID_TEST_ELF32 = "8e5a30338be326934ff93c998dcd0d22fe345870";

constexpr const char *TEST_ELF64 = "/data/test/resource/testdata/report/buildid_test_elf_64";
constexpr const char *BUILDID_TEST_ELF64 = "24c55dccc5baaaa140da0083207abcb8d523e248";

constexpr const char *TEST_ELF_BROKEN = "/data/test/resource/testdata/report/elf32_test_broken";

class HiperfLibReportTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void DefaultReportContentCheck(const std::string &) const;
    void DefaultDumpContentCheck(const std::string &) const;
    void DefaultJsonContentCheck(const std::string &) const;
    void UnwindJsonContentCheck(const std::string &, bool haveUnwind) const;
    void DefaultSymbolsBuildIdContentCheck(const std::string &) const;
};

void HiperfLibReportTest::DefaultSymbolsBuildIdContentCheck(const std::string &content) const
{
    constexpr const char *buildIdList =
        "[/system/lib/libhilogutil.so,c32713a57e92190404f8e46e19346a08],"
        "[/system/lib/libhilog_os_adapter.z.so,6fb456cf373eb617e129c89b6f5982d9],"
        "[/system/lib/libhilog.so,07daae0a6ed91e8ba56a0c76d6a3ac4a],[/system/lib/"
        "libc++.so,38fdac430dfe95b261aa33d3d7cf553415686ba6],"
        "[/system/lib/libutils.z.so,f24970cefc3e5fac09fe07168f9353f9],"
        "[/system/bin/ld-musl-arm.so.1,],[/system/lib/libmpi.so,],"
        "[/system/lib/libhi_osal.so,],[/system/lib/libhi3516cv500_vo.so,],[/system/"
        "lib/libhi3516cv500_vdec.so,],[/system/lib/libhi3516cv500_sys.so,],[/system/lib/"
        "libhi3516cv500_chnl.so,],[/system/lib/libffi.z.so,3b0380999b8469ed9b1ebd252d6cb08f],[/"
        "system/lib/libdsoftbus_trans_direct_channel_sdk.z.so,f3c136104d821facf3573b7c34f36097],[/"
        "system/lib/libipc_core.z.so,5a11ea1cacdad9d160eb8101f5a89e68],[/system/lib/"
        "libtel_core_service.z.so,9dbeadf74de1d9cc83c25fbce88203ed],[/system/lib/"
        "libace_napi_quickjs.z.so,99850793579d24a88d20931ab40147c0],[/system/lib/"
        "libace_engine_qjs.z.so,34dfa8cbdeb49bb797ad306cc6a3e418],[/system/lib/"
        "libvsync_client.z.so,4d6c9ae5004f39e16a4cd6194a2c1f80],[/system/lib/"
        "libace.z.so,b8d9d3bb0184ba917e8d05d471e8387a],[/system/lib/"
        "libeventhandler.z.so,b1e08a8a6eabe33363f721b14393b06b],[/system/bin/"
        "hilogd,b11a9f3700884ded33879f81914e3aa2],[/system/bin/"
        "wifi_hal_service,6beba486dcdf5debb5c9248bc5cdf5f0],[/data/local/tmp/"
        "hiperf,32aa1e9c5f35d49e16fa1b6e86db130c],[/system/bin/"
        "hiview,419493d9ccef1df5dedfa4a144249e49],[/system/lib/"
        "libhiviewbase.z.so,349d82d4f1d2dc21c039156afbe470ad],[/system/lib/"
        "libvsync_module.z.so,b8ad1b79c5816a6540a08d21ff88ac66],[[kernel.kallsyms],"
        "ec918ed092bf1820cfdd9dbad43b19fbe0695472],[/vendor/modules/"
        "hi_mipi_rx.ko,df9b94ace268f6ea6e43bb29a2e4d0e48cb5847d],[/vendor/modules/"
        "hi3516cv500_hdmi.ko,0968b8fa34aa7f26dc5b953785933aeb62b3d5d5],[/vendor/modules/"
        "hifb.ko,939f84e15d744af033284c1e6a6cd047ed3a5da9],[/vendor/modules/"
        "hi3516cv500_vo_dev.ko,d391f542c407edb116fc16f45d25cc5fbee9f287],[/vendor/modules/"
        "hi3516cv500_tde.ko,417a56e829c0773c5ed2303bf33ab51a50c414d7],[/vendor/modules/"
        "hi3516cv500_sys.ko,221223701496c08e458bc7b98f17cb5f8ec54e7c],[/vendor/modules/"
        "hi3516cv500_base.ko,20fc3ae721d798ba72fd62a78bc7c3c9a4007446],[/vendor/modules/"
        "sys_config.ko,8f245b1e73775567c74574f912a96a26d1cb02c8],[/vendor/modules/"
        "hi_proc.ko,789cbddace68515aea94aa2b7f0cbf2b81d48c9f],[/vendor/modules/"
        "hi_irq.ko,3048ea5e3ed49489a876fe9ad4fcdbe73820f751],[/vendor/modules/"
        "hi_osal.ko,3f7b2c2f0030a13dbd01c58f5b52eb0a1dd427af]";

    ASSERT_TRUE(content.size() >= 2u);
    ASSERT_EQ(content.front(), '[');
    ASSERT_EQ(content.back(), ']');
    std::vector<std::string> fileBuildPairs = StringSplit(content, "[");
    for (std::string &pair : fileBuildPairs) {
        std::vector<std::string> buildIdPair = StringSplit(pair, ",");
        ASSERT_EQ(buildIdPair.size(), 2u);
    }
    EXPECT_STREQ(content.c_str(), buildIdList);
}

void HiperfLibReportTest::DefaultJsonContentCheck(const std::string &content) const
{
    /*
        json must have { xxx  } format
    */

    ASSERT_TRUE(content.size() >= 2);
    ASSERT_EQ(content.front(), '{');
    ASSERT_EQ(content.back(), '}');
}

void HiperfLibReportTest::UnwindJsonContentCheck(const std::string &content, bool haveUnwind) const
{
    ASSERT_TRUE(content.size() >= 2);
    ASSERT_EQ(content.front(), '{');
    ASSERT_EQ(content.back(), '}');
#ifdef __arm__
    ASSERT_EQ(content.find("{\"symbol\":8,\"counts\":[0,0,1006548]}") != std::string::npos,
              haveUnwind);
#else
    ASSERT_EQ(content.find("{\"symbol\":16,\"counts\":[24,9065269,81271852]}") != std::string::npos,
              haveUnwind);
#endif
}

void HiperfLibReportTest::DefaultReportContentCheck(const std::string &content) const
{
    /*
<<Hiperf Report>>
hostname: localhost
osrelease: 5.10.57
arch: armv7l
cpudesc: ARMv7 Processor rev 5 (v7l)
cmdline: ./hiperf --verbose record -d 1 -a
hiperf_record_time: Thu Jan  1 00:38:40 1970
Samples Count: 1000
Record Count: 3329
Event Count: 174434595
    */

    // we found 198 times in report.txt
    size_t kernelKallsymsCount = 198;

    EXPECT_EQ(content.find("hostname: localhost") != std::string::npos, true);
    EXPECT_EQ(content.find("osrelease: 5.10.57") != std::string::npos, true);
    EXPECT_EQ(content.find("arch: armv7l") != std::string::npos, true);
    EXPECT_EQ(content.find("cpudesc: ARMv7 Processor rev 5 (v7l)") != std::string::npos, true);
    EXPECT_EQ(content.find("hiperf_record_time: Thu Jan  1 00:38:40 1970") != std::string::npos,
              true);
    EXPECT_EQ(content.find("cmdline: ./hiperf --verbose record -d 1 -a") != std::string::npos,
              true);

    EXPECT_EQ(content.find("Event: hw-cpu-cycles (type 0 id 0)") != std::string::npos, true);
    EXPECT_EQ(content.find("Samples Count: 1000") != std::string::npos, true);
    EXPECT_EQ(content.find("Event Count: 174434595") != std::string::npos, true);
    EXPECT_EQ(SubStringCount(content, "[kernel.kallsyms]"), kernelKallsymsCount);
}

void HiperfLibReportTest::DefaultDumpContentCheck(const std::string &content) const
{
    /*
magic: PERFILE2
header_size: 104
attr_size: 136
attrs[file section]: offset 112, size 136
data[file section]: offset 248, size 368316
event_types[file section]: offset 0, size 0
adds_features[]: 0x1DD8 0x0 0x0 0x5
feature: hostname
feature: osrelease
feature: arch
feature: nrcpus
feature: cpudesc
feature: total_mem
feature: cmdline
feature: event_desc
feature: hiperf_files_symbol
feature: hiperf_record_time
attr 1:
  event_attr:
    type 0, size 120, config 0
    sample_freq 4000
    sample_type (0x103e7)
    sample_type names: ip,tid,time,callchain,id,cpu,period,stream_id,identifier
    read_format (0x7)
    disabled 1, inherit 1, pinned 0, exclusive 0
    exclude_user 0, exclude_kernel 0, exclude_hv 0, exclude_idle 0
    mmap 1, mmap2 1, comm 1, comm_exec 0, freq 1
    inherit_stat 0, enable_on_exec 0, task 0, use_clockid 0
    watermark 0, precise_ip 0, mmap_data 1, clockid 0
    sample_id_all 0, exclude_host 0, exclude_guest 0
    branch_sample_type 0x0
    exclude_callchain_kernel 0, exclude_callchain_user 0
    sample_regs_user 0x0
    sample_stack_user 0x0
  ids: 12
    */

    size_t symbolsCount = 39;
    size_t buildIdCount = 32;
    size_t sampleCount = 1000;
    size_t featureCount = 10;

    EXPECT_EQ(content.find("magic: PERFILE2") != std::string::npos, true);
    EXPECT_EQ(SubStringCount(content, "fileid:"), symbolsCount);
    EXPECT_EQ(SubStringCount(content, "buildId:"), buildIdCount);
    EXPECT_EQ(SubStringCount(content, "record sample:"), sampleCount);
    EXPECT_EQ(SubStringCount(content, "feature:"), featureCount);
}
void HiperfLibReportTest::SetUpTestCase() {}

void HiperfLibReportTest::TearDownTestCase()
{
    DebugLogger::GetInstance()->Reset();
}

void HiperfLibReportTest::SetUp() {}

void HiperfLibReportTest::TearDown() {}

HWTEST_F(HiperfLibReportTest, Test_EchoLoopBackNumber, TestSize.Level1)
{
    const char *result = EchoLoopBack("123");
    EXPECT_EQ(result, "123");
}

HWTEST_F(HiperfLibReportTest, Test_EchoLoopBackString, TestSize.Level1)
{
    const char *result = EchoLoopBack("test");
    EXPECT_EQ(result, "test");
}

HWTEST_F(HiperfLibReportTest, Test_EchoLoopBackStringNumber, TestSize.Level1)
{
    const char *result = EchoLoopBack("test123");
    EXPECT_EQ(result, "test123");
}
HWTEST_F(HiperfLibReportTest, Test_EchoLoopBackEmpty, TestSize.Level1)
{
    const char *result = EchoLoopBack("");
    EXPECT_EQ(result, "");
}

HWTEST_F(HiperfLibReportTest, Test_EchoLoopBackNull, TestSize.Level1)
{
    const char *result = EchoLoopBack(nullptr);
    EXPECT_EQ(result, nullptr);
}

#ifdef HIPERF_DEBUG
HWTEST_F(HiperfLibReportTest, Test_SetDebug_Enable, TestSize.Level1)
{
    EXPECT_EQ(SetDebug(true), 0);
    EXPECT_EQ(DebugLogger::logDisabled_, false);
}

HWTEST_F(HiperfLibReportTest, Test_SetDebug_Disable, TestSize.Level1)
{
    EXPECT_EQ(SetDebug(false), 0);
    EXPECT_EQ(DebugLogger::logDisabled_, true);
}
#endif

HWTEST_F(HiperfLibReportTest, Test_Report_Success, TestSize.Level1)
{
    unlink(REPORT_OUTPUT_PATH);
    EXPECT_NE(access(REPORT_OUTPUT_PATH, F_OK), 0);

    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    EXPECT_EQ(::Report(PERF_DATA_INPUT_PATH, REPORT_OUTPUT_PATH, ""), 0);
    std::string stringOut = stdoutRecord.Stop();
    EXPECT_EQ(stringOut.find("report done") != std::string::npos, true);
    std::string content;
    EXPECT_EQ(ReadFileToString(REPORT_OUTPUT_PATH, content), true);
    DefaultReportContentCheck(content);
}

HWTEST_F(HiperfLibReportTest, Test_Report_Source_Null, TestSize.Level1)
{
    unlink(REPORT_OUTPUT_PATH);
    EXPECT_NE(access(REPORT_OUTPUT_PATH, F_OK), 0);
    EXPECT_NE(::Report(nullptr, REPORT_OUTPUT_PATH, ""), 0);
    EXPECT_NE(access(REPORT_OUTPUT_PATH, F_OK), 0);
}

HWTEST_F(HiperfLibReportTest, Test_Report_Target_Null, TestSize.Level1)
{
    unlink(REPORT_OUTPUT_PATH);
    EXPECT_NE(access(REPORT_OUTPUT_PATH, F_OK), 0);
    EXPECT_NE(::Report(PERF_DATA_INPUT_PATH, nullptr, ""), 0);
    EXPECT_NE(access(REPORT_OUTPUT_PATH, F_OK), 0);
}

HWTEST_F(HiperfLibReportTest, Test_Report_Both_Null, TestSize.Level1)
{
    unlink(REPORT_OUTPUT_PATH);
    EXPECT_NE(access(REPORT_OUTPUT_PATH, F_OK), 0);
    EXPECT_NE(::Report(nullptr, nullptr, ""), 0);
    EXPECT_NE(access(REPORT_OUTPUT_PATH, F_OK), 0);
}

HWTEST_F(HiperfLibReportTest, Test_Report_Parameter_Illegal, TestSize.Level1)
{
    unlink(REPORT_OUTPUT_PATH);
    EXPECT_NE(access(REPORT_OUTPUT_PATH, F_OK), 0);
    EXPECT_NE(::Report(ILLEGAL_PATH, ILLEGAL_PATH, ""), 0);
    EXPECT_NE(access(REPORT_OUTPUT_PATH, F_OK), 0);
    EXPECT_NE(access(ILLEGAL_PATH, F_OK), 0);
}

HWTEST_F(HiperfLibReportTest, Test_Report_Parameter_Empty, TestSize.Level1)
{
    unlink(REPORT_OUTPUT_PATH);
    EXPECT_NE(access(REPORT_OUTPUT_PATH, F_OK), 0);
    EXPECT_NE(::Report("", "", ""), 0);
    EXPECT_NE(access(REPORT_OUTPUT_PATH, F_OK), 0);
    EXPECT_NE(access(ILLEGAL_PATH, F_OK), 0);
}

HWTEST_F(HiperfLibReportTest, Test_Dump_Success, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    EXPECT_EQ(::Dump(PERF_DATA_INPUT_PATH), 0);
    std::string stringOut = stdoutRecord.Stop();
    DefaultDumpContentCheck(stringOut);
}

HWTEST_F(HiperfLibReportTest, Test_Dump_IllegalPath, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    EXPECT_NE(::Dump(ILLEGAL_PATH), 0);
}

HWTEST_F(HiperfLibReportTest, Test_ReportJson_Success, TestSize.Level1)
{
    unlink(REPORT_JSON_OUTPUT_PATH);
    EXPECT_NE(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);

    EXPECT_EQ(::ReportJson(PERF_DATA_INPUT_PATH, REPORT_JSON_OUTPUT_PATH), 0);
    EXPECT_EQ(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);
    std::string content;
    EXPECT_EQ(ReadFileToString(REPORT_JSON_OUTPUT_PATH, content), true);
    DefaultJsonContentCheck(content);
}

HWTEST_F(HiperfLibReportTest, Test_ReportJson_ErrorFormat, TestSize.Level1)
{
    unlink(REPORT_JSON_OUTPUT_PATH);
    EXPECT_NE(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);

    EXPECT_NE(::ReportJson(PERF_DATA_ERROR_FORMAT_INPUT_PATH, REPORT_JSON_OUTPUT_PATH), 0);
    if (access(REPORT_JSON_OUTPUT_PATH, F_OK) == 0) {
        std::string content;
        EXPECT_EQ(ReadFileToString(REPORT_JSON_OUTPUT_PATH, content), true);

        // have file but no content
        EXPECT_EQ(content.empty(), true);
    }
}

HWTEST_F(HiperfLibReportTest, Test_ReportJson_IllegalPath, TestSize.Level1)
{
    unlink(REPORT_JSON_OUTPUT_PATH);
    EXPECT_NE(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);

    EXPECT_NE(::ReportJson(ILLEGAL_PATH, ILLEGAL_PATH), 0);
    EXPECT_NE(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);
    EXPECT_NE(access(ILLEGAL_PATH, F_OK), 0);
}

HWTEST_F(HiperfLibReportTest, Test_ReportJson_Nullptr, TestSize.Level1)
{
    unlink(REPORT_JSON_OUTPUT_PATH);
    EXPECT_NE(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);

    EXPECT_NE(::ReportJson(nullptr, nullptr), 0);
    EXPECT_NE(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);
}

HWTEST_F(HiperfLibReportTest, Test_ReportJson_Empty, TestSize.Level1)
{
    unlink(REPORT_JSON_OUTPUT_PATH);
    EXPECT_NE(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);

    EXPECT_NE(::ReportJson("", ""), 0);
    EXPECT_NE(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);
}

HWTEST_F(HiperfLibReportTest, Test_ReportGetSymbolFiles_Success, TestSize.Level1)
{
    const char *result = ReportGetSymbolFiles(PERF_DATA_INPUT_PATH);
    ASSERT_NE(result, nullptr);
    DefaultSymbolsBuildIdContentCheck(result);
}

HWTEST_F(HiperfLibReportTest, Test_ReportGetSymbolFiles_ErrorFormat, TestSize.Level1)
{
    const char *result = ReportGetSymbolFiles(PERF_DATA_ERROR_FORMAT_INPUT_PATH);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result[0], '\0');
}

HWTEST_F(HiperfLibReportTest, Test_ReportGetSymbolFiles_IllegalPath, TestSize.Level1)
{
    const char *result = ReportGetSymbolFiles(ILLEGAL_PATH);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result[0], '\0');
}

HWTEST_F(HiperfLibReportTest, Test_ReportGetSymbolFiles_Nullptr, TestSize.Level1)
{
    const char *result = ReportGetSymbolFiles(nullptr);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result[0], '\0');
}

HWTEST_F(HiperfLibReportTest, Test_ReportGetSymbolFiles_Empty, TestSize.Level1)
{
    const char *result = ReportGetSymbolFiles("");
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result[0], '\0');
}

HWTEST_F(HiperfLibReportTest, Test_ReportGetBuildId_32_Success, TestSize.Level1)
{
    const char *result = ReportGetBuildId(TEST_ELF32);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, BUILDID_TEST_ELF32);
}

HWTEST_F(HiperfLibReportTest, Test_ReportGetBuildId_64_Success, TestSize.Level1)
{
    const char *result = ReportGetBuildId(TEST_ELF64);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, BUILDID_TEST_ELF64);
}

HWTEST_F(HiperfLibReportTest, Test_ReportGetBuildId_Empty, TestSize.Level1)
{
    const char *result = ReportGetBuildId("");
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, "");
}

HWTEST_F(HiperfLibReportTest, Test_ReportGetBuildId_Nullptr, TestSize.Level1)
{
    const char *result = ReportGetBuildId(TEST_ELF_BROKEN);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, "");
}

HWTEST_F(HiperfLibReportTest, Test_ReportGetBuildId_IllegalPath, TestSize.Level1)
{
    const char *result = ReportGetBuildId(ILLEGAL_PATH);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, "");
}

HWTEST_F(HiperfLibReportTest, Test_ReportUnwindJson_Success, TestSize.Level1)
{
    unlink(REPORT_JSON_OUTPUT_PATH);
    EXPECT_NE(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);

    EXPECT_EQ(::ReportUnwindJson(PERF_DISABLE_UNWIND_DATA_INPUT_PATH, REPORT_JSON_OUTPUT_PATH,
                                 PERF_DISABLE_UNWIND_SYMBOL_INPUT_PATH),
              0);
    EXPECT_EQ(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);
    std::string content;
    EXPECT_EQ(ReadFileToString(REPORT_JSON_OUTPUT_PATH, content), true);
    UnwindJsonContentCheck(content, true);
}

HWTEST_F(HiperfLibReportTest, Test_ReportUnwindJson_NoSymbols_Failed, TestSize.Level1)
{
    unlink(REPORT_JSON_OUTPUT_PATH);
    EXPECT_NE(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);

    EXPECT_EQ(
        ::ReportUnwindJson(PERF_DISABLE_UNWIND_DATA_INPUT_PATH, REPORT_JSON_OUTPUT_PATH, nullptr),
        0);
    EXPECT_EQ(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);
    std::string content;
    EXPECT_EQ(ReadFileToString(REPORT_JSON_OUTPUT_PATH, content), true);
    UnwindJsonContentCheck(content, false);
}

HWTEST_F(HiperfLibReportTest, Test_ReportUnwindJson_ErrorFormat, TestSize.Level1)
{
    unlink(REPORT_JSON_OUTPUT_PATH);
    EXPECT_NE(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);

    EXPECT_NE(::ReportUnwindJson(PERF_DATA_ERROR_FORMAT_INPUT_PATH, REPORT_JSON_OUTPUT_PATH,
                                 PERF_DISABLE_UNWIND_SYMBOL_INPUT_PATH),
              0);
    if (access(REPORT_JSON_OUTPUT_PATH, F_OK) == 0) {
        std::string content;
        EXPECT_EQ(ReadFileToString(REPORT_JSON_OUTPUT_PATH, content), true);

        // have file but no content
        EXPECT_EQ(content.empty(), true);
    }
}

HWTEST_F(HiperfLibReportTest, Test_ReportUnwindJson_IllegalPath, TestSize.Level1)
{
    unlink(REPORT_JSON_OUTPUT_PATH);
    EXPECT_NE(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);

    EXPECT_NE(::ReportUnwindJson(ILLEGAL_PATH, ILLEGAL_PATH, ILLEGAL_PATH), 0);
    EXPECT_NE(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);
    EXPECT_NE(access(ILLEGAL_PATH, F_OK), 0);
}

HWTEST_F(HiperfLibReportTest, Test_ReportUnwindJson_Nullptr, TestSize.Level1)
{
    unlink(REPORT_JSON_OUTPUT_PATH);
    EXPECT_NE(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);

    EXPECT_NE(::ReportUnwindJson(nullptr, nullptr, nullptr), 0);
    EXPECT_NE(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);
}

HWTEST_F(HiperfLibReportTest, Test_ReportUnwindJson_Empty, TestSize.Level1)
{
    unlink(REPORT_JSON_OUTPUT_PATH);
    EXPECT_NE(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);

    EXPECT_NE(::ReportUnwindJson("", "", ""), 0);
    EXPECT_NE(access(REPORT_JSON_OUTPUT_PATH, F_OK), 0);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
