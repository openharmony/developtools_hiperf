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

#include "cpu_usage_test.h"
#include "test_utilities.h"
using namespace testing::ext;
using namespace std::chrono;
namespace OHOS {
namespace Developtools {
namespace Hiperf {
class CpuUsageTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    pid_t GetPidByProcessName(const std::string& procName);

    int GetVmRSSLine(pid_t pid);

    const char* GetItems(const char* buffer, unsigned int item);

    unsigned long GetCpuTotalUsage();

    unsigned long GetCpuProcUsage(int pid);

    float GetCpuUsageRatio(int pid);

    float GetAverageCpuUsage(pid_t pid, uint64_t timeOut);

    void TestCpuUsage(const std::string &option, unsigned int expect, bool fixPid);

    std::string testProcesses = "com.ohos.sceneboard";
};

void CpuUsageTest::SetUpTestCase() {}

void CpuUsageTest::TearDownTestCase() {}

void CpuUsageTest::SetUp()
{
    if (!HiPerf::CheckTestApp(testProcesses)) {
        testProcesses = "com.ohos.launcher";
    }
}

void CpuUsageTest::TearDown() {}

pid_t CpuUsageTest::GetPidByProcessName(const std::string& procName)
{
    FILE *fp = nullptr;
    char buf[100]; // 100: buf size
    pid_t pid = -1;
    std::string cmd = "pidof " + procName;
    if ((fp = popen(cmd.c_str(), "r")) != nullptr) {
        if (fgets(buf, sizeof(buf), fp) != nullptr) {
            pid = atoi(buf);
        }
        pclose(fp);
    }
    return pid;
}

int CpuUsageTest::GetVmRSSLine(pid_t pid)
{
    int line = 0;
    std::string fileName = "/proc" + std::to_string(pid) + "/stat";
    std::ifstream in(fileName, std::ios::in);
    std::string tmp;
    if (in.fail()) {
        return 0;
    } else {
        while (getline(in, tmp)) {
            line++;
            if (tmp.find("VmRSS")) {
                return line;
            }
        }
    }
    in.close();
    return -1;
}

const char* CpuUsageTest::GetItems(const char* buffer, unsigned int item)
{
    // read from buffer by offset
    const char* p = buffer;
    int len = strlen(buffer);
    unsigned int count = 0;
    for (int i = 0; i < len; ++i) {
        if (*p == ' ') {
            count++;
            if (count == item - 1) {
                p++;
                break;
            }
        }
        p++;
    }
    return p;
}

unsigned long CpuUsageTest::GetCpuTotalUsage()
{
    // get total cpu usage time from /proc/stat

    // different mode cpu usage time
    unsigned long userTime;
    unsigned long niceTime;
    unsigned long systemTime;
    unsigned long idleTime;

    FILE *fd = nullptr;
    char buff[1024] = {0};
    std::string fileName = "/proc/stat";
    fd = fopen(fileName.c_str(), "r");
    if (fd == nullptr) {
        return 0;
    }
    fgets (buff, sizeof(buff), fd);
    char name[64] = {0};
    // get first line cpu time data
    std::stringstream stream;
    stream << buff;
    stream >> name >> userTime >> niceTime >> systemTime >> idleTime;
    fclose(fd);
    stream.clear();
    return (userTime + niceTime + systemTime + idleTime);
}

unsigned long CpuUsageTest::GetCpuProcUsage(int pid)
{
    // get cpu usage of specific pid

    unsigned int tmpPid;
    unsigned long utime; // user time
    unsigned long stime; // kernel time
    unsigned long cutime; // all usertime
    unsigned long cstime; // all dead time

    FILE *fd = nullptr;
    char lineBuff[1024] = {0};
    std::string fileName = "/proc" + std::to_string(pid) + "/stat";
    fd = fopen(fileName.c_str(), "r");
    if (fd == nullptr) {
        return 0;
    }
    fgets(lineBuff, sizeof(lineBuff), fd);
    std::stringstream stream;
    stream << lineBuff;
    stream >> tmpPid;
    const char* q = GetItems(lineBuff, PROCESS_ITEM);
    stream.clear();
    stream << q;
    stream >> utime >> stime >> cutime >> cstime;
    fclose(fd);

    return (utime + stime + cutime + cstime);
}

float CpuUsageTest::GetCpuUsageRatio(int pid)
{
    unsigned long totalCpuTimepPrev;
    unsigned long totalcputimeCur;
    unsigned long procCpuTimepPrev;
    unsigned long proccputimeCur;

    totalCpuTimepPrev = GetCpuTotalUsage();
    procCpuTimepPrev = GetCpuProcUsage(pid);

    // sleep 200ms to get two point cpu usage snapshots
    int timeInterval = 200000;
    usleep(timeInterval);

    totalcputimeCur = GetCpuTotalUsage();
    proccputimeCur = GetCpuProcUsage(pid);

    float pcpu = 0.0;
    if (totalcputimeCur - totalCpuTimepPrev != 0) {
        pcpu = (proccputimeCur - procCpuTimepPrev) / float(totalcputimeCur - totalCpuTimepPrev);
    }

    int cpuNum = get_nprocs();
    // multi cpu machine should multiply cpu number
    pcpu *= cpuNum;
    return pcpu;
}

float CpuUsageTest::GetAverageCpuUsage(pid_t pid, uint64_t timeOut)
{
    float cpuUsage = 0.0;
    int count = 0;
    auto startTime = std::chrono::steady_clock::now();
    while (true) {
        ++count;
        cpuUsage += GetCpuUsageRatio(pid);
        auto thisTime = std::chrono::steady_clock::now();
        if ((uint64_t)duration_cast<milliseconds>(thisTime - startTime).count()
            > timeOut) {
                break;
            }
    }
    cpuUsage =  HUNDRED * cpuUsage / count;
    return cpuUsage;
}

void CpuUsageTest::TestCpuUsage(const std::string &option, unsigned int expect, bool fixPid)
{
    std::string cmd = "hiperf record ";
    if (fixPid) {
        cmd += "--app ";
        cmd += " " + testProcesses;
    }
    cmd += " " + option;

    std::thread perf(system, cmd.c_str());
    perf.detach();
    pid_t pid = GetPidByProcessName("hiperf");
    uint64_t timeOut = 10000;
    float cpuUsage = GetAverageCpuUsage(pid, timeOut);

    EXPECT_LE(cpuUsage, expect);
}

/**
 * @tc.name: recordCpuUsageF100_FP_SYSTEM
 * @tc.desc: test hiperf record system wide cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF100_FP_SYSTEM, TestSize.Level1)
{
    TestCpuUsage("-a -f 100 -s fp -d 10", F100_FP_CPU_LIMIT_SYSTEM, false);
}

/**
 * @tc.name: recordCpuUsageF500_FP_SYSTEM
 * @tc.desc: test hiperf record system wide cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF500_FP_SYSTEM, TestSize.Level1)
{
    TestCpuUsage("-a -f 500 -s fp -d 10", F500_FP_CPU_LIMIT_SYSTEM, false);
}

/**
 * @tc.name: recordCpuUsageF1000_FP_SYSTEM
 * @tc.desc: test hiperf record system wide cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF1000_FP_SYSTEM, TestSize.Level1)
{
    TestCpuUsage("-a -f 1000 -s fp -d 10", F1000_FP_CPU_LIMIT_SYSTEM, false);
}

/**
 * @tc.name: recordCpuUsageF2000_FP_SYSTEM
 * @tc.desc: test hiperf record system wide cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF2000_FP_SYSTEM, TestSize.Level1)
{
    TestCpuUsage("-a -f 2000 -s fp -d 10", F2000_FP_CPU_LIMIT_SYSTEM, false);
}

/**
 * @tc.name: recordCpuUsageF4000_FP_SYSTEM
 * @tc.desc: test hiperf record system wide cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF4000_FP_SYSTEM, TestSize.Level1)
{
    TestCpuUsage("-a -f 4000 -s fp -d 10", F4000_FP_CPU_LIMIT_SYSTEM, false);
}

/**
 * @tc.name: recordCpuUsageF8000_FP_SYSTEM
 * @tc.desc: test hiperf record system wide cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF8000_FP_SYSTEM, TestSize.Level1)
{
    TestCpuUsage("-a -f 8000 -s fp -d 10", F8000_FP_CPU_LIMIT_SYSTEM, false);
}

/**
 * @tc.name: recordCpuUsageF100_DWARF_SYSTEM
 * @tc.desc: test hiperf record system wide cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF100_DWARF_SYSTEM, TestSize.Level1)
{
    TestCpuUsage("-a -f 100 -s dwarf -d 10", F100_DWARF_CPU_LIMIT_SYSTEM, false);
}

/**
 * @tc.name: recordCpuUsageF500_DWARF_SYSTEM
 * @tc.desc: test hiperf record system wide cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF500_DWARF_SYSTEM, TestSize.Level1)
{
    TestCpuUsage("-a -f 500 -s dwarf -d 10", F500_DWARF_CPU_LIMIT_SYSTEM, false);
}

/**
 * @tc.name: recordCpuUsageF1000_DWARF_SYSTEM
 * @tc.desc: test hiperf record system wide cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF1000_DWARF_SYSTEM, TestSize.Level1)
{
    TestCpuUsage("-a -f 1000 -s dwarf -d 10", F1000_DWARF_CPU_LIMIT_SYSTEM, false);
}

/**
 * @tc.name: recordCpuUsageF2000_DWARF_SYSTEM
 * @tc.desc: test hiperf record system wide cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF2000_DWARF_SYSTEM, TestSize.Level1)
{
    TestCpuUsage("-a -f 2000 -s dwarf -d 10", F2000_DWARF_CPU_LIMIT_SYSTEM, false);
}

/**
 * @tc.name: recordCpuUsageF4000_DWARF_SYSTEM
 * @tc.desc: test hiperf record system wide cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF4000_DWARF_SYSTEM, TestSize.Level1)
{
    TestCpuUsage("-a -f 4000 -s dwarf -d 10", F4000_DWARF_CPU_LIMIT_SYSTEM, false);
}

/**
 * @tc.name: recordCpuUsageF8000_DWARF_SYSTEM
 * @tc.desc: test hiperf record system wide cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF8000_DWARF_SYSTEM, TestSize.Level1)
{
    TestCpuUsage("-a -f 8000 -s dwarf -d 10", F8000_DWARF_CPU_LIMIT_SYSTEM, false);
}

/**
 * @tc.name: recordCpuUsageF100_FP_PROCESS
 * @tc.desc: test hiperf record one process cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF100_FP_PROCESS, TestSize.Level1)
{
    TestCpuUsage("-f 100 -s fp -d 10", F100_FP_CPU_LIMIT_PROCESS, true);
}

/**
 * @tc.name: recordCpuUsageF500_FP_PROCESS
 * @tc.desc: test hiperf record one process cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF500_FP_PROCESS, TestSize.Level1)
{
    TestCpuUsage("-f 500 -s fp -d 10", F500_FP_CPU_LIMIT_PROCESS, true);
}

/**
 * @tc.name: recordCpuUsageF1000_FP_PROCESS
 * @tc.desc: test hiperf record one process cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF1000_FP_PROCESS, TestSize.Level1)
{
    TestCpuUsage("-f 1000 -s fp -d 10", F1000_FP_CPU_LIMIT_PROCESS, true);
}

/**
 * @tc.name: recordCpuUsageF2000_FP_PROCESS
 * @tc.desc: test hiperf record one process cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF2000_FP_PROCESS, TestSize.Level1)
{
    TestCpuUsage("-f 2000 -s fp -d 10", F2000_FP_CPU_LIMIT_PROCESS, true);
}

/**
 * @tc.name: recordCpuUsageF4000_FP_PROCESS
 * @tc.desc: test hiperf record one process cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF4000_FP_PROCESS, TestSize.Level1)
{
    TestCpuUsage("-f 4000 -s fp -d 10", F4000_FP_CPU_LIMIT_PROCESS, true);
}

/**
 * @tc.name: recordCpuUsageF8000_FP_PROCESS
 * @tc.desc: test hiperf record one process cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF8000_FP_PROCESS, TestSize.Level1)
{
    TestCpuUsage("-f 8000 -s fp -d 10", F8000_FP_CPU_LIMIT_PROCESS, true);
}

/**
 * @tc.name: recordCpuUsageF100_DWARF_PROCESS
 * @tc.desc: test hiperf record one process cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF100_DWARF_PROCESS, TestSize.Level1)
{
    TestCpuUsage("-f 100 -s dwarf -d 10", F100_DWARF_CPU_LIMIT_PROCESS, true);
}

/**
 * @tc.name: recordCpuUsageF500_DWARF_PROCESS
 * @tc.desc: test hiperf record one process cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF500_DWARF_PROCESS, TestSize.Level1)
{
    TestCpuUsage("-f 500 -s dwarf -d 10", F500_DWARF_CPU_LIMIT_PROCESS, true);
}

/**
 * @tc.name: recordCpuUsageF1000_DWARF_PROCESS
 * @tc.desc: test hiperf record one process cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF1000_DWARF_PROCESS, TestSize.Level1)
{
    TestCpuUsage("-f 1000 -s dwarf -d 10", F1000_DWARF_CPU_LIMIT_PROCESS, true);
}

/**
 * @tc.name: recordCpuUsageF2000_DWARF_PROCESS
 * @tc.desc: test hiperf record one process cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF2000_DWARF_PROCESS, TestSize.Level1)
{
    TestCpuUsage("-f 2000 -s dwarf -d 10", F2000_DWARF_CPU_LIMIT_PROCESS, true);
}

/**
 * @tc.name: recordCpuUsageF4000_DWARF_PROCESS
 * @tc.desc: test hiperf record one process cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF4000_DWARF_PROCESS, TestSize.Level1)
{
    TestCpuUsage("-f 4000 -s dwarf -d 10", F4000_DWARF_CPU_LIMIT_PROCESS, true);
}

/**
 * @tc.name: recordCpuUsageF8000_DWARF_PROCESS
 * @tc.desc: test hiperf record one process cpu usage within required limit
 * @tc.type: FUNC
 */
HWTEST_F(CpuUsageTest, recordCpuUsageF8000_DWARF_PROCESS, TestSize.Level1)
{
    TestCpuUsage("-f 8000 -s dwarf -d 10", F8000_DWARF_CPU_LIMIT_PROCESS, true);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
