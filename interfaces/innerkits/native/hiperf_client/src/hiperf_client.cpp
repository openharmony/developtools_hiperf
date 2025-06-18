/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hiperf_client.h"
#include <sys/wait.h>
#include <algorithm>
#include <cinttypes>
#include <csignal>
#include <cstring>
#include <thread>
#include <poll.h>
#include <sys/prctl.h>
#include <unistd.h>
#include "hiperf_hilog.h"

using namespace std::chrono;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
namespace HiperfClient {
static const std::string HIPERF_COMMAND_NAME = "hiperf";
static const std::string SYSTEM_BIN_PATH = "/system/bin/";
static const std::string CURRENT_PATH = "./";
static const std::string PERF_DATA_NAME = "perf.data";
static const std::string COMMAND_RECORD = "record";
static const std::string ARG_OUTPUT_PATH = "-o";
static const std::string ARG_DEBUG = "--verbose";
static const std::string ARG_DEBUG_MUCH = "--much";
static const std::string ARG_HILOG = "--hilog";
static const std::string ARG_PIPE_INPUT = "--pipe_input";
static const std::string ARG_PIPE_OUTPUT = "--pipe_output";
static const std::string ARG_TARGET_SYSTEM_WIDE = "-a";
static const std::string ARG_COMPRESS_DATA = "-z";
static const std::string ARG_SELECT_CPUS = "-c";
static const std::string ARG_TIME_STOP_SEC = "-d";
static const std::string ARG_FREQUENCY = "-f";
static const std::string ARG_PERIOD = "--period";
static const std::string ARG_SELECT_EVENTS = "-e";
static const std::string ARG_SELECT_GROUPS = "-g";
static const std::string ARG_NO_INHERIT = "--no-inherit";
static const std::string ARG_SELECT_PIDS = "-p";
static const std::string ARG_SELECT_TIDS = "-t";
static const std::string ARG_EXCLUDE_PERF = "--exclude-hiperf";
static const std::string ARG_CPU_PERCENT = "--cpu-limit";
static const std::string ARG_OFF_CPU = "--offcpu";
static const std::string ARG_CALL_GRAPH = "--call-stack";
static const std::string ARG_DELAY_UNWIND = "--delay-unwind";
static const std::string ARG_DISABLE_UNWIND = "--disable-unwind";
static const std::string ARG_DISABLE_CALLSTACK_MERGE = "--disable-callstack-expand";
static const std::string ARG_SYMBOL_DIR = "--symbol-dir";
static const std::string ARG_DATA_LIMIT = "--data-limit";
static const std::string ARG_APP_PACKAGE = "--app";
static const std::string ARG_CLOCK_ID = "--clockid";
static const std::string ARG_VEC_BRANCH_SAMPLE_TYPES = "-j";
static const std::string ARG_MMAP_PAGES = "-m";
static const std::string ARG_REPORT = "--report";
static const std::string ARG_EXCLUDE_PROCESS = "--exclude-process";
static const std::string ARG_BACKTRACK = "--backtrack";
static const std::string ARG_BACKTRACK_SEC = "--backtrack-sec";

static constexpr int DEFAULT_DURATION_TIME = 10;
static constexpr int DEFAULT_FREQUENCY_TIME = 100;
static constexpr uint64_t PIPE_READ = 0;
static constexpr uint64_t PIPE_WRITE = 1;
static constexpr ssize_t ERRINFOLEN = 512;
static constexpr size_t SIZE_ARGV_TAIL = 1; // nullptr

void RecordOption::SetOption(const std::string &name, bool enable)
{
    auto it = std::find(args_.begin(), args_.end(), name);
    if (enable) {
        if (it == args_.end()) {
            args_.emplace_back(name);
        }

        return;
    }
    if (it != args_.end()) {
        args_.erase(it);
        return;
    }
}

void RecordOption::SetOption(const std::string &name, int value)
{
    auto it = std::find(args_.begin(), args_.end(), name);
    if (it != args_.end()) {
        it++;
        *it = std::to_string(value);
        return;
    }

    args_.emplace_back(name);
    args_.emplace_back(std::to_string(value));
    return;
}

void RecordOption::SetOption(const std::string &name, const std::vector<int> &vInt)
{
    auto it = std::find(args_.begin(), args_.end(), name);
    if (vInt.empty()) {
        if (it != args_.end()) {
            it = args_.erase(it); // remove key
            if (it != args_.end()) {
                args_.erase(it); // remove value
            }
        }
        return;
    }

    std::string str;
    for (auto n : vInt) {
        str.append(std::to_string(n));
        str.append(",");
    }
    str.pop_back(); // remove the last ','

    if (it != args_.end()) {
        it++;
        *it = str;
        return;
    }
    args_.emplace_back(name);
    args_.emplace_back(str);
}

void RecordOption::SetOption(const std::string &name, const std::string &str)
{
    auto it = std::find(args_.begin(), args_.end(), name);
    if (str.empty()) {
        if (it != args_.end()) {
            args_.erase(it);
            args_.erase(it); // remove value
        }
        return;
    }
    if (it != args_.end()) {
        it++;
        *it = str;
        return;
    }
    args_.emplace_back(name);
    args_.emplace_back(str);
}

void RecordOption::SetOption(const std::string &name, const std::vector<std::string> &vStr)
{
    auto it = std::find(args_.begin(), args_.end(), name);
    if (vStr.empty()) {
        if (it != args_.end()) {
            args_.erase(it);
            args_.erase(it); // remove value
        }
        return;
    }

    std::string str;
    for (auto substr : vStr) {
        str.append(substr);
        str.append(",");
    }
    str.pop_back(); // remove the last ','

    if (it != args_.end()) {
        it++;
        *it = str;
        return;
    }
    args_.emplace_back(name);
    args_.emplace_back(str);
}

void RecordOption::SetTargetSystemWide(bool enable)
{
    SetOption(ARG_TARGET_SYSTEM_WIDE, enable);
}

void RecordOption::SetCompressData(bool enable)
{
    SetOption(ARG_COMPRESS_DATA, enable);
}

void RecordOption::SetSelectCpus(const std::vector<int> &cpus)
{
    SetOption(ARG_SELECT_CPUS, cpus);
}

void RecordOption::SetTimeStopSec(int timeStopSec)
{
    this->timeSpec_ = true;
    SetOption(ARG_TIME_STOP_SEC, timeStopSec);
}

void RecordOption::SetFrequency(int frequency)
{
    SetOption(ARG_FREQUENCY, frequency);
}

void RecordOption::SetPeriod(int period)
{
    SetOption(ARG_PERIOD, period);
}

void RecordOption::SetSelectEvents(const std::vector<std::string> &selectEvents)
{
    SetOption(ARG_SELECT_EVENTS, selectEvents);
}

void RecordOption::SetSelectGroups(const std::vector<std::string> &selectGroups)
{
    SetOption(ARG_SELECT_GROUPS, selectGroups);
}

void RecordOption::SetNoInherit(bool enable)
{
    SetOption(ARG_NO_INHERIT, enable);
}

void RecordOption::SetSelectPids(const std::vector<pid_t> &selectPids)
{
    SetOption(ARG_SELECT_PIDS, selectPids);
}

void RecordOption::SetCallStackSamplingConfigs(int duration)
{
    if (duration <= 0) {
        duration = DEFAULT_DURATION_TIME;
    }
    RecordOption opt;
    SetSelectEvents(opt.GetSelectEvents());
    SetTimeStopSec(duration);
    SetFrequency(DEFAULT_FREQUENCY_TIME);
    SetCallGraph("fp");
}

void RecordOption::SetSelectTids(const std::vector<pid_t> &selectTids)
{
    SetOption(ARG_SELECT_TIDS, selectTids);
}

void RecordOption::SetExcludePerf(bool excludePerf)
{
    SetOption(ARG_EXCLUDE_PERF, excludePerf);
}

void RecordOption::SetCpuPercent(int cpuPercent)
{
    SetOption(ARG_CPU_PERCENT, cpuPercent);
}

void RecordOption::SetOffCPU(bool offCPU)
{
    SetOption(ARG_OFF_CPU, offCPU);
}

void RecordOption::SetCallGraph(const std::string &callGraph)
{
    SetOption(ARG_CALL_GRAPH, callGraph);
}

void RecordOption::SetDelayUnwind(bool delayUnwind)
{
    SetOption(ARG_DELAY_UNWIND, delayUnwind);
}

void RecordOption::SetDisableUnwind(bool disableUnwind)
{
    SetOption(ARG_DISABLE_UNWIND, disableUnwind);
}

void RecordOption::SetDisableCallstackMerge(bool disableCallstackMerge)
{
    SetOption(ARG_DISABLE_CALLSTACK_MERGE, disableCallstackMerge);
}

void RecordOption::SetSymbolDir(const std::string &symbolDir_)
{
    SetOption(ARG_SYMBOL_DIR, symbolDir_);
}

void RecordOption::SetDataLimit(const std::string &limit)
{
    SetOption(ARG_DATA_LIMIT, limit);
}

void RecordOption::SetAppPackage(const std::string &appPackage)
{
    SetOption(ARG_APP_PACKAGE, appPackage);
}

void RecordOption::SetClockId(const std::string &clockId)
{
    SetOption(ARG_CLOCK_ID, clockId);
}

void RecordOption::SetVecBranchSampleTypes(const std::vector<std::string> &vecBranchSampleTypes)
{
    SetOption(ARG_VEC_BRANCH_SAMPLE_TYPES, vecBranchSampleTypes);
}

void RecordOption::SetMmapPages(int mmapPages)
{
    SetOption(ARG_MMAP_PAGES, mmapPages);
}

void RecordOption::SetReport(bool report)
{
    SetOption(ARG_REPORT, report);
}

void RecordOption::SetExcludeProcess(const std::vector<std::string> &excludeProcess)
{
    SetOption(ARG_EXCLUDE_PROCESS, excludeProcess);
}
void RecordOption::SetBackTrack(bool backtrack)
{
    SetOption(ARG_BACKTRACK, backtrack);
}
void RecordOption::SetBackTrackSec(int backTracesec)
{
    SetOption(ARG_BACKTRACK_SEC, backTracesec);
}

Client::Client(const std::string &outputDir)
{
    HIPERF_HILOGI(MODULE_CPP_API, "%" HILOG_PUBLIC "s default init with %" HILOG_PUBLIC "s\n",
                  __FUNCTION__, outputDir.c_str());
    Setup(outputDir);
}

bool Client::Setup(std::string outputDir)
{
    std::string SystemCommandPath = SYSTEM_BIN_PATH + HIPERF_COMMAND_NAME;

    if (!outputDir.empty() && outputDir.back() != '/') {
        outputDir.push_back('/');
    }
    HIPERF_HILOGI(MODULE_CPP_API, "outputDir setup to %" HILOG_PUBLIC "s\n", outputDir.c_str());

    executeCommandPath_ = SystemCommandPath;

    // check output path
    // found command path
    if (access(outputDir.c_str(), W_OK) == 0) {
        outputDir_ = outputDir;
    } else if (access(CURRENT_PATH.c_str(), W_OK) == 0) {
        outputDir_ = CURRENT_PATH;
    } else {
        HIPERF_HILOGI(MODULE_CPP_API, "no writeable output path found\n");
        return ready_;
    }
    outputFileName_ = PERF_DATA_NAME;

    myPid_ = getpid();

    // every thing check ok
    ready_ = true;

    return ready_;
}

Client::~Client()
{
    KillChild();
}

bool Client::IsReady()
{
    return ready_;
}

void Client::SetDebugMode()
{
    debug_ = true;
}

void Client::SetDebugMuchMode()
{
    debugMuch_ = true;
}

bool Client::Start()
{
    HIPERF_HILOGI(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);

    std::vector<std::string> args;
    args.push_back("-p");
    args.push_back(std::to_string(getpid()));
    return Start(args);
}

void Client::PrepareExecCmd(std::vector<std::string> &cmd)
{
    cmd.clear();
    cmd.emplace_back(executeCommandPath_);

    if (debug_) {
        cmd.emplace_back(ARG_DEBUG);
    } else if (debugMuch_) {
        cmd.emplace_back(ARG_DEBUG_MUCH);
    }

    if (hilog_) {
        cmd.emplace_back(ARG_HILOG);
    }

    cmd.emplace_back(COMMAND_RECORD);
    cmd.emplace_back(ARG_OUTPUT_PATH);
    cmd.emplace_back(GetOutputPerfDataPath());
}

void Client::GetExecCmd(std::vector<std::string> &cmd, int pipeIn, int pipeOut,
                        const std::vector<std::string> &args)
{
    PrepareExecCmd(cmd);
    cmd.emplace_back(ARG_PIPE_INPUT);
    cmd.emplace_back(std::to_string(pipeIn));
    cmd.emplace_back(ARG_PIPE_OUTPUT);
    cmd.emplace_back(std::to_string(pipeOut));

    cmd.insert(cmd.end(), args.begin(), args.end());
}

void Client::GetExecCmd(std::vector<std::string> &cmd,
                        const std::vector<std::string> &args)
{
    PrepareExecCmd(cmd);

    cmd.insert(cmd.end(), args.begin(), args.end());
}

bool Client::Start(const std::vector<std::string> &args, bool immediately)
{
    HIPERF_HILOGI(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);
    if (!ready_) {
        HIPERF_HILOGI(MODULE_CPP_API, "Client:hiperf not ready.\n");
        return false;
    }

    int clientToServerFd[2];
    int serverToClientFd[2];
    if (pipe(clientToServerFd) != 0) {
        char errInfo[ERRINFOLEN] = { 0 };
        strerror_r(errno, errInfo, ERRINFOLEN);
        HIPERF_HILOGI(MODULE_CPP_API, "failed to create pipe: %" HILOG_PUBLIC "s", errInfo);
        return false;
    } else if (pipe(serverToClientFd) != 0) {
        char errInfo[ERRINFOLEN] = { 0 };
        strerror_r(errno, errInfo, ERRINFOLEN);
        HIPERF_HILOGI(MODULE_CPP_API, "failed to create pipe: %" HILOG_PUBLIC "s", errInfo);
        close(clientToServerFd[PIPE_READ]);
        close(clientToServerFd[PIPE_WRITE]);
        return false;
    }

    hperfPrePid_ = fork();
    if (hperfPrePid_ == -1) {
        char errInfo[ERRINFOLEN] = { 0 };
        strerror_r(errno, errInfo, ERRINFOLEN);
        HIPERF_HILOGI(MODULE_CPP_API, "failed to fork: %" HILOG_PUBLIC "s", errInfo);
        close(clientToServerFd[PIPE_READ]);
        close(clientToServerFd[PIPE_WRITE]);
        close(serverToClientFd[PIPE_READ]);
        close(serverToClientFd[PIPE_WRITE]);
        return false;
    } else if (hperfPrePid_ == 0) {
        // child process
        close(clientToServerFd[PIPE_WRITE]);
        close(serverToClientFd[PIPE_READ]);

        std::vector<std::string> cmd;
        GetExecCmd(cmd, clientToServerFd[PIPE_READ], serverToClientFd[PIPE_WRITE], args);
        ChildRunExecv(cmd);
    } else {
        // parent process
        close(clientToServerFd[PIPE_READ]);
        close(serverToClientFd[PIPE_WRITE]);

        clientToServerFd_ = clientToServerFd[PIPE_WRITE];
        serverToClientFd_ = serverToClientFd[PIPE_READ];
    }
    using namespace std::chrono_literals;
    if (!WaitCommandReply(2000ms)) {
        HIPERF_HILOGI(MODULE_CPP_API, "start failed . lets kill it");
        KillChild();
        return false;
    }
    if (immediately) {
        return StartRun();
    }
    return true;
}

bool Client::Start(const RecordOption &option)
{
    HIPERF_HILOGI(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);
    if (!option.GetOutputFileName().empty()) {
        outputFileName_ = option.GetOutputFileName();
    }
    if (option.IsTimeSpecified()) {
        return RunHiperfCmdSync(option);
    }
    return Start(option.GetOptionVecString());
}

void Client::ChildRunExecv(std::vector<std::string> &cmd)
{
    // conver vector to array for execvp()
    char *argv[cmd.size() + SIZE_ARGV_TAIL];
    size_t i = 0;
    for (i = 0; i < cmd.size(); ++i) {
        HIPERF_HILOGI(MODULE_CPP_API, "args %" HILOG_PUBLIC "zu : %" HILOG_PUBLIC "s", i,
                        cmd[i].c_str());
        argv[i] = cmd[i].data();
    }
    argv[i] = nullptr;

    execv(argv[0], argv);

    // never reach the following line, unless calling of execv function failed.
    char errInfo[ERRINFOLEN] = { 0 };
    strerror_r(errno, errInfo, ERRINFOLEN);
    HIPERF_HILOGI(MODULE_CPP_API,
            "failed to call exec: '%" HILOG_PUBLIC "s' %" HILOG_PUBLIC "s\n",
            executeCommandPath_.c_str(), errInfo);
    exit(EXIT_FAILURE); // EXIT_FAILURE 1
}

bool Client::ParentWait(pid_t &wpid, pid_t pid, int &childStatus)
{
    bool ret = false;
    do {
        // blocking...
        int option;
#ifdef WCONTINUED
        option = WUNTRACED | WCONTINUED;
#else
        option = WUNTRACED;
#endif
        wpid = waitpid(pid, &childStatus, option);
        if (wpid == -1) {
            perror("waitpid");
            return false;
        }

        if (WIFEXITED(childStatus)) {
            // child normally exit
            // WEXITSTATUS(childStatus) value :
            // true -> Calling of execv func successed, and recording finished
            // and child will return the value of recording process's retVal
            // false -> Calling of execv func failed, child will output errInfo
            ret = WEXITSTATUS(childStatus) == 0 ? true : false;
            HIPERF_HILOGI(MODULE_CPP_API,
                "Hiperf Api Child normally exit Calling of execv : '%" HILOG_PUBLIC "s' \n",
                ret ? "success" : "failed");
            return ret;
        } else if (WIFSIGNALED(childStatus)) {
            // child was killed by SIGKILL
            HIPERF_HILOGI(MODULE_CPP_API, "Hiperf recording process was killed by signal SIGKILL\n");
            ret = false;
            return ret;
        } else if (WIFSTOPPED(childStatus)) {
            // child was stopped by SIGSTOP, and waiting for SIGCONT
            HIPERF_HILOGI(MODULE_CPP_API, "Hiperf recording process was stopped by signal SIGSTOP\n");
#ifdef WIFCONTINUED
        } else if (WIFCONTINUED(childStatus)) {
            // child was continued by SIGCONT
            HIPERF_HILOGI(MODULE_CPP_API, "Hiperf recording process was continued\n by SIGCONT");
#endif
        } else {
            // non-standard case, may never happen
            HIPERF_HILOGI(MODULE_CPP_API, "Hiperf recording process Unexpected status\n");
        }
    } while (!WIFEXITED(childStatus) && !WIFSIGNALED(childStatus));

    // normal exit.
    if (WIFEXITED(childStatus)) {
        ret = WEXITSTATUS(childStatus) == HIPERF_EXIT_CODE;
    } else {
    // signal exit, means Hiperf recording process may occur some runtime errors.
        HIPERF_HILOGI(MODULE_CPP_API,
            "Hiperf recording occurs some runtime errors, end with signal : %"
            HILOG_PUBLIC "d,  exit status : %" HILOG_PUBLIC "d\n",
            WIFSIGNALED(childStatus), WEXITSTATUS(childStatus));
        ret = false;
    }
    return ret;
}


bool Client::RunHiperfCmdSync(const RecordOption &option)
{
    HIPERF_HILOGI(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);
    if (!ready_) {
        HIPERF_HILOGI(MODULE_CPP_API, "Client:hiperf not ready.\n");
        return false;
    }
    const std::vector<std::string> &args = option.GetOptionVecString();

    pid_t wpid;
    int childStatus;
    bool ret = false;
    hperfPid_ = fork();
    if (hperfPid_ == -1) {
        char errInfo[ERRINFOLEN] = { 0 };
        strerror_r(errno, errInfo, ERRINFOLEN);
        HIPERF_HILOGI(MODULE_CPP_API, "failed to fork: %" HILOG_PUBLIC "s", errInfo);
        return false;
    } else if (hperfPid_ == 0) {
        // child execute
        std::vector<std::string> cmd;
        GetExecCmd(cmd, args);
        ChildRunExecv(cmd);
    } else {
        ret = ParentWait(wpid, hperfPid_, childStatus);
    }
    return ret;
}

bool Client::PrePare(const RecordOption &option)
{
    HIPERF_HILOGI(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);
    if (!option.GetOutputFileName().empty()) {
        outputFileName_ = option.GetOutputFileName();
    }
    return Start(option.GetOptionVecString(), false);
}

bool Client::WaitCommandReply(std::chrono::milliseconds timeOut)
{
    std::string reply;
    struct pollfd pollFd;
    pollFd.fd = serverToClientFd_;
    pollFd.events = POLLIN;
    pollFd.revents = 0;

    // wait some data
    int polled = poll(&pollFd, 1, timeOut.count());
    if (polled <= 0) {
        HIPERF_HILOGI(MODULE_CPP_API, "Client:command poll failed, retry.");
        polled = poll(&pollFd, 1, timeOut.count());
    }
    if (polled > 0) {
        while (true) {
            char c;
            ssize_t result = TEMP_FAILURE_RETRY(read(serverToClientFd_, &c, 1));
            if (result <= 0) {
                HIPERF_HILOGI(MODULE_CPP_API, "read failed from pipe");
                return false; // read fial means not ok
            }

            reply.push_back(c);
            if (c == '\n') {
                break;
            }
        }
    } else if (polled == 0) {
        HIPERF_HILOGI(MODULE_CPP_API, "Client:command no response %" HILOG_PUBLIC "" PRIu64 ".\n",
                      (uint64_t)timeOut.count());
    } else {
        HIPERF_HILOGI(MODULE_CPP_API, "Client:command poll failed.\n");
    }
    HIPERF_HILOGI(MODULE_CPP_API, "Client:new reply:%" HILOG_PUBLIC "s\n", reply.c_str());
    if (reply == ReplyOK) {
        return true;
    } else {
        return false;
    }
}

void Client::KillChild()
{
    HIPERF_HILOGI(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);
    if (clientToServerFd_ != -1) {
        close(clientToServerFd_);
        clientToServerFd_ = -1;
    }
    if (serverToClientFd_ != -1) {
        close(serverToClientFd_);
        serverToClientFd_ = -1;
    }
    if (hperfPid_ > 0) {
        kill(hperfPid_, SIGKILL);
        hperfPid_ = -1;
    }
    if (hperfPrePid_ > 0) {
        pid_t wpid;
        int childStatus;
        ParentWait(wpid, hperfPrePid_, childStatus);
        hperfPrePid_ = -1;
    }
}

bool Client::SendCommandAndWait(const std::string &cmd)
{
    if (clientToServerFd_ == -1) {
        HIPERF_HILOGI(MODULE_CPP_API, "fd not ready. maybe not called start.");
        return false;
    }
    size_t size = write(clientToServerFd_, cmd.c_str(), cmd.size());
    HIPERF_HILOGI(MODULE_CPP_API,
                  "Client:%" HILOG_PUBLIC "s -> %" HILOG_PUBLIC "d : %" HILOG_PUBLIC "zd\n",
                  cmd.c_str(), clientToServerFd_, size);
    if (size == cmd.size()) {
        return WaitCommandReply();
    } else {
        return false;
    }
}

bool Client::StartRun()
{
    if (!ready_) {
        HIPERF_HILOGI(MODULE_CPP_API, "Client:hiperf not ready.\n");
        return false;
    }
    HIPERF_HILOGI(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);
    if (SendCommandAndWait(ReplyStart)) {
        return true;
    }
    return false;
}

bool Client::Pause()
{
    if (!ready_) {
        HIPERF_HILOGI(MODULE_CPP_API, "Client:hiperf not ready.\n");
        return false;
    }
    HIPERF_HILOGI(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);
    if (SendCommandAndWait(ReplyPause)) {
        return true;
    }
    return false;
}

bool Client::Resume()
{
    if (!ready_) {
        HIPERF_HILOGI(MODULE_CPP_API, "Client:hiperf not ready.\n");
        return false;
    }
    HIPERF_HILOGI(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);
    if (SendCommandAndWait(ReplyResume)) {
        return true;
    }
    return false;
}

bool Client::Output()
{
    if (!ready_) {
        HIPERF_HILOGI(MODULE_CPP_API, "Client:hiperf not ready.\n");
        return false;
    }
    HIPERF_HILOGI(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);
    if (SendCommandAndWait(ReplyOutput)) {
        // wait output process exit really
        while (SendCommandAndWait(ReplyOutputCheck)) {
            std::this_thread::sleep_for(1s);
        }
        return true;
    }
    return false;
}

bool Client::Stop()
{
    if (!ready_) {
        HIPERF_HILOGI(MODULE_CPP_API, "Client:hiperf not ready.\n");
        return false;
    }
    HIPERF_HILOGI(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);
    if (SendCommandAndWait(ReplyStop)) {
        // wait sampling process exit really
        while (SendCommandAndWait(ReplyCheck)) {
            std::this_thread::sleep_for(1s);
        }
        return true;
    }
    return false;
}

void Client::EnableHilog()
{
    HIPERF_HILOGI(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);
    hilog_ = true;
}
} // namespace HiperfClient
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
