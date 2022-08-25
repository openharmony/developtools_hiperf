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
#include "hiperf_client.h"
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
const ssize_t ERRINFOLEN = 512;
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
    SetOption(ArgTargetSystemWide, enable);
}

void RecordOption::SetCompressData(bool enable)
{
    SetOption(ArgCompressData, enable);
}

void RecordOption::SetSelectCpus(const std::vector<int> &cpus)
{
    SetOption(ArgSelectCpus, cpus);
}

void RecordOption::SetTimeStopSec(int timeStopSec)
{
    SetOption(ArgTimeStopSec, timeStopSec);
}

void RecordOption::SetFrequency(int frequency)
{
    SetOption(ArgFrequency, frequency);
}

void RecordOption::SetPeriod(int period)
{
    SetOption(ArgPeriod, period);
}

void RecordOption::SetSelectEvents(const std::vector<std::string> &selectEvents)
{
    SetOption(ArgSelectEvents, selectEvents);
}

void RecordOption::SetSelectGroups(const std::vector<std::string> &selectGroups)
{
    SetOption(ArgSelectGroups, selectGroups);
}

void RecordOption::SetNoInherit(bool enable)
{
    SetOption(ArgNoInherit, enable);
}

void RecordOption::SetSelectPids(const std::vector<pid_t> &selectPids)
{
    SetOption(ArgSelectPids, selectPids);
}

void RecordOption::SetSelectTids(const std::vector<pid_t> &selectTids)
{
    SetOption(ArgSelectTids, selectTids);
}

void RecordOption::SetExcludePerf(bool excludePerf)
{
    SetOption(ArgExcludePerf, excludePerf);
}

void RecordOption::SetCpuPercent(int cpuPercent)
{
    SetOption(ArgCpuPercent, cpuPercent);
}

void RecordOption::SetOffCPU(bool offCPU)
{
    SetOption(ArgOffCPU, offCPU);
}

void RecordOption::SetCallGraph(const std::string &callGraph)
{
    SetOption(ArgCallGraph, callGraph);
}

void RecordOption::SetDelayUnwind(bool delayUnwind)
{
    SetOption(ArgDelayUnwind, delayUnwind);
}

void RecordOption::SetDisableUnwind(bool disableUnwind)
{
    SetOption(ArgDisableUnwind, disableUnwind);
}

void RecordOption::SetDisableCallstackMerge(bool disableCallstackMerge)
{
    SetOption(ArgDisableCallstackMerge, disableCallstackMerge);
}

void RecordOption::SetSymbolDir(const std::string &symbolDir_)
{
    SetOption(ArgSymbolDir, symbolDir_);
}

void RecordOption::SetDataLimit(const std::string &limit)
{
    SetOption(ArgDataLimit, limit);
}

void RecordOption::SetAppPackage(const std::string &appPackage)
{
    SetOption(ArgAppPackage, appPackage);
}

void RecordOption::SetClockId(const std::string &clockId)
{
    SetOption(ArgClockId, clockId);
}

void RecordOption::SetVecBranchSampleTypes(const std::vector<std::string> &vecBranchSampleTypes)
{
    SetOption(ArgVecBranchSampleTypes, vecBranchSampleTypes);
}

void RecordOption::SetMmapPages(int mmapPages)
{
    SetOption(ArgMmapPages, mmapPages);
}

Client::Client(const std::string &outputDir)
{
    HIPERF_HILOGD(MODULE_CPP_API, "%" HILOG_PUBLIC "s default init with %" HILOG_PUBLIC "s\n",
                  __FUNCTION__, outputDir.c_str());
    Setup(outputDir);
}

bool Client::Setup(std::string outputDir)
{
    std::string CurrentCommandPath = CurrentPath + HiperfCommandName;
    std::string SystemCommandPath = SystemBinPath + HiperfCommandName;
    std::string TempCommandPath = TempBinPath + HiperfCommandName;

    if (!outputDir.empty() && outputDir.back() != '/') {
        outputDir.push_back('/');
    }
    HIPERF_HILOGD(MODULE_CPP_API, "outputDir setup to %" HILOG_PUBLIC "s\n", outputDir.c_str());

    // found command path
    if (access(CurrentCommandPath.c_str(), X_OK) == 0) {
        executeCommandPath_ = CurrentCommandPath;
    } else if (access(TempCommandPath.c_str(), X_OK) == 0) {
        executeCommandPath_ = TempCommandPath;
    } else if (access(SystemCommandPath.c_str(), X_OK) == 0) {
        executeCommandPath_ = SystemCommandPath;
    } else {
        HIPERF_HILOGD(MODULE_CPP_API, "no hiperf command found\n");
        return ready_;
    }

    // check output path
    // found command path
    if (access(outputDir.c_str(), W_OK) == 0) {
        outputDir_ = outputDir;
    } else if (access(CurrentPath.c_str(), W_OK) == 0) {
        outputDir_ = CurrentPath;
    } else {
        HIPERF_HILOGD(MODULE_CPP_API, "no writeable output path found\n");
        return ready_;
    }
    outputFileName_ = PerfDataName;

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
    HIPERF_HILOGD(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);

    std::vector<std::string> args;
    args.push_back("-p");
    args.push_back(std::to_string(getpid()));
    return Start(args);
}

void Client::GetExecCmd(std::vector<std::string> &cmd, int pipeIn, int pipeOut,
                        const std::vector<std::string> &args)
{
    cmd.clear();
    cmd.emplace_back(executeCommandPath_);

    if (debug_) {
        cmd.emplace_back(ArgDebug);
    } else if (debugMuch_) {
        cmd.emplace_back(ArgDebugMuch);
    }

    if (hilog_) {
        cmd.emplace_back(ArgHilog);
    }

    cmd.emplace_back(CommandRecord);
    cmd.emplace_back(ArgPipeInput);
    cmd.emplace_back(std::to_string(pipeIn));
    cmd.emplace_back(ArgPipeOutput);
    cmd.emplace_back(std::to_string(pipeOut));
    cmd.emplace_back(ArgOutputPath);
    cmd.emplace_back(GetOutputPerfDataPath());

    cmd.insert(cmd.end(), args.begin(), args.end());
}

bool Client::Start(const std::vector<std::string> &args)
{
    HIPERF_HILOGD(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);
    if (!ready_) {
        HIPERF_HILOGD(MODULE_CPP_API, "Client:hiperf not ready.\n");
        return false;
    }

    int clientToServerFd[2];
    int serverToClientFd[2];
    if (pipe(clientToServerFd) != 0) {
        char errInfo[ERRINFOLEN] = { 0 };
        strerror_r(errno, errInfo, ERRINFOLEN);
        HIPERF_HILOGD(MODULE_CPP_API, "failed to create pipe: %" HILOG_PUBLIC "s", errInfo);
        return false;
    } else if (pipe(serverToClientFd) != 0) {
        char errInfo[ERRINFOLEN] = { 0 };
        strerror_r(errno, errInfo, ERRINFOLEN);
        HIPERF_HILOGD(MODULE_CPP_API, "failed to create pipe: %" HILOG_PUBLIC "s", errInfo);
        close(clientToServerFd[PIPE_READ]);
        close(clientToServerFd[PIPE_WRITE]);
        return false;
    }

    hperfPid_ = fork();
    if (hperfPid_ == -1) {
        char errInfo[ERRINFOLEN] = { 0 };
        strerror_r(errno, errInfo, ERRINFOLEN);
        HIPERF_HILOGD(MODULE_CPP_API, "failed to fork: %" HILOG_PUBLIC "s", errInfo);
        close(clientToServerFd[PIPE_READ]);
        close(clientToServerFd[PIPE_WRITE]);
        close(serverToClientFd[PIPE_READ]);
        close(serverToClientFd[PIPE_WRITE]);
        return false;
    } else if (hperfPid_ == 0) {
        // child process
        prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        close(clientToServerFd[PIPE_WRITE]);
        close(serverToClientFd[PIPE_READ]);

        std::vector<std::string> cmd;
        GetExecCmd(cmd, clientToServerFd[PIPE_READ], serverToClientFd[PIPE_WRITE], args);
        // conver vector to array for execvp()
        char *argv[cmd.size() + SIZE_ARGV_TAIL];
        size_t i = 0;
        for (i = 0; i < cmd.size(); ++i) {
            HIPERF_HILOGD(MODULE_CPP_API, "args %" HILOG_PUBLIC "zu : %" HILOG_PUBLIC "s", i,
                          cmd[i].c_str());
            argv[i] = cmd[i].data();
        }
        argv[i] = nullptr;

        execv(argv[0], argv);
        char errInfo[ERRINFOLEN] = { 0 };
        strerror_r(errno, errInfo, ERRINFOLEN);
        HIPERF_HILOGD(MODULE_CPP_API,
                      "failed to call exec: '%" HILOG_PUBLIC "s' %" HILOG_PUBLIC "s\n",
                      executeCommandPath_.c_str(), errInfo);
        exit(0);
    } else {
        // parent process
        close(clientToServerFd[PIPE_READ]);
        close(serverToClientFd[PIPE_WRITE]);

        clientToServerFd_ = clientToServerFd[PIPE_WRITE];
        serverToClientFd_ = serverToClientFd[PIPE_READ];
    }
    using namespace std::chrono_literals;
    if (!WaitCommandReply(1000ms)) {
        HIPERF_HILOGD(MODULE_CPP_API, "start failed . lets kill it");
        KillChild();
        return false;
    }
    return true;
}

bool Client::Start(const RecordOption &option)
{
    HIPERF_HILOGD(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);
    if (!option.GetOutputFileName().empty()) {
        outputFileName_ = option.GetOutputFileName();
    }
    return Start(option.GetOptionVecString());
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
    if (polled > 0) {
        while (true) {
            char c;
            ssize_t result = TEMP_FAILURE_RETRY(read(serverToClientFd_, &c, 1));
            if (result <= 0) {
                HIPERF_HILOGD(MODULE_CPP_API, "read failed from pipe");
                return false; // read fial means not ok
            }

            reply.push_back(c);
            if (c == '\n') {
                break;
            }
        }
    } else if (polled == 0) {
        HIPERF_HILOGD(MODULE_CPP_API, "Client:command no response %" HILOG_PUBLIC "" PRIu64 ".\n",
                      (uint64_t)timeOut.count());
    } else {
        HIPERF_HILOGD(MODULE_CPP_API, "Client:command poll failed.\n");
    }
    HIPERF_HILOGD(MODULE_CPP_API, "Client:new reply:%" HILOG_PUBLIC "s\n", reply.c_str());
    if (reply == ReplyOK) {
        return true;
    } else {
        return false;
    }
}

void Client::KillChild()
{
    HIPERF_HILOGD(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);
    if (clientToServerFd_ != -1) {
        close(clientToServerFd_);
    }
    if (serverToClientFd_ != -1) {
        close(serverToClientFd_);
    }
    if (hperfPid_ > 0) {
        kill(hperfPid_, SIGKILL);
    }
}

bool Client::SendCommandAndWait(const std::string &cmd)
{
    if (clientToServerFd_ == -1) {
        HIPERF_HILOGD(MODULE_CPP_API, "fd not ready. maybe not called start.");
        return false;
    }
    size_t size = write(clientToServerFd_, cmd.c_str(), cmd.size());
    HIPERF_HILOGD(MODULE_CPP_API,
                  "Client:%" HILOG_PUBLIC "s -> %" HILOG_PUBLIC "d : %" HILOG_PUBLIC "zd\n",
                  cmd.c_str(), clientToServerFd_, size);
    if (size == cmd.size()) {
        return WaitCommandReply();
    } else {
        return false;
    }
}

bool Client::Pause()
{
    if (!ready_) {
        HIPERF_HILOGD(MODULE_CPP_API, "Client:hiperf not ready.\n");
        return false;
    }
    HIPERF_HILOGD(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);
    if (SendCommandAndWait(ReplyPause)) {
        return true;
    }
    return false;
}

bool Client::Resume()
{
    if (!ready_) {
        HIPERF_HILOGD(MODULE_CPP_API, "Client:hiperf not ready.\n");
        return false;
    }
    HIPERF_HILOGD(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);
    if (SendCommandAndWait(ReplyResume)) {
        return true;
    }
    return false;
}

bool Client::Stop()
{
    if (!ready_) {
        HIPERF_HILOGD(MODULE_CPP_API, "Client:hiperf not ready.\n");
        return false;
    }
    HIPERF_HILOGD(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);
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
    HIPERF_HILOGD(MODULE_CPP_API, "Client:%" HILOG_PUBLIC "s\n", __FUNCTION__);
    hilog_ = true;
}
} // namespace HiperfClient
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
