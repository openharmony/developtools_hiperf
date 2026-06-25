/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#define HILOG_TAG "ThreadManager"

#include "thread_manager.h"

#include <algorithm>
#include <cinttypes>

#include "debug_logger.h"
#include "hiperf_hilog.h"
#include "utilities.h"

using namespace std::chrono;

namespace OHOS {
namespace Developtools {
namespace HiPerf {

ThreadManager::ThreadManager(const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles,
                             const RuntimeContext& runtimeContext)
    : symbolsFiles_(symbolsFiles), runtimeContext_(runtimeContext)
{
}

ThreadManager::~ThreadManager()
{
    if (savedCmdLines_.is_open()) {
        savedCmdLines_.close();
    }
}

std::string ThreadManager::ReadFromSavedCmdLines(const pid_t tid)
{
    if (!savedCmdLines_.is_open()) {
        savedCmdLines_.open(SAVED_CMDLINES, std::ios::in);
    }
    if (!savedCmdLines_.is_open()) {
        return EMPTY_STRING;
    }
    savedCmdLines_.seekg(0, std::ios::beg);
    std::string line;
    std::string threadid = std::to_string(tid);
    while (getline(savedCmdLines_, line)) {
        if (line.find(threadid) != std::string::npos) {
            constexpr size_t sizeLimit {2};
            std::vector<std::string> linesToken = StringSplit(line, " ");
            if (linesToken.size() < sizeLimit) {
                return EMPTY_STRING;
            }
            if (threadid != linesToken[0]) {
                continue;
            }
            return linesToken[1];
        }
    }
    return EMPTY_STRING;
}

std::string ThreadManager::ReadThreadName(const pid_t tid, const bool isThread)
{
    std::string comm = "";
    if (tid == SYSMGR_PID) {
        comm = SYSMGR_NAME;
    } else if (tid == runtimeContext_.devhostPid) {
        comm = DEVHOST_FILE_NAME;
    } else if (isThread) {
        comm = ReadFileToString(StringPrintf("/proc/%d/comm", tid));
    } else {
        comm = ReadFileToString(StringPrintf("/proc/%d/cmdline", tid));
    }
    if (comm == EMPTY_STRING) {
        comm = ReadFromSavedCmdLines(tid);
    }
    size_t nullPos = comm.find('\0');
    if (nullPos != std::string::npos) {
        comm.resize(nullPos);
    }
    comm.erase(std::remove(comm.begin(), comm.end(), '\r'), comm.end());
    comm.erase(std::remove(comm.begin(), comm.end(), '\n'), comm.end());
    return comm;
}

VirtualThread& ThreadManager::UpdateThread(pid_t pid, pid_t tid, const std::string& name)
{
#ifdef HIPERF_DEBUG_TIME
    const auto startTime = steady_clock::now();
#endif
    VirtualThread& thread = GetThread(pid, tid, name);
    if (!name.empty() && (thread.name_.empty() || !StringEndsWith(thread.name_, name))) {
        thread.name_ = name;
    }
#ifdef HIPERF_DEBUG_TIME
    updateThreadTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif
    return thread;
}

VirtualThread& ThreadManager::CreateThread(pid_t pid, pid_t tid, const std::string& name)
{
    // make a new one
    if (pid == tid) {
        userSpaceThreadMap_.emplace(std::piecewise_construct, std::forward_as_tuple(tid),
                                    std::forward_as_tuple(pid, symbolsFiles_));
    } else {
        // for thread we need give it process info( for same mmap)
        userSpaceThreadMap_.emplace(
            std::piecewise_construct, std::forward_as_tuple(tid),
            std::forward_as_tuple(pid, tid, GetThread(pid, pid), symbolsFiles_));
    }
    VirtualThread &thread = userSpaceThreadMap_.at(tid);
    if (recordCallBack_) {
        if (pid == tid && !IsKernelThread(pid)) {
#ifdef HIPERF_DEBUG_TIME
            const auto startTime = steady_clock::now();
#endif
            thread.ParseMap();
#ifdef HIPERF_DEBUG_TIME
            threadParseMapsTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif
        }
#ifdef HIPERF_DEBUG_TIME
        const auto startCreateMmapTime = steady_clock::now();
#endif
        thread.name_ = name;
        if (thread.name_.empty()) {
            thread.name_ = ReadThreadName(tid, pid != tid);
        }
        HLOGD("create a new thread record for %u:%u:%s with %zu dso", pid, tid,
              thread.name_.c_str(), thread.GetMaps().size());
        // we need make a PerfRecordComm
        auto commRecord = std::make_unique<PerfRecordComm>(IsKernelThread(pid), pid, tid, thread.name_);
        recordCallBack_(*commRecord);
        if (pid == tid) {
            if (processSymbolsCallBack_) {
                processSymbolsCallBack_(thread, pid);
            }
        }
        HLOGV("thread created");
#ifdef HIPERF_DEBUG_TIME
        threadCreateMmapTimes_ +=
            duration_cast<microseconds>(steady_clock::now() - startCreateMmapTime);
#endif
    }
    return thread;
}

VirtualThread& ThreadManager::GetThread(pid_t pid, pid_t tid, const std::string& name)
{
    if (userSpaceThreadMap_.find(pid) == userSpaceThreadMap_.end()) {
        // no pid found
        // create process first
        CreateThread(pid, pid);
    }

    auto it = userSpaceThreadMap_.find(tid);
    if (it == userSpaceThreadMap_.end()) {
        // we also need thread
        return CreateThread(pid, tid, name);
    } else {
        return it->second;
    }
}

bool ThreadManager::IsKernelThread(const pid_t pid) const
{
    if (!runtimeContext_.isHM) {
        return false;
    }
    return pid == SYSMGR_PID || pid == runtimeContext_.devhostPid;
}

void ThreadManager::Clear()
{
    userSpaceThreadMap_.clear();
    if (savedCmdLines_.is_open()) {
        savedCmdLines_.close();
    }
}

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
