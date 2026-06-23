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
#ifndef HIPERF_THREAD_MANAGER_H
#define HIPERF_THREAD_MANAGER_H

#include <fstream>
#include <functional>
#include <map>
#include <string>

#include "perf_event_record.h"
#include "runtime_context.h"
#include "symbols_file.h"
#include "virtual_thread.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {

class ThreadManager {
public:
    using RecordCallBack = std::function<bool(PerfEventRecord&)>;
    using ProcessSymbolsCallBack = std::function<void(VirtualThread&, pid_t)>;

    explicit ThreadManager(const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles,
                           const RuntimeContext& runtimeContext);
    ~ThreadManager();
    VirtualThread& GetThread(pid_t pid, pid_t tid, const std::string& name = "");
    VirtualThread& CreateThread(pid_t pid, pid_t tid, const std::string& name = "");
    VirtualThread& UpdateThread(pid_t pid, pid_t tid, const std::string& name = "");
    std::string ReadThreadName(pid_t tid, bool isThread);
    std::string ReadFromSavedCmdLines(pid_t tid);
    bool IsKernelThread(pid_t pid) const;
    const std::map<pid_t, VirtualThread>& GetThreads() const { return userSpaceThreadMap_; }
    std::map<pid_t, VirtualThread>& GetMutableThreads() { return userSpaceThreadMap_; }
    void SetRecordMode(const RecordCallBack& recordCallBack) { recordCallBack_ = recordCallBack; }
    void SetProcessSymbolsCallBack(const ProcessSymbolsCallBack& callback) { processSymbolsCallBack_ = callback; }
    void Clear();

#ifdef HIPERF_DEBUG_TIME
    std::chrono::microseconds updateThreadTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds threadParseMapsTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds threadCreateMmapTimes_ = std::chrono::microseconds::zero();
#endif

private:
    std::map<pid_t, VirtualThread> userSpaceThreadMap_;
    const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles_;
    const RuntimeContext& runtimeContext_;
    std::ifstream savedCmdLines_;
    RecordCallBack recordCallBack_;
    ProcessSymbolsCallBack processSymbolsCallBack_;
};

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_THREAD_MANAGER_H
