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
#ifndef HIPERF_RECORD_PROCESSOR_H
#define HIPERF_RECORD_PROCESSOR_H

#include <functional>
#include <memory>

#include "callstack_processor.h"
#include "memory_map_manager.h"
#include "perf_event_record.h"
#include "runtime_context.h"
#include "smo_processor.h"
#include "symbols_file.h"
#include "thread_manager.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {

class RecordProcessor {
public:
    using RecordCallBack = std::function<bool(PerfEventRecord&)>;
    using SymbolsFileRegisterFunc = std::function<int32_t(std::unique_ptr<SymbolsFile>)>;

    RecordProcessor(ThreadManager& threadManager, MemoryMapManager& mapManager,
                    CallStackProcessor& callStackProcessor, SmoProcessor& smoProcessor,
                    const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles,
                    const RuntimeContext& ctx, const SymbolsFileRegisterFunc& registerFunc);
    ~RecordProcessor() = default;
    void UpdateFromRecord(PerfEventRecord& record);
    void FixHMBundleMmap(char* filename, int pid, u16& headerSize);
    void SetLoadSymbolsWhenNeeded(bool loadWhenNeeded) { loadSymbolsWhenNeeded_ = loadWhenNeeded; }
    void SetEnableDebugInfoSymbolic(bool enable) { enableDebugInfoSymbolic_ = enable; }
    void SetSymbolsPaths(const std::vector<std::string>& paths) { symbolsPaths_ = paths; }
    void SetRecordMode(const RecordCallBack& recordCallBack) { recordCallBack_ = recordCallBack; }
    void SetDisableUnwind(bool disable) { disableUnwind_ = disable; }
    void UpdateSymbols(std::shared_ptr<DfxMap> map, pid_t pid);
    void UpdateProcessSymbols(VirtualThread& thread, pid_t pid);

#ifdef HIPERF_DEBUG_TIME
    std::chrono::microseconds updateSymbolsTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds processSampleRecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds processMmapRecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds processMmap2RecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds processCommRecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds processAuxtraceRecordTimes_ = std::chrono::microseconds::zero();
#endif

private:
    void UpdateFromRecord(PerfRecordSample& record);
    void UpdateFromRecord(PerfRecordMmap& record);
    void UpdateFromRecord(PerfRecordMmap2& record);
    void UpdateFromRecord(PerfRecordComm& record);
    void UpdateFromRecord(PerfRecordAuxtrace& record);
    bool CheckValidSandBoxMmap(PerfRecordMmap2& record);
    void UpdateSandBoxThreadMaps(std::unique_ptr<SymbolsFile>& symFile,
                                 std::shared_ptr<DfxMap>& curMap,
                                 std::shared_ptr<DfxMap>& prevMap,
                                 PerfRecordMmap2& record);
    bool UpdateHapSymbols(std::shared_ptr<DfxMap> map);

    ThreadManager& threadManager_;
    MemoryMapManager& mapManager_;
    CallStackProcessor& callStackProcessor_;
    SmoProcessor& smoProcessor_;
    const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles_;
    const RuntimeContext& ctx_;
    const SymbolsFileRegisterFunc& registerFunc_;
    std::vector<std::string> symbolsPaths_;
    bool loadSymbolsWhenNeeded_ = true;
    bool enableDebugInfoSymbolic_ = false;
    RecordCallBack recordCallBack_;
    bool disableUnwind_ = true;
};

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_RECORD_PROCESSOR_H
