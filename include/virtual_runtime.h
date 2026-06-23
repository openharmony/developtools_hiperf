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
#ifndef HIPERF_VIRTUAL_RUNTIME_H
#define HIPERF_VIRTUAL_RUNTIME_H

#include <chrono>
#include <functional>
#include <memory>
#include <unordered_set>

#include "callstack_processor.h"
#include "kernel_symbol_loader.h"
#include "memory_map_manager.h"
#include "perf_event_record.h"
#include "record_processor.h"
#include "runtime_context.h"
#include "smo_processor.h"
#include "symbol_manager.h"
#include "symbols_file.h"
#include "thread_manager.h"
#include "unique_stack_table.h"
#include "virtual_thread.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
/*
This Class contains userspace thread objects. and kernel space objects
It represents a virtual operating environment, mainly referring to the relationship between pid,
mmaps, and symbols.

It mainly receives data is ip pointer (virtual address), pid
According to these data, it will find the corresponding mmap and its corresponding elf (also called
DSO)

Then find the corresponding symbol in the corresponding elf symbol file according to the offset
recorded in the corresponding mmap.
*/

class VirtualRuntime {
public:
    explicit VirtualRuntime(const bool onDevice = true);
    ~VirtualRuntime();
    // thread need hook the record
    // from the record , it will call back to write some Simulated Record
    // case 1. some mmap will be create when it read mmaps for each new process (from record sample)

    using RecordCallBack = std::function<bool(PerfEventRecord&)>;
    using CollectSymbolCallBack = std::function<void(PerfRecordSample*)>;
    using SymbolsFileRegisterFunc = std::function<int32_t(std::unique_ptr<SymbolsFile>)>;
    RuntimeContext& GetRuntimeContext() { return runtimeContext_; }
    const RuntimeContext& GetRuntimeContext() const { return runtimeContext_; }
    void SetRecordMode(const RecordCallBack &recordCallBack);
    void SetCollectSymbolCallBack(const CollectSymbolCallBack &collectSymbolCallBack);
    void SetSmoFlag(bool flag);
    int32_t RegisterSymbolsFile(std::unique_ptr<SymbolsFile> symbolsFile);

    // this both used in report and record follow
    // it process the record, and rebuild the trhread maps
    // It internally determines whether to go to the Record process (which will generate virtual
    // events) or the Report process by judging whether SetRecordMode has been passed.
    void UpdateFromRecord(PerfEventRecord &record);
    void SetNeedKernelCallChain(const bool kernelCallChain);
    void NeedDropKernelCallChain(PerfRecordSample &sample);
    // in reocrd mode
    // we make a kernel symbols from some proc file
    void UpdateKernelSpaceMaps();
    void UpdateKernelModulesSpaceMaps();
    void UpdateServiceSpaceMaps();
    void UpdateDevhostSpaceMaps();
    void LoadVdso();
    void UpdateKernelSymbols();
    void UpdateKernelModulesSymbols();
    void UpdateServiceSymbols();
    void UpdateDevhostSymbols();
    void SetDevhostPid(const pid_t devhost);
    void FixHMBundleMmap(char *filename, const int pid, u16 &headerSize);

    // set symbols path , it will send to every symobile file for search
    bool SetSymbolsPaths(const std::vector<std::string> &symbolsPaths);
    static_assert(sizeof(pid_t) == sizeof(int));
    const std::map<std::string, std::vector<AdltMapDataFragment>>& GetSoMappingMap();
    const std::vector<std::unique_ptr<SymbolsFile>> &GetSymbolsFiles() const
    {
        return symbolsFiles_;
    }
    const ProcessStackMap* GetUniStackTable();
    void SetCallStackExpend(const size_t mergeLevel = 0);
    void SetDisableUnwind(const bool disableUnwind);
    void EnableDebugInfoSymbolic(const bool enable);
    void SetDedupStack();
    void ImportUniqueStackNodes(const std::vector<UniStackTableInfo>&);
    void SetHM(bool isHM);
    void SetIsRoot(bool isRoot);
    DfxSymbol GetSymbol(const uint64_t ip, const pid_t pid, const pid_t tid,
                        const perf_callchain_context &context = PERF_CONTEXT_MAX);
    void ClearSymbolCache();
    void ReleaseRecordResources();
    VirtualThread &GetThread(const pid_t pid, const pid_t tid, const std::string name = "");
    const std::map<pid_t, VirtualThread> &GetThreads() const;
    void SymbolicRecord(PerfRecordSample &recordSample);
    void SymbolSpeRecord(PerfRecordAuxtrace &recordAuxTrace);

    // report use
    void UpdateFromPerfData(const std::vector<SymbolFileStruct> &);
    void UpdateFilesFromSmoRecordData();
    void UnwindFromRecord(PerfRecordSample &recordSample);
    std::string ReadThreadName(const pid_t tid, const bool isThread);
    std::string ReadFromSavedCmdLines(const pid_t tid);
    bool IsKernelThread(const pid_t pid);
    void CollectDedupSymbol(kSymbolsHits &kernelSymbolsHits, uSymbolsHits &userSymbolsHits);
    bool UpdateProcessSmoInfo(const VirtualThread &thread);
    const bool loadSymbolsWhenNeeded_ = true;

#ifdef HIPERF_DEBUG_TIME
    std::chrono::microseconds updateSymbolsTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds unwindFromRecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds unwindCallStackTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds symbolicRecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds updateThreadTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds processSampleRecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds processMmapRecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds processMmap2RecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds processCommRecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds processAuxtraceRecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds threadParseMapsTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds threadCreateMmapTimes_ = std::chrono::microseconds::zero();
    void AggregateDebugTimes();
#endif

private:
    std::unique_ptr<ThreadManager> threadManager_;
    std::unique_ptr<MemoryMapManager> mapManager_;
    std::unique_ptr<CallStackProcessor> callStackProcessor_;
    std::unique_ptr<RecordProcessor> recordProcessor_;
    std::unique_ptr<KernelSymbolLoader> kernelSymbolLoader_;
    std::unique_ptr<SmoProcessor> smoProcessor_;
    std::unique_ptr<SymbolManager> symbolManager_;

    std::vector<std::unique_ptr<SymbolsFile>> symbolsFiles_;
    RuntimeContext runtimeContext_;
    SymbolsFileRegisterFunc symbolsFileRegisterFunc_;

#ifdef HIPERF_DEBUG
    std::unordered_set<uint64_t> missedRuntimeVaddr_;
#endif
};
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_VIRTUAL_RUNTIME_H
