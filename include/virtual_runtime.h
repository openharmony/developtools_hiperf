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

#include <functional>

#include "callstack.h"
#include "perf_event_record.h"
#include "symbols_file.h"
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
    VirtualRuntime(bool onDevice = true);

    // thread need hook the record
    // from the record , it will call back to write some Simulated Record
    // case 1. some mmap will be create when it read mmaps for each new process (from record sample)

    using RecordCallBack = std::function<bool(std::unique_ptr<PerfEventRecord>)>;
    void SetRecordMode(RecordCallBack recordCallBack);

    // this both used in report and record follow
    // it process the record, and rebuild the trhread maps
    // It internally determines whether to go to the Record process (which will generate virtual
    // events) or the Report process by judging whether SetRecordMode has been passed.
    void UpdateFromRecord(PerfEventRecord &reocrd);

    // in reocrd mode
    // we make a kernel symbols from some proc file
    void UpdateKernelSpaceMaps();
    void UpdateKernelModulesSpaceMaps();
    // load vdso
    void LoadVdso();

    void UpdateKernelSymbols();
    void UpdateKernelModulesSymbols();

    // set symbols path , it will send to every symobile file for search
    bool SetSymbolsPaths(const std::vector<std::string> &symbolsPaths);

    // any mode
    static_assert(sizeof(pid_t) == sizeof(int));

    const std::vector<std::unique_ptr<SymbolsFile>> &GetSymbolsFiles() const
    {
        return symbolsFiles_;
    }

    void SetCallStackExpend(size_t mergeLevel = 0)
    {
        callstackMergeLevel_ = mergeLevel;
    }

    void SetDisableUnwind(bool disableUnwind)
    {
        HLOGV("disableUnwind change to %d", disableUnwind);
        disableUnwind_ = disableUnwind;
    }

    const Symbol GetSymbol(uint64_t ip, pid_t pid, pid_t tid,
                           const perf_callchain_context &context = PERF_CONTEXT_MAX);

    VirtualThread &GetThread(pid_t pid, pid_t tid);
    const std::map<pid_t, VirtualThread> &GetThreads() const
    {
        return userSpaceThreadMap_;
    }
    void SymbolicRecord(PerfRecordSample &recordSample);

    // report use
    void UpdateFromPerfData(const std::vector<SymbolFileStruct> &);
    void UnwindFromRecord(PerfRecordSample &recordSample);
    std::string ReadThreadName(pid_t tid);

    // debug time
#ifdef HIPERF_DEBUG_TIME
    std::chrono::microseconds updateSymbolsTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds unwindFromRecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds unwindCallStackTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds symbolicRecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds updateThreadTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds prcessSampleRecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds prcessMmapRecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds prcessMmap2RecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds prcessCommRecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds threadParseMapsTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds threadCreateMmapTimes_ = std::chrono::microseconds::zero();
#endif
    const bool loadSymboleWhenNeeded_ = true; // this is a feature config

private:
    bool disableUnwind_ = true;
    size_t callstackMergeLevel_ = 1;
    CallStack callstack_;
    // pid map with user space thread
    std::map<pid_t, VirtualThread> userSpaceThreadMap_;
    // not pid , just memmap
    std::vector<MemMapItem> kernelSpaceMemMaps_;
    RecordCallBack recordCallBack_;
    std::vector<std::unique_ptr<SymbolsFile>> symbolsFiles_;
    enum SymbolCacheLimit : std::size_t {
        KERNEL_SYMBOL_CACHE_LIMIT = 4000,
        THREAD_SYMBOL_CACHE_LIMIT = 2000,
    };
    std::unordered_map<pid_t, HashList<uint64_t, Symbol>> threadSymbolCache_;
    HashList<uint64_t, Symbol> kernelSymbolCache_ {KERNEL_SYMBOL_CACHE_LIMIT};
    bool GetSymbolCache(uint64_t ip, pid_t pid, pid_t tid, Symbol &symbol,
                        const perf_callchain_context &context);
    // find synbols function name
    void MakeCallFrame(Symbol &symbol, CallFrame &callFrame);
    // records
    void UpdateSymbols(std::string filename);
    void UpdateFromRecord(PerfRecordSample &recordSample);
    void UpdateFromRecord(PerfRecordMmap &recordMmap);
    void UpdateFromRecord(PerfRecordMmap2 &recordMmap2);
    void UpdateFromRecord(PerfRecordComm &recordComm);

    // threads
    VirtualThread &UpdateThread(pid_t pid, pid_t tid, const std::string name = "");
    VirtualThread &CreateThread(pid_t pid, pid_t tid);

    // maps
    void UpdateThreadMaps(pid_t pid, pid_t tid, const std::string filename, uint64_t begin,
                          uint64_t len, uint64_t offset);
    void UpdatekernelMap(uint64_t begin, uint64_t end, uint64_t offset, std::string filename);

    const Symbol GetKernelSymbol(uint64_t ip, const std::vector<MemMapItem> &memMaps,
                                 const VirtualThread &thread);
    const Symbol GetUserSymbol(uint64_t ip, const VirtualThread &thread);
#ifdef HIPERF_DEBUG
    std::unordered_set<uint64_t> missedRuntimeVaddr_;
#endif
    void SymbolicCallFrame(PerfRecordSample &recordSample, uint64_t ip,
                           perf_callchain_context context);

    std::vector<std::string> symbolsPaths_;

    FRIEND_TEST(VirtualRuntimeTest, SetRecordMode);
    FRIEND_TEST(VirtualRuntimeTest, UpdateKernelSymbols);
    FRIEND_TEST(VirtualRuntimeTest, UpdateKernelModulesSymbols);
    FRIEND_TEST(VirtualRuntimeTest, SetCallStackExpend);
    FRIEND_TEST(VirtualRuntimeTest, SetDisableUnwind);
    FRIEND_TEST(VirtualRuntimeTest, UnwindFromRecord);
    friend class VirtualRuntimeTest;
};
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_VIRTUAL_RUNTIME_H
