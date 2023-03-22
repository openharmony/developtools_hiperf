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
#define HILOG_TAG "Runtime"

#include "virtual_runtime.h"

#include <cinttypes>
#include <iostream>
#include <sstream>
#include <unistd.h>
#if !is_mingw
#include <sys/mman.h>
#endif

#include "register.h"
#include "symbols_file.h"
#include "utilities.h"

using namespace std::chrono;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
// we unable to access 'swapper' from /proc/0/
VirtualRuntime::VirtualRuntime(bool onDevice)
{
    UpdateThread(0, 0, "swapper");
}

std::string VirtualRuntime::ReadThreadName(pid_t tid)
{
    std::string comm = ReadFileToString(StringPrintf("/proc/%d/cmdline", tid)).c_str();
    comm.erase(std::remove(comm.begin(), comm.end(), '\r'), comm.end());
    comm.erase(std::remove(comm.begin(), comm.end(), '\n'), comm.end());
    return comm;
}

VirtualThread &VirtualRuntime::UpdateThread(pid_t pid, pid_t tid, const std::string name)
{
#ifdef HIPERF_DEBUG_TIME
    const auto startTime = steady_clock::now();
#endif
    VirtualThread &thread = GetThread(pid, tid);
    if (!name.empty()) {
        thread.name_ = name;
    }
#ifdef HIPERF_DEBUG_TIME
    updateThreadTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif
    return thread;
}

VirtualThread &VirtualRuntime::CreateThread(pid_t pid, pid_t tid)
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
        if (pid == tid) {
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
        thread.name_ = ReadThreadName(pid);
        HLOGD("create a new thread record for %u:%u:%s with %zu dso", pid, tid,
              thread.name_.c_str(), thread.GetMaps().size());
        // we need make a PerfRecordComm
        auto commRecord = std::make_unique<PerfRecordComm>(false, pid, tid, thread.name_);
        recordCallBack_(std::move(commRecord));
        // only work for pid
        if (pid == tid) {
            for (auto &memMapItem : thread.GetMaps()) {
                auto mmapRecord =
                    std::make_unique<PerfRecordMmap2>(false, thread.pid_, thread.tid_, memMapItem);
                if (mmapRecord->data_.pgoff == 0 || (mmapRecord->data_.prot & PROT_EXEC) == 0) {
                    continue;
                }
                HLOGD("make PerfRecordMmap2 %d:%d:%s:%s(0x%" PRIx64 "-0x%" PRIx64 ")@%" PRIx64 " ",
                      thread.pid_, thread.tid_, thread.name_.c_str(), memMapItem.name_.c_str(),
                      memMapItem.begin_, memMapItem.end_, memMapItem.pageoffset_);
                recordCallBack_(std::move(mmapRecord));
                UpdateSymbols(memMapItem.name_);
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

VirtualThread &VirtualRuntime::GetThread(pid_t pid, pid_t tid)
{
    if (userSpaceThreadMap_.find(pid) == userSpaceThreadMap_.end()) {
        // no pid found
        // create process first
        CreateThread(pid, pid);
    }

    auto it = userSpaceThreadMap_.find(tid);
    if (it == userSpaceThreadMap_.end()) {
        // we also need thread
        return CreateThread(pid, tid);
    } else {
        return it->second;
    }
}

void VirtualRuntime::UpdateThreadMaps(pid_t pid, pid_t tid, const std::string filename,
                                      uint64_t begin, uint64_t len, uint64_t offset)
{
    VirtualThread &thread = GetThread(pid, tid);
    thread.CreateMapItem(filename, begin, len, offset);
}

void VirtualRuntime::UpdateKernelModulesSpaceMaps()
{
    // found the kernel modules
    std::vector<MemMapItem> koMaps;
    std::ifstream ifs("/proc/modules", std::ifstream::in);
    if (!ifs.is_open()) {
        perror("kernel modules read failed(/proc/modules)\n");
        return;
    }
    std::string line;
    while (getline(ifs, line)) {
        uint64_t addr = 0;
        uint64_t size = 0;
        char module[line.size()];
        /*
        name       size  load     map
        hi_mipi_rx 53248 0 - Live 0xbf109000 (O)
        hi3516cv500_hdmi 237568 0 - Live 0xbf0bb000 (O)
        hifb 143360 0 - Live 0xbf089000 (O)
        hi3516cv500_vo_dev 98304 0 - Live 0xbf070000 (O)
        hi3516cv500_tde 110592 0 - Live 0xbf04a000 (O)
        hi3516cv500_sys 36864 0 - Live 0xbf03a000 (O)
        hi3516cv500_base 20480 5
        hi_mipi_rx,hi3516cv500_hdmi,hifb,hi3516cv500_vo_dev,hi3516cv500_tde,hi3516cv500_sys,
        hi3516cv500_base,sys_config,hi_proc,hi_irq,Live 0xbf000000 (O)
        */
        int ret = sscanf_s(line.c_str(), "%s%" PRIu64 "%*u%*s%*s 0x%" PRIx64 "", module,
                           sizeof(module), &size, &addr, sizeof(addr));
        constexpr int numSlices {3};
        if (ret == numSlices) {
            MemMapItem &map = koMaps.emplace_back(addr, addr + size, 0, std::string(module));
            HLOGV("add ko map %s", map.ToString().c_str());
        } else {
            HLOGE("unknown line %d: '%s'", ret, line.c_str());
        }
    }

    if (std::all_of(koMaps.begin(), koMaps.end(),
                    [](const MemMapItem &item) { return item.begin_ == 0; })) {
        koMaps.clear();
        HLOGW("no addr found in /proc/modules. remove all the ko");
    }
    if (recordCallBack_) {
        for (MemMapItem &map : koMaps) {
            auto record = std::make_unique<PerfRecordMmap>(true, 0, 0, map.begin_,
                                                           map.end_ - map.begin_, 0, map.name_);
            recordCallBack_(std::move(record));
        }
    }
    std::move(koMaps.begin(), koMaps.end(), std::back_inserter(kernelSpaceMemMaps_));
}

void VirtualRuntime::UpdateKernelSpaceMaps()
{
    // add kernel first
    auto &map = kernelSpaceMemMaps_.emplace_back(0, std::numeric_limits<uint64_t>::max(), 0,
                                                 KERNEL_MMAP_NAME);
    if (recordCallBack_) {
        auto record = std::make_unique<PerfRecordMmap>(true, 0, 0, map.begin_,
                                                       map.end_ - map.begin_, 0, map.name_);
        recordCallBack_(std::move(record));
    }
}

void VirtualRuntime::UpdateKernelModulesSymbols()
{
    HLOGD("load ko symbol and build id");
    for (MemMapItem &map : kernelSpaceMemMaps_) {
        if (map.name_ == KERNEL_MMAP_NAME) {
            continue;
        }
        auto kernelModuleFile =
            SymbolsFile::CreateSymbolsFile(SYMBOL_KERNEL_MODULE_FILE, map.name_);
        if (symbolsPaths_.size() > 0) {
            kernelModuleFile->setSymbolsFilePath(symbolsPaths_); // also load from search path
        }
        kernelModuleFile->LoadSymbols();
        symbolsFiles_.emplace_back(std::move(kernelModuleFile));
    }
}

void VirtualRuntime::UpdateKernelSymbols()
{
    HLOGD("create a kernel mmap record");
    // found kernel source
    auto kernelFile = SymbolsFile::CreateSymbolsFile(KERNEL_MMAP_NAME);
    // set sybol path If it exists
    if (symbolsPaths_.size() > 0) {
        kernelFile->setSymbolsFilePath(symbolsPaths_); // also load from search path
    }
    if (kernelFile->LoadSymbols()) {
        auto record = std::make_unique<PerfRecordMmap>(
            true, 0, 0, kernelFile->textExecVaddr_, kernelFile->textExecVaddrRange_,
            kernelFile->textExecVaddrFileOffset_, KERNEL_MMAP_NAME);

        if (recordCallBack_) {
            recordCallBack_(std::move(record));
        }
        symbolsFiles_.emplace_back(std::move(kernelFile));
    } else {
        HLOGW("kernel symbol not found.\n");
    }
}

void VirtualRuntime::UpdatekernelMap(uint64_t begin, uint64_t end, uint64_t offset,
                                     std::string filename)
{
    HLOGV("update kernel map name:'%s' 0x%" PRIx64 " - 0x%" PRIx64 "@0x%08" PRIx64 "",
          filename.c_str(), begin, end, offset);

    HLOG_ASSERT(!filename.empty());
    auto it = find(kernelSpaceMemMaps_.begin(), kernelSpaceMemMaps_.end(), filename);
    if (it == kernelSpaceMemMaps_.end()) {
        kernelSpaceMemMaps_.emplace_back(begin, end, offset, filename);
    } else {
        it->begin_ = begin;
        it->end_ = end;
        it->pageoffset_ = offset;
        it->name_ = filename;
    }
}

void VirtualRuntime::UpdateFromRecord(PerfEventRecord &record)
{
#ifdef HIPERF_DEBUG_TIME
    const auto startTime = steady_clock::now();
#endif
    if (record.GetType() == PERF_RECORD_SAMPLE) {
        auto recordSample = static_cast<PerfRecordSample *>(&record);
        UpdateFromRecord(*recordSample);
#ifdef HIPERF_DEBUG_TIME
        prcessSampleRecordTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif
    } else if (record.GetType() == PERF_RECORD_MMAP) {
        auto recordMmap = static_cast<PerfRecordMmap *>(&record);
        UpdateFromRecord(*recordMmap);
#ifdef HIPERF_DEBUG_TIME
        prcessMmapRecordTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif
    } else if (record.GetType() == PERF_RECORD_MMAP2) {
        auto recordMmap2 = static_cast<PerfRecordMmap2 *>(&record);
        UpdateFromRecord(*recordMmap2);
#ifdef HIPERF_DEBUG_TIME
        prcessMmap2RecordTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif
    } else if (record.GetType() == PERF_RECORD_COMM) {
        auto recordCommp = static_cast<PerfRecordComm *>(&record);
        UpdateFromRecord(*recordCommp);
#ifdef HIPERF_DEBUG_TIME
        prcessCommRecordTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif
    } else {
        HLOGW("skip record type %d", record.GetType());
    }
}

void VirtualRuntime::MakeCallFrame(Symbol &symbol, CallFrame &callFrame)
{
    callFrame.vaddrInFile_ = symbol.funcVaddr_;
    callFrame.offsetToVaddr_ = symbol.offsetToVaddr_;
    callFrame.symbolFileIndex_ = symbol.symbolFileIndex_;
    callFrame.symbolName_ = symbol.Name();
    callFrame.symbolIndex_ = symbol.index_;
    callFrame.filePath_ = symbol.module_.empty() ? symbol.comm_ : symbol.module_;
    HLOG_ASSERT_MESSAGE(!callFrame.symbolName_.empty(), "%s", symbol.ToDebugString().c_str());
}

void VirtualRuntime::SymbolicCallFrame(PerfRecordSample &recordSample, uint64_t ip,
                                       perf_callchain_context context)
{
    auto symbol = GetSymbol(ip, recordSample.data_.pid, recordSample.data_.tid, context);
    MakeCallFrame(symbol, recordSample.callFrames_.emplace_back(ip, 0));
    HLOGV(" (%zu)unwind symbol: %*s%s", recordSample.callFrames_.size(),
          static_cast<int>(recordSample.callFrames_.size()), "",
          recordSample.callFrames_.back().ToSymbolString().c_str());
}

void VirtualRuntime::SymbolicRecord(PerfRecordSample &recordSample)
{
#ifdef HIPERF_DEBUG_TIME
    const auto startTime = steady_clock::now();
#endif
    // Symbolic the Call Stack
    recordSample.callFrames_.clear();
    perf_callchain_context context = PERF_CONTEXT_MAX;
    if (recordSample.data_.nr == 0) {
        SymbolicCallFrame(recordSample, recordSample.data_.ip, PERF_CONTEXT_MAX);
    }
    for (u64 i = 0; i < recordSample.data_.nr; i++) {
        uint64_t ip = recordSample.data_.ips[i];
        if (ip >= PERF_CONTEXT_MAX) {
            std::string contextName = UpdatePerfContext(ip, context);
            HLOGV("context switch to %s", contextName.c_str());
            continue;
        } else if (ip < BAD_IP_ADDRESS) {
            // ip 0 or 1 or less than 0
            continue;
        }
        SymbolicCallFrame(recordSample, ip, context);
    }
#ifdef HIPERF_DEBUG_TIME
    auto usedTime = duration_cast<microseconds>(steady_clock::now() - startTime);
    if (usedTime.count() != 0) {
        HLOGV("cost %0.3f ms to symbolic ", usedTime.count() / MS_DUARTION);
    }
    symbolicRecordTimes_ += usedTime;
#endif
}

void VirtualRuntime::UnwindFromRecord(PerfRecordSample &recordSample)
{
#ifdef HIPERF_DEBUG_TIME
    const auto startTime = steady_clock::now();
#endif
    HLOGV("unwind record (time:%llu)", recordSample.data_.time);
    // if we have userstack ?
    if (recordSample.data_.stack_size > 0) {
        auto &thread = UpdateThread(recordSample.data_.pid, recordSample.data_.tid);
        callstack_.UnwindCallStack(thread, recordSample.data_.user_abi == PERF_SAMPLE_REGS_ABI_32,
                                   recordSample.data_.user_regs, recordSample.data_.reg_nr,
                                   recordSample.data_.stack_data, recordSample.data_.dyn_size,
                                   recordSample.callFrames_);
#ifdef HIPERF_DEBUG_TIME
        unwindCallStackTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif
        size_t oldSize = recordSample.callFrames_.size();
        HLOGV("unwind %zu", recordSample.callFrames_.size());
        callstack_.ExpandCallStack(thread.tid_, recordSample.callFrames_, callstackMergeLevel_);
        HLOGV("expand %zu (+%zu)", recordSample.callFrames_.size(),
              recordSample.callFrames_.size() - oldSize);

        recordSample.ReplaceWithCallStack(oldSize);
    }

#ifdef HIPERF_DEBUG_TIME
    unwindFromRecordTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif

    // we will not do this in record mode
    if (recordCallBack_ == nullptr) {
        // find the symbols , reabuild frame info
        SymbolicRecord(recordSample);
    }
}

void VirtualRuntime::UpdateFromRecord(PerfRecordSample &recordSample)
{
    UpdateThread(recordSample.data_.pid, recordSample.data_.tid);
    // unwind
    if (disableUnwind_) {
        return;
    } else {
        UnwindFromRecord(recordSample);
    }
}

void VirtualRuntime::UpdateFromRecord(PerfRecordMmap &recordMmap)
{
    HLOGV("  MMAP: size %d pid %u tid %u", recordMmap.header.size, recordMmap.data_.pid,
          recordMmap.data_.tid);
    HLOGV("  MMAP: %s dso '%s' (0x%llx-0x%llx)@0x%llx", recordMmap.inKernel() ? "kernel" : "user",
          recordMmap.data_.filename, recordMmap.data_.addr,
          recordMmap.data_.addr + recordMmap.data_.len, recordMmap.data_.pgoff);
    // kernel mmap
    // don't overwrite the vailed mmap , so we also check the recordMmap.data_.len
    if (recordMmap.inKernel()) {
        UpdatekernelMap(recordMmap.data_.addr, recordMmap.data_.addr + recordMmap.data_.len,
                        recordMmap.data_.pgoff, recordMmap.data_.filename);
    } else {
        UpdateThreadMaps(recordMmap.data_.pid, recordMmap.data_.tid, recordMmap.data_.filename,
                         recordMmap.data_.addr, recordMmap.data_.len, recordMmap.data_.pgoff);
        UpdateSymbols(recordMmap.data_.filename);
    }
}

void VirtualRuntime::UpdateFromRecord(PerfRecordMmap2 &recordMmap2)
{
    if (!VirtualThread::IsLegalFileName(recordMmap2.data_.filename)) {
        return;
    }
    HLOGV("  MMAP2: size %d pid %u tid %u", recordMmap2.header.size, recordMmap2.data_.pid,
          recordMmap2.data_.tid);
    HLOGV("  MMAP2: %s dso '%s' (0x%llx-0x%llx)@0x%llx", recordMmap2.inKernel() ? "kernel" : "user",
          recordMmap2.data_.filename, recordMmap2.data_.addr,
          recordMmap2.data_.addr + recordMmap2.data_.len, recordMmap2.data_.pgoff);
    UpdateThreadMaps(recordMmap2.data_.pid, recordMmap2.data_.tid, recordMmap2.data_.filename,
                     recordMmap2.data_.addr, recordMmap2.data_.len, recordMmap2.data_.pgoff);
    UpdateSymbols(recordMmap2.data_.filename);
}

void VirtualRuntime::UpdateFromRecord(PerfRecordComm &recordComm)
{
    recordComm.DumpLog(__FUNCTION__);
    UpdateThread(recordComm.data_.pid, recordComm.data_.tid, recordComm.data_.comm);
}

void VirtualRuntime::SetRecordMode(RecordCallBack recordCallBack)
{
    recordCallBack_ = recordCallBack;
}

void VirtualRuntime::UpdateSymbols(std::string fileName)
{
    HLOGD("try to find symbols for file: %s", fileName.c_str());
#ifdef HIPERF_DEBUG_TIME
    const auto startTime = steady_clock::now();
#endif
    for (auto &symbolsFile : symbolsFiles_) {
        if (symbolsFile->filePath_ == fileName) {
            HLOGV("already have '%s'", fileName.c_str());
            return;
        }
    }
    // found it by name
    auto symbolsFile = SymbolsFile::CreateSymbolsFile(fileName);

    // set sybol path If it exists
    if (symbolsPaths_.size() > 0) {
        symbolsFile->setSymbolsFilePath(symbolsPaths_); // also load from search path
    }
    if (loadSymboleWhenNeeded_) {
        // load it when we need it
        symbolsFiles_.emplace_back(std::move(symbolsFile));
    } else if (symbolsFile->LoadSymbols()) {
        symbolsFiles_.emplace_back(std::move(symbolsFile));
    } else {
        HLOGW("symbols file for '%s' not found.", fileName.c_str());
    }
#ifdef HIPERF_DEBUG_TIME
    auto usedTime = duration_cast<microseconds>(steady_clock::now() - startTime);
    if (usedTime.count() != 0) {
        HLOGV("cost %0.3f ms to load '%s'", usedTime.count() / MS_DUARTION, fileName.c_str());
    }
    updateSymbolsTimes_ += usedTime;
#endif
}

const Symbol VirtualRuntime::GetKernelSymbol(uint64_t ip, const std::vector<MemMapItem> &memMaps,
                                             const VirtualThread &thread)
{
    Symbol vaddrSymbol(ip, thread.name_);
    for (auto &map : memMaps) {
        if (ip > map.begin_ && ip < map.end_) {
            HLOGM("found addr 0x%" PRIx64 " in kernel map 0x%" PRIx64 " - 0x%" PRIx64 " from %s",
                  ip, map.begin_, map.end_, map.name_.c_str());
            vaddrSymbol.module_ = map.name_;
            // found symbols by file name
            for (auto &symbolsFile : symbolsFiles_) {
                if (symbolsFile->filePath_ == map.name_) {
                    vaddrSymbol.symbolFileIndex_ = symbolsFile->id_;
                    vaddrSymbol.fileVaddr_ =
                        symbolsFile->GetVaddrInSymbols(ip, map.begin_, map.pageoffset_);
                    HLOGV("found symbol vaddr 0x%" PRIx64 " for runtime vaddr 0x%" PRIx64
                          " at '%s'",
                          vaddrSymbol.fileVaddr_, ip, map.name_.c_str());
                    if (!symbolsFile->SymbolsLoaded()) {
                        symbolsFile->LoadSymbols();
                    }
                    Symbol foundSymbols = symbolsFile->GetSymbolWithVaddr(vaddrSymbol.fileVaddr_);
                    foundSymbols.taskVaddr_ = ip;
                    if (!foundSymbols.isValid()) {
                        HLOGW("addr 0x%" PRIx64 " vaddr  0x%" PRIx64 " NOT found in symbol file %s",
                              ip, vaddrSymbol.fileVaddr_, map.name_.c_str());
                        return vaddrSymbol;
                    } else {
                        return foundSymbols;
                    }
                }
            }
            HLOGW("addr 0x%" PRIx64 " in map but NOT found the symbol file %s", ip,
                  map.name_.c_str());
        } else {
            HLOGM("addr 0x%" PRIx64 " not in map 0x%" PRIx64 " - 0x%" PRIx64 " from %s", ip,
                  map.begin_, map.end_, map.name_.c_str());
        }
    }
    return vaddrSymbol;
}

const Symbol VirtualRuntime::GetUserSymbol(uint64_t ip, const VirtualThread &thread)
{
    Symbol vaddrSymbol(ip, thread.name_);
    const MemMapItem *mmap = thread.FindMapByAddr(ip);
    if (mmap != nullptr) {
        SymbolsFile *symbolsFile = thread.FindSymbolsFileByMap(*mmap);
        if (symbolsFile != nullptr) {
            vaddrSymbol.symbolFileIndex_ = symbolsFile->id_;
            vaddrSymbol.fileVaddr_ =
                symbolsFile->GetVaddrInSymbols(ip, mmap->begin_, mmap->pageoffset_);
            vaddrSymbol.module_ = mmap->nameHold_;
            HLOGV("found symbol vaddr 0x%" PRIx64 " for runtime vaddr 0x%" PRIx64 " at '%s'",
                  vaddrSymbol.fileVaddr_, ip, mmap->name_.c_str());
            if (!symbolsFile->SymbolsLoaded()) {
                symbolsFile->LoadSymbols();
            }
            Symbol foundSymbols = symbolsFile->GetSymbolWithVaddr(vaddrSymbol.fileVaddr_);
            foundSymbols.taskVaddr_ = ip;
            if (!foundSymbols.isValid()) {
                HLOGW("addr 0x%" PRIx64 " vaddr  0x%" PRIx64 " NOT found in symbol file %s", ip,
                      vaddrSymbol.fileVaddr_, mmap->name_.c_str());
                return vaddrSymbol;
            } else {
                return foundSymbols;
            }
        } else {
            HLOGW("addr 0x%" PRIx64 " in map but NOT found the symbol file %s", ip,
                  mmap->name_.c_str());
        }
    } else {
#ifdef HIPERF_DEBUG
        thread.ReportVaddrMapMiss(ip);
#endif
    }
    return vaddrSymbol;
}

bool VirtualRuntime::GetSymbolCache(uint64_t ip, pid_t pid, pid_t tid, Symbol &symbol,
                                    const perf_callchain_context &context)
{
    if (context != PERF_CONTEXT_USER and kernelSymbolCache_.count(ip)) {
        if (kernelSymbolCache_.find(ip) == kernelSymbolCache_.end()) {
            return false;
        }
        Symbol &foundSymbol = kernelSymbolCache_[ip];
        foundSymbol.hit_++;
        HLOGV("hit kernel cache 0x%" PRIx64 " %d", ip, foundSymbol.hit_);
        symbol = foundSymbol;
        return true;
    } else if (threadSymbolCache_[tid].count(ip) != 0) {
        Symbol &foundSymbol = threadSymbolCache_[tid][ip];
        foundSymbol.hit_++;
        HLOGV("hit user cache 0x%" PRIx64 " %d %s", ip, foundSymbol.hit_,
              foundSymbol.ToDebugString().c_str());
        symbol = foundSymbol;
        return true;
    } else {
        HLOGM("cache miss k %zu u %zu", kernelSymbolCache_.size(), threadSymbolCache_[tid].size());
    }
    return false;
}

const Symbol VirtualRuntime::GetSymbol(uint64_t ip, pid_t pid, pid_t tid,
                                       const perf_callchain_context &context)
{
    HLOGV("try find tid %u ip 0x%" PRIx64 " in %zu symbolsFiles", tid, ip, symbolsFiles_.size());
    Symbol symbol;
    if (threadSymbolCache_.find(tid) == threadSymbolCache_.end()) {
        threadSymbolCache_[tid].reserve(THREAD_SYMBOL_CACHE_LIMIT);
    }
    if (GetSymbolCache(ip, pid, tid, symbol, context)) {
        return symbol;
    }
    if (context == PERF_CONTEXT_USER or (context == PERF_CONTEXT_MAX and !symbol.isValid())) {
        // check userspace memmap
        symbol = GetUserSymbol(ip, GetThread(pid, tid));
        threadSymbolCache_[tid][ip] = symbol;
        HLOGV("cache ip 0x%" PRIx64 " to %s", ip,
              threadSymbolCache_[tid][ip].ToDebugString().c_str());
    }

    if (context == PERF_CONTEXT_KERNEL or (context == PERF_CONTEXT_MAX and !symbol.isValid())) {
        // check kernelspace
        HLOGM("try found addr in kernelspace %zu maps", kernelSpaceMemMaps_.size());
        symbol = GetKernelSymbol(ip, kernelSpaceMemMaps_, GetThread(pid, tid));
        HLOGM("add addr to kernel cache 0x%" PRIx64 " cache size %zu", ip,
              kernelSymbolCache_.size());
        kernelSymbolCache_[ip] = symbol;
    }
    return symbol;
}

bool VirtualRuntime::SetSymbolsPaths(const std::vector<std::string> &symbolsPaths)
{
    std::unique_ptr<SymbolsFile> symbolsFile = SymbolsFile::CreateSymbolsFile(SYMBOL_UNKNOW_FILE);
    // we need check if the path is accessible
    bool accessible = symbolsFile->setSymbolsFilePath(symbolsPaths);
    if (accessible) {
        symbolsPaths_ = symbolsPaths;
    } else {
        if (!symbolsPaths.empty()) {
            printf("some symbols path unable access\n");
        }
    }
    return accessible;
}

void VirtualRuntime::UpdateFromPerfData(const std::vector<SymbolFileStruct> &symbolFileStructs)
{
    // review: if we need move to some other place ?
    HLOG_ASSERT_MESSAGE(symbolsFiles_.size() == 0, " symbolsFiles_ size is %zu",
                        symbolsFiles_.size());
    for (const auto &symbolFileStruct : symbolFileStructs) {
        HLOGV("symbolFileStruct.filePath_:'%s'", symbolFileStruct.filePath_.c_str());
        HLOGV("symbolFileStruct.buildId_:'%s'", symbolFileStruct.buildId_.c_str());
        HLOGV("process symbols file:'%s':'%s'", symbolFileStruct.filePath_.c_str(),
              symbolFileStruct.buildId_.c_str());

        // load from symbolFileStruct (perf.data)
        std::unique_ptr<SymbolsFile> symbolsFile =
            SymbolsFile::LoadSymbolsFromSaved(symbolFileStruct);

        // reaload from sybol path If it exists
        if (symbolsPaths_.size() > 0) {
            HLOGV("try again with symbolsPaths setup");
            symbolsFile->setSymbolsFilePath(symbolsPaths_); // also load from search path
            // use give us path ,we must reload it.
            symbolsFile->LoadSymbols();
        }
        symbolsFile->id_ = symbolsFiles_.size();
        symbolsFiles_.emplace_back(std::move(symbolsFile));
    }
}

/*
   ARM functions
       The table below lists the symbols exported by the vDSO.

       symbol                 version
       ────────────────────────────────────────────────────────────
       __vdso_gettimeofday    LINUX_2.6 (exported since Linux 4.1)
       __vdso_clock_gettime   LINUX_2.6 (exported since Linux 4.1)

       Additionally, the ARM port has a code page full of utility
       functions.  Since it's just a raw page of code, there is no ELF
       information for doing symbol lookups or versioning.  It does
       provide support for different versions though.

       For information on this code page, it's best to refer to the
       kernel documentation as it's extremely detailed and covers
       everything you need to know:
       Documentation/arm/kernel_user_helpers.txt.

   aarch64 functions
       The table below lists the symbols exported by the vDSO.

       symbol                   version
       ──────────────────────────────────────
       __kernel_rt_sigreturn    LINUX_2.6.39
       __kernel_gettimeofday    LINUX_2.6.39
       __kernel_clock_gettime   LINUX_2.6.39
       __kernel_clock_getres    LINUX_2.6.39
*/
void VirtualRuntime::LoadVdso()
{
#if !is_mingw
    VirtualThread myThread(getpid(), symbolsFiles_);
    myThread.ParseMap();
    for (const auto &map : myThread.GetMaps()) {
        if (map.name_ == MMAP_VDSO_NAME) {
            std::string memory(map.end_ - map.begin_, '\0');
            std::copy(reinterpret_cast<char *>((map.begin_)), reinterpret_cast<char *>((map.end_)),
                      &memory[0]);
            std::string tempPath("/data/local/tmp/");
            std::string tempFileName = tempPath + MMAP_VDSO_NAME;
            if (!WriteStringToFile(tempFileName, memory)) {
                printf("vdso temp file create fail at %s\n", tempFileName.c_str());
            } else {
                HLOGD("vdso temp file create at %s:%zu", tempFileName.c_str(), memory.size());
                auto symbolsFile = SymbolsFile::CreateSymbolsFile(MMAP_VDSO_NAME);
                symbolsFile->setSymbolsFilePath(tempPath); // also load from search path
                symbolsFiles_.emplace_back(std::move(symbolsFile));
                return;
            }
        }
    }
    HLOGD("no vdso found");
#endif
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
