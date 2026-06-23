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
#define HILOG_TAG "RecordProcessor"

#include "record_processor.h"

#include <cinttypes>

#include "dfx_map.h"
#include "string_util.h"

#include "debug_logger.h"
#include "hiperf_hilog.h"
#include "utilities.h"

using namespace std::chrono;

namespace OHOS {
namespace Developtools {
namespace HiPerf {

RecordProcessor::RecordProcessor(ThreadManager& threadManager, MemoryMapManager& mapManager,
                                 CallStackProcessor& callStackProcessor, SmoProcessor& smoProcessor,
                                 const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles,
                                 const RuntimeContext& ctx, const SymbolsFileRegisterFunc& registerFunc)
    : threadManager_(threadManager), mapManager_(mapManager),
      callStackProcessor_(callStackProcessor), smoProcessor_(smoProcessor),
      symbolsFiles_(symbolsFiles), ctx_(ctx), registerFunc_(registerFunc)
{
}

void RecordProcessor::UpdateFromRecord(PerfEventRecord& record)
{
#ifdef HIPERF_DEBUG_TIME
    const auto startTime = steady_clock::now();
#endif
    if (record.GetType() == PERF_RECORD_SAMPLE) {
        auto recordSample = static_cast<PerfRecordSample*>(&record);
        UpdateFromRecord(*recordSample);
#ifdef HIPERF_DEBUG_TIME
        processSampleRecordTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif
    } else if (record.GetType() == PERF_RECORD_MMAP) {
        auto recordMmap = static_cast<PerfRecordMmap*>(&record);
        UpdateFromRecord(*recordMmap);
#ifdef HIPERF_DEBUG_TIME
        processMmapRecordTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif
    } else if (record.GetType() == PERF_RECORD_MMAP2) {
        auto recordMmap2 = static_cast<PerfRecordMmap2*>(&record);
        UpdateFromRecord(*recordMmap2);
#ifdef HIPERF_DEBUG_TIME
        processMmap2RecordTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif
    } else if (record.GetType() == PERF_RECORD_COMM) {
        auto recordComm = static_cast<PerfRecordComm*>(&record);
        UpdateFromRecord(*recordComm);
#ifdef HIPERF_DEBUG_TIME
        processCommRecordTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif
    } else if (record.GetType() == PERF_RECORD_AUXTRACE) {
        auto recordAuxTrace = static_cast<PerfRecordAuxtrace*>(&record);
        UpdateFromRecord(*recordAuxTrace);
#ifdef HIPERF_DEBUG_TIME
        processAuxtraceRecordTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif
    } else if (record.GetType() == PERF_RECORD_TYPE_SMO_NUM) {
        auto perfRecordSmo = static_cast<PerfRecordSmoDetachingEvent*>(&record);
        smoProcessor_.UpdateFromRecord(*perfRecordSmo);
    } else {
        HLOGW("skip record type %d", record.GetType());
    }
}

void RecordProcessor::UpdateProcessSymbols(VirtualThread& thread, const pid_t pid)
{
    if (ctx_.isHM) {
        thread.FixHMBundleMap();
    }
    std::shared_ptr<DfxMap> prevMap = nullptr;
    for (auto& map : thread.GetMaps()) {
        // so in hap is load before start perf record
        // dynamic load library should be treat in the same way
        bool updateNormalSymbol = true;
        if (map->name.find(".hap") != std::string::npos && (map->prots & PROT_EXEC)) {
            map->prevMap = prevMap;
            updateNormalSymbol = !UpdateHapSymbols(map);
            HLOGD("UpdateHapSymbols");
        }
        auto mmapRecord =
            std::make_unique<PerfRecordMmap2>(false, thread.pid_, thread.tid_, map);
        HLOGD("make PerfRecordMmap2 %d:%d:%s:%s(0x%" PRIx64 "-0x%" PRIx64 ")@%" PRIx64 " ",
              thread.pid_, thread.tid_, thread.name_.c_str(), map->name.c_str(),
              map->begin, map->end, map->offset);
        recordCallBack_(*mmapRecord);
        if (updateNormalSymbol) {
            UpdateSymbols(map, pid);
        }
        prevMap = map;
    }
}

bool RecordProcessor::UpdateHapSymbols(std::shared_ptr<DfxMap> map)
{
    if (map == nullptr) {
        return false;
    }
    HLOGV("hap name:%s", map->name.c_str());
    // found it by name
    auto symbolsFile = SymbolsFile::CreateSymbolsFile(map->name);
    CHECK_TRUE(symbolsFile != nullptr, false, 1,
               "Failed to load CreateSymbolsFile for exec section in hap(%s)", map->name.c_str());
    symbolsFile->SetMapsInfo(map);
    // update maps name if load debuginfo successfully
    CHECK_TRUE(symbolsFile->LoadDebugInfo(map), false, 1,
               "Failed to load debuginfo for exec section in hap(%s)", map->name.c_str());

    if (!loadSymbolsWhenNeeded_) {
        symbolsFile->LoadSymbols(map);
    }
    registerFunc_(std::move(symbolsFile));
    return true;
}

void RecordProcessor::UpdateSymbols(std::shared_ptr<DfxMap> map, const pid_t pid)
{
    CHECK_TRUE(map != nullptr && map->symbolFileIndex == -1, NO_RETVAL, 0, "");
    HLOGD("try to find symbols for file: %s", map->name.c_str());
    for (size_t i = 0; i < symbolsFiles_.size(); ++i) {
        if (symbolsFiles_[i]->filePath_ == map->name) {
            map->symbolFileIndex = static_cast<int32_t>(i);
            HLOGV("already have '%s', symbol index:%zu", map->name.c_str(), i);
            return;
        }
    }

#ifdef HIPERF_DEBUG_TIME
    const auto startTime = steady_clock::now();
#endif
    /**
     * map[]     map.name = SymbolsFile.filePath_         prot    SymbolsFileType
     * seg1      /data/storage/el1/bundle/entry.hap       r--p    ABC
     * seg2      /data/storage/el1/bundle/entry.hap       r-xp    ELF
     * seg3      /data/storage/el1/bundle/entry.hap       r--p    ABC
     * seg4      /data/storage/el1/bundle/entry.hap       r--p    ABC
     * segN      .hap                                     r--p    .an/jit/etc
     * 1.map.name == symbolsFile.filePath_
     * 2.map.FileType == symbolsFiles_[map.symbolFileIndex]
     * 3.cache pc->map->symbolsFiles[map.symbolFileIndex]
     * 4.must ensure map.mapType assigned with SymbolsFile constructions at the same time.
    */
    auto symbolsFile = SymbolsFile::CreateSymbolsFile(map->name, pid);
    symbolsFile->SetMapsInfo(map);
    if (enableDebugInfoSymbolic_ && symbolsFile->symbolFileType_ == SymbolsFileType::SYMBOL_ELF_FILE) {
        symbolsFile->EnableMiniDebugInfo();
    }
    // set symbol path If it exists
    if (symbolsPaths_.size() > 0) {
        // also load from search path
        symbolsFile->setSymbolsFilePath(symbolsPaths_);
    }
    if (loadSymbolsWhenNeeded_) {
        // load it when we need it
        registerFunc_(std::move(symbolsFile));
    } else if (symbolsFile->LoadSymbols()) {
        registerFunc_(std::move(symbolsFile));
    } else {
        HLOGW("symbols file for '%s' not found.", map->name.c_str());
    }
#ifdef HIPERF_DEBUG_TIME
    auto usedTime = duration_cast<microseconds>(steady_clock::now() - startTime);
    if (usedTime.count() != 0) {
        HLOGV("cost %0.3f ms to load '%s'", usedTime.count() / MS_DURATION, map->name.c_str());
    }
    updateSymbolsTimes_ += usedTime;
#endif
}

void RecordProcessor::UpdateFromRecord(PerfRecordSample& recordSample)
{
    threadManager_.UpdateThread(recordSample.data_.pid, recordSample.data_.tid);
    if (recordSample.data_.server_nr) {
        // update all server threads
        for (size_t i = 0; i < recordSample.data_.server_nr; i++) {
            pid_t pid = static_cast<pid_t>(recordSample.data_.server_pids[i]);
            threadManager_.UpdateThread(pid, pid);
        }
    }
    callStackProcessor_.AdjustCallChain(recordSample);
    callStackProcessor_.ProcessKernelCallChain(recordSample);
    // unwind
    if (disableUnwind_) {
        return;
    }
    callStackProcessor_.UnwindFromRecord(recordSample);
}

void RecordProcessor::UpdateFromRecord(PerfRecordMmap& recordMmap)
{
    HLOGV("  MMAP: size %d pid %u tid %u", recordMmap.header_.size, recordMmap.data_.pid,
          recordMmap.data_.tid);
    HLOGV("  MMAP: %s dso '%s' (0x%llx-0x%llx)@0x%llx", recordMmap.InKernel() ? "kernel" : "user",
          recordMmap.data_.filename, recordMmap.data_.addr,
          recordMmap.data_.addr + recordMmap.data_.len, recordMmap.data_.pgoff);
    // kernel mmap
    // don't overwrite the vailed mmap , so we also check the recordMmap.data_.len
    if (threadManager_.IsKernelThread(recordMmap.data_.pid)) {
        mapManager_.UpdateKernelThreadMap(recordMmap.data_.pid, recordMmap.data_.addr,
                                          recordMmap.data_.len, recordMmap.data_.pgoff,
                                          recordMmap.data_.filename);
    } else if (recordMmap.InKernel()) {
        mapManager_.UpdateKernelMap(recordMmap.data_.addr, recordMmap.data_.addr + recordMmap.data_.len,
                                    recordMmap.data_.pgoff, recordMmap.data_.filename);
    } else {
        NeedAdaptSandboxPath(recordMmap.data_.filename, recordMmap.data_.pid, recordMmap.header_.size);
        FixHMBundleMmap(recordMmap.data_.filename, recordMmap.data_.pid, recordMmap.header_.size);
        auto map = mapManager_.UpdateThreadMaps(recordMmap.data_.pid, recordMmap.data_.tid,
                                                recordMmap.data_.filename, recordMmap.data_.addr,
                                                recordMmap.data_.len, recordMmap.data_.pgoff);
        UpdateSymbols(map, recordMmap.data_.pid);
    }
}

void RecordProcessor::UpdateSandBoxThreadMaps(std::unique_ptr<SymbolsFile>& symFile,
                                              std::shared_ptr<DfxMap>& curMap,
                                              std::shared_ptr<DfxMap>& prevMap,
                                              PerfRecordMmap2& recordMmap2)
{
    if (strstr(recordMmap2.data_.filename, ".hap") == nullptr) {
        auto elfLoadInfoMap = symFile->GetPtLoads();
        u64 begin = recordMmap2.data_.addr - elfLoadInfoMap[0].mmapLen;
        u64 len = elfLoadInfoMap[0].mmapLen;
        u64 alignMask = elfLoadInfoMap[0].align >= 1 ? elfLoadInfoMap[0].align - 1 : 0;
        u64 pgoff = elfLoadInfoMap[0].offset & (~alignMask);
        std::unique_ptr<PerfRecordMmap2> mmap2FirstSeg =
            std::make_unique<PerfRecordMmap2>(recordMmap2.InKernel(), recordMmap2.data_.pid, recordMmap2.data_.tid,
                                              begin, len, pgoff, 0, 0, 0, PROT_READ, 0,
                                              std::string(recordMmap2.data_.filename));
        mapManager_.UpdateThreadMaps(mmap2FirstSeg->data_.pid, mmap2FirstSeg->data_.tid, mmap2FirstSeg->data_.filename,
                                     mmap2FirstSeg->data_.addr, mmap2FirstSeg->data_.len, mmap2FirstSeg->data_.pgoff);
        recordCallBack_(*mmap2FirstSeg);
    } else {
        auto elfLoadInfoMap = symFile->GetPtLoads();
        u64 begin = recordMmap2.data_.addr - elfLoadInfoMap[0].mmapLen;
        u64 len = elfLoadInfoMap[0].mmapLen;
        u64 pgoff = elfLoadInfoMap[0].offset &
                    (~(elfLoadInfoMap[0].align >= 1 ? elfLoadInfoMap[0].align - 1 : 0));
        std::unique_ptr<PerfRecordMmap2> mmap2FirstSeg =
            std::make_unique<PerfRecordMmap2>(recordMmap2.InKernel(), recordMmap2.data_.pid, recordMmap2.data_.tid,
                                              begin, len, pgoff, 0, 0, 0, PROT_READ, 0, curMap->name);
        mapManager_.UpdateThreadMaps(recordMmap2.data_.pid, recordMmap2.data_.tid, curMap->name,
                                     begin, len, pgoff);
        recordCallBack_(*mmap2FirstSeg);

        std::unique_ptr<PerfRecordMmap2> mmap2SecondSegment =
            std::make_unique<PerfRecordMmap2>(recordMmap2.InKernel(), recordMmap2.data_.pid, recordMmap2.data_.tid,
                                              recordMmap2.data_.addr,
                                              recordMmap2.data_.len,
                                              recordMmap2.data_.pgoff - prevMap->offset, // minus load offset of hap
                                              0, 0, 0, recordMmap2.data_.prot, 0, curMap->name);
        mapManager_.UpdateThreadMaps(recordMmap2.data_.pid, recordMmap2.data_.tid, curMap->name,
                                     recordMmap2.data_.addr, recordMmap2.data_.len,
                                     recordMmap2.data_.pgoff - prevMap->offset);
        recordCallBack_(*mmap2SecondSegment);
        recordMmap2.discard_ = true;
    }
}

bool RecordProcessor::CheckValidSandBoxMmap(PerfRecordMmap2& recordMmap2)
{
    static std::shared_ptr<DfxMap> prevMap;
    if ((recordMmap2.data_.prot & PROT_EXEC) != 0) {
        // fake first segment, when second segment come.
        auto symFile = SymbolsFile::CreateSymbolsFile(
            SYMBOL_ELF_FILE, recordMmap2.data_.filename, recordMmap2.data_.pid);
        CHECK_TRUE(symFile != nullptr, false, 1, "CheckValidSandBoxMmap Failed to create symbolFile!");

        std::shared_ptr<DfxMap> curMap;
        if (strstr(recordMmap2.data_.filename, ".hap") != nullptr) {
            curMap = std::make_shared<DfxMap>(
                recordMmap2.data_.addr,
                recordMmap2.data_.addr + recordMmap2.data_.len,
                recordMmap2.data_.pgoff,
                "",
                // prot
                recordMmap2.data_.filename
            );
            curMap->prevMap = prevMap;
        }

        CHECK_TRUE(symFile->LoadDebugInfo(curMap), false, 1, "CheckValidSandBoxMmap Failed to load debuginfo!");

        if (!loadSymbolsWhenNeeded_) {
            symFile->LoadSymbols(curMap);
        }
        UpdateSandBoxThreadMaps(symFile, curMap, prevMap, recordMmap2);
        registerFunc_(std::move(symFile));
        return true;
    } else if (recordMmap2.data_.pgoff == 0) {
        recordMmap2.discard_ = true;
    }

    if (strstr(recordMmap2.data_.filename, ".hap") != nullptr) {
        prevMap = std::make_shared<DfxMap>(
            recordMmap2.data_.addr,
            recordMmap2.data_.addr + recordMmap2.data_.len,
            recordMmap2.data_.pgoff,
            "", // prot
            recordMmap2.data_.filename
        );
        HLOGD("CheckValidSandBoxMmap Update prev map!");
    }
    return !recordMmap2.discard_;
}

void RecordProcessor::UpdateFromRecord(PerfRecordMmap2& recordMmap2)
{
    if (!OHOS::HiviewDFX::DfxMaps::IsLegalMapItem(recordMmap2.data_.filename)) {
        return;
    }

    HLOGV("  MMAP2: size %d pid %u tid %u", recordMmap2.header_.size, recordMmap2.data_.pid,
          recordMmap2.data_.tid);
    HLOGV("  MMAP2: %s dso '%s' (0x%llx-0x%llx)@0x%llx prot:%u", recordMmap2.InKernel() ? "kernel" : "user",
          recordMmap2.data_.filename, recordMmap2.data_.addr,
          recordMmap2.data_.addr + recordMmap2.data_.len, recordMmap2.data_.pgoff, recordMmap2.data_.prot);
    if (recordCallBack_) {
        if (NeedAdaptSandboxPath(recordMmap2.data_.filename, recordMmap2.data_.pid, recordMmap2.header_.size)) {
            FixHMBundleMmap(recordMmap2.data_.filename, recordMmap2.data_.pid, recordMmap2.header_.size);
            CHECK_TRUE(CheckValidSandBoxMmap(recordMmap2), NO_RETVAL, 0, "");
        }
    }
    auto map = mapManager_.UpdateThreadMaps(recordMmap2.data_.pid, recordMmap2.data_.tid,
                                            recordMmap2.data_.filename, recordMmap2.data_.addr,
                                            recordMmap2.data_.len, recordMmap2.data_.pgoff,
                                            recordMmap2.data_.prot);
    UpdateSymbols(map, recordMmap2.data_.pid);
}

void RecordProcessor::UpdateFromRecord(PerfRecordComm& recordComm)
{
    recordComm.DumpLog(__FUNCTION__);
    threadManager_.UpdateThread(recordComm.data_.pid, recordComm.data_.tid, recordComm.data_.comm);
}

void RecordProcessor::UpdateFromRecord(PerfRecordAuxtrace& recordAuxTrace)
{
    if (recordCallBack_ == nullptr) {
        callStackProcessor_.ProcessAuxtraceRecord(recordAuxTrace);
    }
}

void RecordProcessor::FixHMBundleMmap(char* filename, const int pid, u16& headerSize)
{
    if (!ctx_.isHM) {
        return;
    }
    // fix bundle path in mmap
    std::string newFilename = filename;
    VirtualThread &thread = threadManager_.GetThread(pid, pid);
    if (NeedAdaptHMBundlePath(newFilename, thread.name_)) {
        size_t oldSize = strlen(filename);
        if (memset_s(filename, KILO, '\0', KILO) != EOK) {
            HLOGD("memset_s failed in FixHMBundleMmap.");
        }
        if (strncpy_s(filename, KILO, newFilename.c_str(), newFilename.size()) != 0) {
            HLOGD("strncpy_s recordMmap2 failed!");
        }
        headerSize += newFilename.size() - oldSize;
    }
}

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
