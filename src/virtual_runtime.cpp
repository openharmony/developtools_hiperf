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

#include "debug_logger.h"
#include "hiperf_hilog.h"
#include "utilities.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {

VirtualRuntime::VirtualRuntime(const bool onDevice)
{
    runtimeContext_.isRoot = IsRoot();

    symbolsFileRegisterFunc_ = [this](std::unique_ptr<SymbolsFile> symFile) -> int32_t {
        if (symFile == nullptr) {
            return -1;
        }
        int32_t id = static_cast<int32_t>(symbolsFiles_.size());
        symFile->id_ = id;
        symbolsFiles_.emplace_back(std::move(symFile));
        return id;
    };

    threadManager_ = std::make_unique<ThreadManager>(symbolsFiles_, runtimeContext_);
    threadManager_->UpdateThread(0, 0, "swapper");

    mapManager_ = std::make_unique<MemoryMapManager>(*threadManager_, runtimeContext_);

    symbolManager_ = std::make_unique<SymbolManager>(
        symbolsFiles_,
        mapManager_->GetKernelMaps(),
        runtimeContext_
    );

    callStackProcessor_ = std::make_unique<CallStackProcessor>(*symbolManager_, *threadManager_, runtimeContext_);

    smoProcessor_ = std::make_unique<SmoProcessor>(symbolsFiles_, *symbolManager_, symbolsFileRegisterFunc_);

    recordProcessor_ = std::make_unique<RecordProcessor>(
        *threadManager_,
        *mapManager_,
        *callStackProcessor_,
        *smoProcessor_,
        symbolsFiles_,
        runtimeContext_,
        symbolsFileRegisterFunc_
    );
    recordProcessor_->SetLoadSymbolsWhenNeeded(loadSymbolsWhenNeeded_);

    kernelSymbolLoader_ = std::make_unique<KernelSymbolLoader>(
        symbolsFiles_,
        *mapManager_,
        *threadManager_,
        runtimeContext_,
        symbolsFileRegisterFunc_
    );

    threadManager_->SetProcessSymbolsCallBack(
        [this](VirtualThread& thread, pid_t pid) {
            recordProcessor_->UpdateProcessSymbols(thread, pid);
        });

    kernelSymbolLoader_->SetUpdateSymbolsCallBack(
        [this](std::shared_ptr<DfxMap> map, pid_t pid) {
            recordProcessor_->UpdateSymbols(map, pid);
        });
}

VirtualRuntime::~VirtualRuntime()
{
}

void VirtualRuntime::SetRecordMode(const RecordCallBack& recordCallBack)
{
    threadManager_->SetRecordMode(recordCallBack);
    mapManager_->SetRecordMode(recordCallBack);
    smoProcessor_->SetRecordMode(recordCallBack);
    callStackProcessor_->SetRecordMode(recordCallBack);
    symbolManager_->SetRecordMode(recordCallBack != nullptr);
    kernelSymbolLoader_->SetRecordMode(recordCallBack);
    recordProcessor_->SetRecordMode(recordCallBack);
}

void VirtualRuntime::SetCollectSymbolCallBack(const CollectSymbolCallBack& collectSymbolCallBack)
{
    callStackProcessor_->SetCollectSymbolCallBack(collectSymbolCallBack);
}

void VirtualRuntime::SetSmoFlag(bool flag)
{
    runtimeContext_.smoFlag = flag;
}

void VirtualRuntime::UpdateFromRecord(PerfEventRecord& record)
{
    recordProcessor_->UpdateFromRecord(record);
}

void VirtualRuntime::NeedDropKernelCallChain(PerfRecordSample& sample)
{
    callStackProcessor_->NeedDropKernelCallChain(sample);
}

void VirtualRuntime::UpdateKernelSpaceMaps()
{
    mapManager_->UpdateKernelSpaceMaps();
}

void VirtualRuntime::UpdateKernelModulesSpaceMaps()
{
    mapManager_->UpdateKernelModulesSpaceMaps();
}

void VirtualRuntime::UpdateServiceSpaceMaps()
{
    mapManager_->UpdateServiceSpaceMaps();
}

void VirtualRuntime::UpdateDevhostSpaceMaps()
{
    mapManager_->UpdateDevhostSpaceMaps();
}

void VirtualRuntime::LoadVdso()
{
    kernelSymbolLoader_->LoadVdso();
}

void VirtualRuntime::UpdateKernelSymbols()
{
    kernelSymbolLoader_->UpdateKernelSymbols();
}

void VirtualRuntime::UpdateKernelModulesSymbols()
{
    kernelSymbolLoader_->UpdateKernelModulesSymbols();
}

void VirtualRuntime::UpdateServiceSymbols()
{
    kernelSymbolLoader_->UpdateServiceSymbols();
}

void VirtualRuntime::UpdateDevhostSymbols()
{
    kernelSymbolLoader_->UpdateDevhostSymbols();
}

void VirtualRuntime::SetDevhostPid(const pid_t devhost)
{
    HLOGD("Set devhost pid: %d", devhost);
    runtimeContext_.devhostPid = devhost;
    symbolManager_->SetDevhostPid(devhost);
}

void VirtualRuntime::FixHMBundleMmap(char* filename, const int pid, u16& headerSize)
{
    recordProcessor_->FixHMBundleMmap(filename, pid, headerSize);
}

bool VirtualRuntime::SetSymbolsPaths(const std::vector<std::string>& symbolsPaths)
{
    std::unique_ptr<SymbolsFile> symbolsFile = SymbolsFile::CreateSymbolsFile(SYMBOL_UNKNOW_FILE);
    CHECK_TRUE(symbolsFile != nullptr, false, 0, "");
    // we need check if the path is accessible
    bool accessible = symbolsFile->setSymbolsFilePath(symbolsPaths);
    if (accessible) {
        kernelSymbolLoader_->SetSymbolsPaths(symbolsPaths);
        recordProcessor_->SetSymbolsPaths(symbolsPaths);
    } else {
        if (!symbolsPaths.empty()) {
            HLOGE("some symbols path unable access");
        }
    }
    return accessible;
}

const std::map<std::string, std::vector<AdltMapDataFragment>>& VirtualRuntime::GetSoMappingMap()
{
    return smoProcessor_->GetSoMappingMap();
}

const ProcessStackMap* VirtualRuntime::GetUniStackTable()
{
    return callStackProcessor_->GetUniStackTable();
}

void VirtualRuntime::SetCallStackExpend(const size_t mergeLevel)
{
    callStackProcessor_->SetCallStackExpend(mergeLevel);
}

void VirtualRuntime::SetDisableUnwind(const bool disableUnwind)
{
    HLOGV("disableUnwind change to %d", disableUnwind);
    callStackProcessor_->SetDisableUnwind(disableUnwind);
    recordProcessor_->SetDisableUnwind(disableUnwind);
}

void VirtualRuntime::EnableDebugInfoSymbolic(const bool enable)
{
    recordProcessor_->SetEnableDebugInfoSymbolic(enable);
}

void VirtualRuntime::SetDedupStack()
{
    callStackProcessor_->SetDedupStack(true);
}

void VirtualRuntime::ImportUniqueStackNodes(const std::vector<UniStackTableInfo>& infos)
{
    callStackProcessor_->ImportUniqueStackNodes(infos);
}

void VirtualRuntime::SetHM(bool isHM)
{
    runtimeContext_.isHM = isHM;
}

void VirtualRuntime::SetIsRoot(bool isRoot)
{
    runtimeContext_.isRoot = isRoot;
}

void VirtualRuntime::SetNeedKernelCallChain(const bool kernelCallChain)
{
    callStackProcessor_->SetNeedKernelCallChain(kernelCallChain);
}

DfxSymbol VirtualRuntime::GetSymbol(const uint64_t ip, const pid_t pid, const pid_t tid,
                                    const perf_callchain_context& context)
{
    HLOGV("try find tid %u ip 0x%" PRIx64 " in %zu symbolsFiles", tid, ip, symbolsFiles_.size());

    if (symbolManager_ == nullptr) {
        return DfxSymbol(ip, EMPTY_STRING);
    }

    const bool isKernelThread = threadManager_->IsKernelThread(pid);
    return symbolManager_->ResolveSymbol(ip, threadManager_->GetThread(pid, tid), context, isKernelThread);
}

void VirtualRuntime::ClearSymbolCache()
{
    if (threadManager_) {
        threadManager_->Clear();
    }
    if (mapManager_) {
        mapManager_->Clear();
    }
    if (symbolManager_) {
        symbolManager_->ClearCache();
    }
    if (callStackProcessor_) {
        callStackProcessor_->Clear();
    }
    if (smoProcessor_) {
        smoProcessor_->Clear();
    }
    symbolsFiles_.clear();
    kernelSymbolLoader_->SetSymbolsPaths({});
    recordProcessor_->SetSymbolsPaths({});
}

void VirtualRuntime::ReleaseRecordResources()
{
    if (symbolsFiles_.empty() && threadManager_->GetThreads().empty() &&
        mapManager_->GetKernelMaps().empty() && callStackProcessor_->GetUniStackTable()->empty()) {
        return;
    }

    for (auto& symbolsFile : symbolsFiles_) {
        symbolsFile->ReleaseDebugInfo();
    }
    ClearSymbolCache();
}

VirtualThread& VirtualRuntime::GetThread(const pid_t pid, const pid_t tid, const std::string name)
{
    return threadManager_->GetThread(pid, tid, name);
}

const std::map<pid_t, VirtualThread>& VirtualRuntime::GetThreads() const
{
    return threadManager_->GetThreads();
}

void VirtualRuntime::SymbolicRecord(PerfRecordSample& recordSample)
{
    callStackProcessor_->SymbolicRecord(recordSample);
}

void VirtualRuntime::SymbolSpeRecord(PerfRecordAuxtrace& recordAuxTrace)
{
    callStackProcessor_->SymbolSpeRecord(recordAuxTrace);
}

int32_t VirtualRuntime::RegisterSymbolsFile(std::unique_ptr<SymbolsFile> symbolsFile)
{
    return symbolsFileRegisterFunc_(std::move(symbolsFile));
}

void VirtualRuntime::UpdateFromPerfData(const std::vector<SymbolFileStruct>& symbolFileStructs)
{
    HLOG_ASSERT_MESSAGE(symbolsFiles_.size() == 0, " symbolsFiles_ size is %zu", symbolsFiles_.size());
    for (const auto& symbolFileStruct : symbolFileStructs) {
        HLOGV("symbolFileStruct.filePath_:'%s'", symbolFileStruct.filePath_.c_str());
        HLOGV("symbolFileStruct.buildId_:'%s'", symbolFileStruct.buildId_.c_str());
        HLOGV("process symbols file:'%s':'%s'", symbolFileStruct.filePath_.c_str(),
              symbolFileStruct.buildId_.c_str());

        std::unique_ptr<SymbolsFile> symbolsFile = SymbolsFile::LoadSymbolsFromSaved(symbolFileStruct);
        if (symbolsFile == nullptr) {
            continue;
        }
        if (kernelSymbolLoader_->GetSymbolsPaths().size() > 0) {
            HLOGV("try again with symbolsPaths setup");
            symbolsFile->setSymbolsFilePath(kernelSymbolLoader_->GetSymbolsPaths());
            symbolsFile->LoadSymbols();
        }
        RegisterSymbolsFile(std::move(symbolsFile));
    }
}

void VirtualRuntime::UpdateFilesFromSmoRecordData()
{
    smoProcessor_->UpdateFilesFromSmoRecordData();
}

void VirtualRuntime::UnwindFromRecord(PerfRecordSample& recordSample)
{
    callStackProcessor_->UnwindFromRecord(recordSample);
}

std::string VirtualRuntime::ReadThreadName(const pid_t tid, const bool isThread)
{
    return threadManager_->ReadThreadName(tid, isThread);
}

std::string VirtualRuntime::ReadFromSavedCmdLines(const pid_t tid)
{
    return threadManager_->ReadFromSavedCmdLines(tid);
}

bool VirtualRuntime::IsKernelThread(const pid_t pid)
{
    return threadManager_->IsKernelThread(pid);
}

void VirtualRuntime::CollectDedupSymbol(kSymbolsHits& kernelSymbolsHits,
                                        uSymbolsHits& userSymbolsHits)
{
    callStackProcessor_->CollectDedupSymbol(kernelSymbolsHits, userSymbolsHits);
}

bool VirtualRuntime::UpdateProcessSmoInfo(const VirtualThread& thread)
{
    return smoProcessor_->UpdateProcessSmoInfo(thread);
}

#ifdef HIPERF_DEBUG_TIME
void VirtualRuntime::AggregateDebugTimes()
{
    if (recordProcessor_) {
        updateSymbolsTimes_ = recordProcessor_->updateSymbolsTimes_;
        processSampleRecordTimes_ = recordProcessor_->processSampleRecordTimes_;
        processMmapRecordTimes_ = recordProcessor_->processMmapRecordTimes_;
        processMmap2RecordTimes_ = recordProcessor_->processMmap2RecordTimes_;
        processCommRecordTimes_ = recordProcessor_->processCommRecordTimes_;
        processAuxtraceRecordTimes_ = recordProcessor_->processAuxtraceRecordTimes_;
    }
    if (callStackProcessor_) {
        unwindFromRecordTimes_ = callStackProcessor_->unwindFromRecordTimes_;
        unwindCallStackTimes_ = callStackProcessor_->unwindCallStackTimes_;
        symbolicRecordTimes_ = callStackProcessor_->symbolicRecordTimes_;
    }
    if (threadManager_) {
        updateThreadTimes_ = threadManager_->updateThreadTimes_;
        threadParseMapsTimes_ = threadManager_->threadParseMapsTimes_;
        threadCreateMmapTimes_ = threadManager_->threadCreateMmapTimes_;
    }
}
#endif

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
