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
#define HILOG_TAG "SymbolResolver"

#include "symbol_manager.h"

#include "kernel_map_lookup.h"

#include "debug_logger.h"
#include "hiperf_hilog.h"
#include "mingw_adapter.h"
#include "utilities.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {

SymbolResolver::SymbolResolver(
    const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles)
    : symbolsFiles_(symbolsFiles), cache_(CACHE_SIZE)
{
}

bool SymbolResolver::GetFromCache(uint64_t fileVaddr, DfxSymbol& symbol,
                                  const STRING_VIEW& moduleCheck)
{
    auto it = cache_.find(fileVaddr);
    if (!(it == cache_.end())) {
        if (!moduleCheck.empty() && it->module_ != moduleCheck) {
            ++cacheMisses_;
            return false;
        }
        symbol = *it;
        ++symbol.hit_;
        ++cacheHits_;
        return true;
    }
    ++cacheMisses_;
    return false;
}

void SymbolResolver::PutToCache(uint64_t fileVaddr, const DfxSymbol& symbol)
{
    cache_.push_front(fileVaddr, symbol);
}

SymbolsFile* SymbolResolver::FindSymbolsFile(const std::string& filePath) const
{
    for (auto& symbolsFile : symbolsFiles_) {
        if (symbolsFile->filePath_ == filePath) {
            return symbolsFile.get();
        }
    }
    return nullptr;
}

SymbolResolver::CacheStats SymbolResolver::GetCacheStats() const
{
    double hitRate = 0.0;
    if (cacheHits_ + cacheMisses_ > 0) {
        hitRate = static_cast<double>(cacheHits_) / (cacheHits_ + cacheMisses_);
    }
    return {cacheHits_, cacheMisses_, hitRate};
}

size_t SymbolResolver::GetCacheSize() const
{
    return cache_.size();
}

void SymbolResolver::ClearCache()
{
    cache_.clear();
}

UserSymbolResolver::UserSymbolResolver(
    const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles, const RuntimeContext& ctx)
    : SymbolResolver(symbolsFiles), ctx_(ctx)
{
}

std::string UserSymbolResolver::GetSoNameFromPc(uint64_t pc, const std::string& fileName) const
{
    if (soMappingMap_.empty()) {
        return "";
    }
    auto soMapPairPtr = soMappingMap_.find(fileName);
    if (soMapPairPtr == soMappingMap_.end()) {
        return "";
    }
    auto soPtr = std::lower_bound(soMapPairPtr->second.begin(), soMapPairPtr->second.end(),
        pc, [](const AdltMapDataFragment& a, uint64_t pc) {
        return a.pcEnd <= pc;
    });
    if (soPtr == soMapPairPtr->second.end() || pc >= soPtr->pcEnd || pc < soPtr->pcBegin) {
        return "";
    }
    return soPtr->originalSoName;
}

std::string UserSymbolResolver::GetOriginSoName(const uint64_t ip, const VirtualThread &thread,
    DfxSymbol &vaddrSymbol, std::shared_ptr<DfxMap> &map, SymbolsFile* symbolsFile)
{
    vaddrSymbol.symbolFileIndex_ = symbolsFile->id_;
    vaddrSymbol.module_ = map->name;
    vaddrSymbol.fileVaddr_ = symbolsFile->GetVaddrInSymbols(ip, map->begin, map->offset);

    std::string originSoName = "";
    if (map->name.find("libadlt") != std::string::npos && EndsWith(map->name, ".so")) {
        vaddrSymbol.fileVaddr_ = symbolsFile->GetVaddrByLoadBase(ip, map->GetAdltLoadBase());
        // get originSoName from smo record in perf.data,
        // no root && no --append-smo-data option, the return value will be ""
        originSoName = GetSoNameFromPc(vaddrSymbol.fileVaddr_, map->name);
        auto elf = GetElfByMap(map);
        // when there is no smo record in perf.data, only in root mode,try to get originSoName from elf
        if (ctx_.isRoot && originSoName.empty() && elf != nullptr && elf->IsAdlt()) {
            originSoName = elf->GetAdltOriginSoNameByRelPc(vaddrSymbol.fileVaddr_);
        }
        HLOGV("Get new fileVaddr:0x%" PRIx64 " loadbase: 0x%" PRIx64 " ip:0x%" PRIx64 " originSo:'%s'",
            vaddrSymbol.fileVaddr_, map->GetAdltLoadBase(), ip, originSoName.c_str());
    }
    vaddrSymbol.map = map;
    vaddrSymbol.originSoName_ = originSoName;
    return originSoName;
}

DfxSymbol UserSymbolResolver::Resolve(uint64_t ip, const VirtualThread& thread)
{
    DfxSymbol vaddrSymbol(ip, thread.name_);

    int64_t mapIndex = thread.FindMapIndexByAddr(ip);
    if (mapIndex < 0) {
        HLOGV("User symbol: addr 0x%" PRIx64 " not found in any map", ip);
        return vaddrSymbol;
    }

    auto map = thread.GetMaps()[mapIndex];
    SymbolsFile* symbolsFile = thread.FindSymbolsFileByMap(map);
    if (symbolsFile == nullptr) {
        HLOGW("addr 0x%" PRIx64 " in map but NOT found the symbol file %s", ip, map->name.c_str());
        return vaddrSymbol;
    }
    std::string originSoName = GetOriginSoName(ip, thread, vaddrSymbol, map, symbolsFile);
    if (GetFromCache(vaddrSymbol.fileVaddr_, vaddrSymbol, vaddrSymbol.module_)) {
        HLOGV("hit user cache 0x%" PRIx64 " %d %s", vaddrSymbol.fileVaddr_,
            vaddrSymbol.hit_, vaddrSymbol.ToDebugString().c_str());
        return vaddrSymbol;
    }
    HLOGM("cache miss u %zu", cache_.size());
    HLOGV("found symbol vaddr 0x%" PRIx64 " for runtime vaddr 0x%" PRIx64 " at '%s'",
          vaddrSymbol.fileVaddr_, ip, map->name.c_str());
    if (!symbolsFile->SymbolsLoaded()) {
        symbolsFile->LoadDebugInfo(map);
        symbolsFile->LoadSymbols(map);
    }
    DfxSymbol foundSymbol;
    bool isAbcOrJsEngine = symbolsFile->IsAbc() || IsJsvmV8File(map->name) || IsArkwebV8File(map->name);
    if (!isAbcOrJsEngine) {
        foundSymbol = symbolsFile->GetSymbolWithVaddr(vaddrSymbol.fileVaddr_);
    } else {
        HLOGD("symbolsFile:%s is ABC or JS engine :%d", symbolsFile->filePath_.c_str(), isAbcOrJsEngine);
        foundSymbol = symbolsFile->GetSymbolWithPcAndMap(ip, map);
    }

    if (foundSymbol.IsValid()) {
        foundSymbol.map = map;
        foundSymbol.originSoName_ = originSoName;
        PutToCache(vaddrSymbol.fileVaddr_, foundSymbol);
        return foundSymbol;
    }
    HLOGW("User symbol: addr 0x%" PRIx64 " vaddr  0x%" PRIx64 " NOT found in symbol file %s", ip,
          vaddrSymbol.fileVaddr_, map->name.c_str());
    if (vaddrSymbol.fileVaddr_ != 0) {
        PutToCache(vaddrSymbol.fileVaddr_, vaddrSymbol);
    }
    if (isAbcOrJsEngine) {
        symbolsFile->symbolsMap_.emplace(ip, vaddrSymbol);
    }
    return vaddrSymbol;
}

void UserSymbolResolver::SetSoMappingMap(const std::map<std::string, std::vector<AdltMapDataFragment>>& soMappingMap)
{
    soMappingMap_ = soMappingMap;
}

KernelSymbolResolver::KernelSymbolResolver(
    const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles,
    const std::vector<DfxMap>& kernelMaps)
    : SymbolResolver(symbolsFiles), kernelMaps_(kernelMaps)
{
}

DfxSymbol KernelSymbolResolver::Resolve(uint64_t ip, const VirtualThread& thread)
{
    DfxSymbol vaddrSymbol(ip, thread.name_);
    size_t mapIdx = OHOS::Developtools::StackCommon::FindFirstMapContainingIp(ip, kernelMaps_);
    if (mapIdx == OHOS::Developtools::StackCommon::K_INVALID_KERNEL_MAP_INDEX) {
        HLOGM("Kernel symbol: addr 0x%" PRIx64 " not found in kernel maps", ip);
        return vaddrSymbol;
    }
    const auto &map = kernelMaps_[mapIdx];
    HLOGM("found addr 0x%" PRIx64 " in kernel map 0x%" PRIx64 " - 0x%" PRIx64 " from %s",
          ip, map.begin, map.end, map.name.c_str());
    vaddrSymbol.module_ = map.name;
    SymbolsFile* symbolsFile = FindSymbolsFile(map.name);
    if (!symbolsFile) {
        HLOGW("addr 0x%" PRIx64 " in map but NOT found the symbol file %s", ip,
                map.name.c_str());
        return vaddrSymbol;
    }

    vaddrSymbol.symbolFileIndex_ = symbolsFile->id_;
    vaddrSymbol.fileVaddr_ = symbolsFile->GetVaddrInSymbols(ip, map.begin, map.offset);

    if (GetFromCache(vaddrSymbol.fileVaddr_, vaddrSymbol)) {
        HLOGV("hit kernel cache 0x%" PRIx64 " %d", vaddrSymbol.fileVaddr_, vaddrSymbol.hit_);
        return vaddrSymbol;
    }
    HLOGM("cache miss k %zu", cache_.size());
    HLOGV("found symbol vaddr 0x%" PRIx64 " for runtime vaddr 0x%" PRIx64
          " at '%s'", vaddrSymbol.fileVaddr_, ip, map.name.c_str());
    if (!symbolsFile->SymbolsLoaded()) {
        symbolsFile->LoadSymbols();
    }

    DfxSymbol foundSymbol = symbolsFile->GetSymbolWithVaddr(vaddrSymbol.fileVaddr_);
    foundSymbol.taskVaddr_ = ip;
    if (foundSymbol.IsValid()) {
        PutToCache(vaddrSymbol.fileVaddr_, foundSymbol);
        return foundSymbol;
    }

    HLOGW("Kernel symbol: addr 0x%" PRIx64 " vaddr 0x%" PRIx64 " NOT found in symbol file %s",
            ip, vaddrSymbol.fileVaddr_, map.name.c_str());
    if (vaddrSymbol.fileVaddr_ != 0) {
        PutToCache(vaddrSymbol.fileVaddr_, vaddrSymbol);
    }
    return vaddrSymbol;
}

KernelThreadSymbolResolver::KernelThreadSymbolResolver(
    const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles,
    pid_t devhostPid)
    : SymbolResolver(symbolsFiles), devhostPid_(devhostPid)
{
}

DfxSymbol KernelThreadSymbolResolver::Resolve(uint64_t ip, const VirtualThread& thread)
{
    DfxSymbol vaddrSymbol(ip, thread.name_);
    int64_t mapIndex = thread.FindMapIndexByAddr(ip);
    if (mapIndex < 0) {
        HLOGV("Kernel thread symbol: addr 0x%" PRIx64 " not found in any map", ip);
        return vaddrSymbol;
    }

    auto map = thread.GetMaps()[mapIndex];
    CHECK_TRUE(map != nullptr, vaddrSymbol, 0, "");

    HLOGM("found addr 0x%" PRIx64 " in kthread map 0x%" PRIx64 " - 0x%" PRIx64 " from %s",
          ip, map->begin, map->end, map->name.c_str());

    SymbolsFile* symbolsFile = FindSymbolsFile(map->name);
    if (!symbolsFile) {
        HLOGW("addr 0x%" PRIx64 " in map but NOT found the symbol file %s", ip, map->name.c_str());
        return vaddrSymbol;
    }

    vaddrSymbol.symbolFileIndex_ = symbolsFile->id_;
    vaddrSymbol.module_ = map->name;
    vaddrSymbol.fileVaddr_ = symbolsFile->GetVaddrInSymbols(ip, map->begin, map->offset);

    if (GetFromCache(vaddrSymbol.fileVaddr_, vaddrSymbol)) {
        HLOGV("hit kernel thread cache 0x%" PRIx64 " %d", vaddrSymbol.fileVaddr_, vaddrSymbol.hit_);
        return vaddrSymbol;
    }
    HLOGM("cache miss kt %zu", cache_.size());
    HLOGV("found symbol vaddr 0x%" PRIx64 " for runtime vaddr 0x%" PRIx64 " at '%s'",
          vaddrSymbol.fileVaddr_, ip, map->name.c_str());
    if (!symbolsFile->SymbolsLoaded()) {
        symbolsFile->LoadDebugInfo();
        symbolsFile->LoadSymbols(map);
    }

    DfxSymbol foundSymbol;
    if (thread.pid_ == devhostPid_ && needRecordCallBack_) {
        foundSymbol = symbolsFile->GetSymbolWithPcAndMap(vaddrSymbol.fileVaddr_, map);
    } else {
        foundSymbol = symbolsFile->GetSymbolWithVaddr(vaddrSymbol.fileVaddr_);
    }

    foundSymbol.taskVaddr_ = ip;

    if (!foundSymbol.IsValid()) {
        HLOGW("Kernel thread: addr 0x%" PRIx64 " vaddr 0x%" PRIx64 " NOT found in symbol file %s",
              ip, vaddrSymbol.fileVaddr_, map->name.c_str());
        PutToCache(vaddrSymbol.fileVaddr_, vaddrSymbol);
        return vaddrSymbol;
    }

    PutToCache(vaddrSymbol.fileVaddr_, foundSymbol);
    return foundSymbol;
}

SymbolManager::SymbolManager(
    const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles, const std::vector<DfxMap>& kernelMaps,
    const RuntimeContext& ctx, pid_t devhostPid)
    : ctx_(ctx)
{
    userResolver_ = std::make_unique<UserSymbolResolver>(symbolsFiles, ctx_);
    kernelResolver_ = std::make_unique<KernelSymbolResolver>(symbolsFiles, kernelMaps);
    kernelThreadResolver_ = std::make_unique<KernelThreadSymbolResolver>(
        symbolsFiles, devhostPid);
}

DfxSymbol SymbolManager::ResolveSymbol(
    uint64_t ip, const VirtualThread& thread,
    perf_callchain_context context, bool isKernelThread)
{
    if (isKernelThread) {
        HLOGM("try found addr in kernel thread %u with %zu maps", thread.pid_,
              thread.GetMaps().size());
        DfxSymbol symbol = kernelThreadResolver_->Resolve(ip, thread);
        ++kernelThreadResolveCount_;
        HLOGM("add addr to kernel thread cache 0x%" PRIx64 " cache size %zu", ip,
              kernelThreadResolver_->GetCacheSize());
        if (symbol.IsValid()) {
            return symbol;
        }
    }

    if (context == PERF_CONTEXT_KERNEL) {
        HLOGM("try found addr in kernelspace %zu maps", kernelResolver_->GetKernelMapsSize());
        DfxSymbol kernelSymbol = kernelResolver_->Resolve(ip, thread);
        ++kernelResolveCount_;
        HLOGM("add addr to kernel cache 0x%" PRIx64 " cache size %zu", ip,
              kernelResolver_->GetCacheSize());
        return kernelSymbol;
    } else if (context == PERF_CONTEXT_USER) {
        ++userResolveCount_;
        DfxSymbol userSymbol = userResolver_->Resolve(ip, thread);
        HLOGV("cache ip 0x%" PRIx64 " to %s", ip, userSymbol.ToDebugString().c_str());
        return userSymbol;
    } else {
        ++userResolveCount_;
        DfxSymbol symbol = userResolver_->Resolve(ip, thread);
        if (symbol.IsValid()) {
            return symbol;
        }
        HLOGM("try found addr in kernelspace %zu maps", kernelResolver_->GetKernelMapsSize());
        DfxSymbol kernelSymbol = kernelResolver_->Resolve(ip, thread);
        ++kernelResolveCount_;
        HLOGM("add addr to kernel cache 0x%" PRIx64 " cache size %zu", ip,
              kernelResolver_->GetCacheSize());
        return kernelSymbol;
    }
}

void SymbolManager::SetSoMappingMap(const std::map<std::string, std::vector<AdltMapDataFragment>>& soMappingMap)
{
    if (userResolver_) {
        userResolver_->SetSoMappingMap(soMappingMap);
    }
}

void SymbolManager::SetDevhostPid(pid_t devhostPid)
{
    if (kernelThreadResolver_) {
        kernelThreadResolver_->SetDevhostPid(devhostPid);
    }
}

void SymbolManager::SetRecordMode(bool needRecordCallBack)
{
    if (kernelThreadResolver_) {
        kernelThreadResolver_->SetRecordMode(needRecordCallBack);
    }
}

void SymbolManager::DumpStats() const
{
    HLOGD("[SymbolResolver Stats] resolves: user=%zu kernel=%zu kthread=%zu",
          userResolveCount_, kernelResolveCount_, kernelThreadResolveCount_);
    constexpr double PERCENT_MULTIPLIER = 100.0;
    if (userResolver_) {
        auto s = userResolver_->GetCacheStats();
        HLOGD("  user   cache: hits=%zu misses=%zu hitRate=%.2f%%",
              s.hits, s.misses, s.hitRate * PERCENT_MULTIPLIER);
    }
    if (kernelResolver_) {
        auto s = kernelResolver_->GetCacheStats();
        HLOGD("  kernel cache: hits=%zu misses=%zu hitRate=%.2f%%",
              s.hits, s.misses, s.hitRate * PERCENT_MULTIPLIER);
    }
    if (kernelThreadResolver_) {
        auto s = kernelThreadResolver_->GetCacheStats();
        HLOGD("  kernelThread cache: hits=%zu misses=%zu hitRate=%.2f%%",
              s.hits, s.misses, s.hitRate * PERCENT_MULTIPLIER);
    }
}

void SymbolManager::ClearCache()
{
    DumpStats();
    if (userResolver_) {
        userResolver_->ClearCache();
    }
    if (kernelResolver_) {
        kernelResolver_->ClearCache();
    }
    if (kernelThreadResolver_) {
        kernelThreadResolver_->ClearCache();
    }
}

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
