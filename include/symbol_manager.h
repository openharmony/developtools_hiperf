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
#ifndef HIPERF_SYMBOL_MANAGER_H
#define HIPERF_SYMBOL_MANAGER_H

#include <functional>
#include <map>
#include <memory>
#include <vector>

#if defined(is_ohos) && is_ohos
#include <linux/perf_event.h>
#else
#include "linux/perf_event_host.h"
#endif

#include "dfx_map.h"
#include "dfx_symbol.h"

#include "hashlist.h"
#include "perf_record_format.h"
#include "runtime_context.h"
#include "symbols_file.h"
#include "virtual_thread.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {

class SymbolResolver {
public:
    explicit SymbolResolver(const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles);
    virtual ~SymbolResolver() = default;
    virtual DfxSymbol Resolve(uint64_t ip, const VirtualThread& thread) = 0;
    virtual std::string GetType() const = 0;

    struct CacheStats {
        size_t hits = 0;
        size_t misses = 0;
        double hitRate = 0.0;
    };

    CacheStats GetCacheStats() const;
    size_t GetCacheSize() const;
    void ClearCache();

protected:
    bool GetFromCache(uint64_t fileVaddr, DfxSymbol& symbol, const STRING_VIEW& moduleCheck = "");
    void PutToCache(uint64_t fileVaddr, const DfxSymbol& symbol);
    SymbolsFile* FindSymbolsFile(const std::string& filePath) const;
    const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles_;
    HashList<uint64_t, DfxSymbol> cache_;
    size_t cacheHits_ = 0;
    size_t cacheMisses_ = 0;
    static constexpr size_t CACHE_SIZE = 4000;
};

class UserSymbolResolver : public SymbolResolver {
public:
    explicit UserSymbolResolver(const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles,
                                const RuntimeContext& ctx);
    std::string GetSoNameFromPc(uint64_t pc, const std::string& fileName) const;
    std::string GetOriginSoName(const uint64_t ip, const VirtualThread &thread,
        DfxSymbol &vaddrSymbol, std::shared_ptr<DfxMap> &map, SymbolsFile* symbolsFile);
    void SetSoMappingMap(const std::map<std::string, std::vector<AdltMapDataFragment>>& soMappingMap);
    DfxSymbol Resolve(uint64_t ip, const VirtualThread& thread) override;
    std::string GetType() const override { return "UserSymbol"; }

private:
    const RuntimeContext& ctx_;
    std::map<std::string, std::vector<AdltMapDataFragment>> soMappingMap_;
};

class KernelSymbolResolver : public SymbolResolver {
public:
    KernelSymbolResolver(const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles,
                         const std::vector<DfxMap>& kernelMaps);
    DfxSymbol Resolve(uint64_t ip, const VirtualThread& thread) override;
    std::string GetType() const override { return "KernelSymbol"; }
    size_t GetKernelMapsSize() const { return kernelMaps_.size(); }

private:
    const std::vector<DfxMap>& kernelMaps_;
};

class KernelThreadSymbolResolver : public SymbolResolver {
public:
    KernelThreadSymbolResolver(const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles,
                               pid_t devhostPid);
    DfxSymbol Resolve(uint64_t ip, const VirtualThread& thread) override;
    void SetRecordMode(bool needRecordCallBack) { needRecordCallBack_ = needRecordCallBack; }
    void SetDevhostPid(pid_t devhostPid) { devhostPid_ = devhostPid; }
    std::string GetType() const override { return "KernelThreadSymbol"; }

private:
    pid_t devhostPid_ = -1;
    bool needRecordCallBack_ = false;
};

class SymbolManager {
public:
    SymbolManager(const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles,
                  const std::vector<DfxMap>& kernelMaps,
                  const RuntimeContext& ctx, pid_t devhostPid = -1);
    DfxSymbol ResolveSymbol(uint64_t ip, const VirtualThread& thread,
                            perf_callchain_context context = PERF_CONTEXT_MAX, bool isKernelThread = false);
    void ClearCache();
    void SetSoMappingMap(const std::map<std::string, std::vector<AdltMapDataFragment>>& soMappingMap);
    void SetRecordMode(bool needRecordCallBack);
    void SetDevhostPid(pid_t devhostPid);
    void DumpStats() const;

private:
    const RuntimeContext& ctx_;
    std::unique_ptr<UserSymbolResolver> userResolver_;
    std::unique_ptr<KernelSymbolResolver> kernelResolver_;
    std::unique_ptr<KernelThreadSymbolResolver> kernelThreadResolver_;
    size_t userResolveCount_ = 0;
    size_t kernelResolveCount_ = 0;
    size_t kernelThreadResolveCount_ = 0;
};

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_SYMBOL_MANAGER_H