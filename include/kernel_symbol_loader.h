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
#ifndef HIPERF_KERNEL_SYMBOL_LOADER_H
#define HIPERF_KERNEL_SYMBOL_LOADER_H

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "dfx_map.h"
#include "memory_map_manager.h"
#include "perf_event_record.h"
#include "runtime_context.h"
#include "symbols_file.h"
#include "thread_manager.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {

class KernelSymbolLoader {
public:
    using RecordCallBack = std::function<bool(PerfEventRecord&)>;
    using UpdateSymbolsCallBack = std::function<void(std::shared_ptr<DfxMap>, pid_t)>;
    using SymbolsFileRegisterFunc = std::function<int32_t(std::unique_ptr<SymbolsFile>)>;

    KernelSymbolLoader(const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles,
                       MemoryMapManager& mapManager, ThreadManager& threadManager,
                       const RuntimeContext& ctx, const SymbolsFileRegisterFunc& registerFunc);
    ~KernelSymbolLoader() = default;
    void UpdateKernelSymbols();
    void UpdateKernelModulesSymbols();
    void UpdateServiceSymbols();
    void UpdateDevhostSymbols();
    void LoadVdso();
    void SetSymbolsPaths(const std::vector<std::string>& paths) { symbolsPaths_ = paths; }
    const std::vector<std::string>& GetSymbolsPaths() const { return symbolsPaths_; }
    void SetRecordMode(const RecordCallBack& recordCallBack) { recordCallBack_ = recordCallBack; }
    void SetUpdateSymbolsCallBack(const UpdateSymbolsCallBack& callback) { updateSymbolsCallBack_ = callback; }

private:
    [[maybe_unused]] const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles_;
    MemoryMapManager& mapManager_;
    ThreadManager& threadManager_;
    [[maybe_unused]] const RuntimeContext& ctx_;
    const SymbolsFileRegisterFunc& registerFunc_;
    std::vector<std::string> symbolsPaths_;
    RecordCallBack recordCallBack_;
    UpdateSymbolsCallBack updateSymbolsCallBack_;
};

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_KERNEL_SYMBOL_LOADER_H
