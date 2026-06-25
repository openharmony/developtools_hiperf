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
#ifndef HIPERF_CALLSTACK_PROCESSOR_H
#define HIPERF_CALLSTACK_PROCESSOR_H

#include <functional>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(is_ohos) && is_ohos
#include "callstack.h"
#endif

#include "perf_event_record.h"
#include "runtime_context.h"
#include "symbol_manager.h"
#include "thread_manager.h"
#include "unique_stack_table.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {

using kSymbolsHits = std::unordered_set<uint64_t>;
using uSymbolsHits = std::unordered_map<pid_t, std::unordered_set<uint64_t>>;

class CallStackProcessor {
public:
    using RecordCallBack = std::function<bool(PerfEventRecord&)>;
    using CollectSymbolCallBack = std::function<void(PerfRecordSample*)>;
    CallStackProcessor(SymbolManager& symbolManager, ThreadManager& threadManager, const RuntimeContext& ctx);
    ~CallStackProcessor() = default;

    void UnwindFromRecord(PerfRecordSample& record);
    void SymbolicRecord(PerfRecordSample& record);
    void SymbolSpeRecord(PerfRecordAuxtrace& record);
    void ProcessAuxtraceRecord(PerfRecordAuxtrace& record);
    void DedupFromRecord(PerfRecordSample* record);
    bool RecoverCallStack(PerfRecordSample& record);
    void NeedDropKernelCallChain(PerfRecordSample& sample);
    void AdjustCallChain(PerfRecordSample& sample);
    void ProcessKernelCallChain(PerfRecordSample& sample);

    void SetDisableUnwind(bool disable) { disableUnwind_ = disable; }
    void SetDedupStack(bool enable) { dedupStack_ = enable; }
    void SetCallStackExpend(size_t mergeLevel) { callstackMergeLevel_ = mergeLevel; }
    void SetNeedKernelCallChain(bool need) { needKernelCallChain_ = need; }
    void SetRecordMode(const RecordCallBack& recordCallBack) { recordCallBack_ = recordCallBack; }
    void SetCollectSymbolCallBack(const CollectSymbolCallBack& callback) { collectSymbolCallBack_ = callback; }
    void CollectDedupSymbol(kSymbolsHits& kernelSymbolsHits, uSymbolsHits& userSymbolsHits);
    const ProcessStackMap* GetUniStackTable() const { return &processStackMap_; }
    void ImportUniqueStackNodes(const std::vector<UniStackTableInfo>& infos);
    void Clear();

#ifdef HIPERF_DEBUG_TIME
    std::chrono::microseconds unwindFromRecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds unwindCallStackTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds symbolicRecordTimes_ = std::chrono::microseconds::zero();
#endif

private:
    void SymbolicCallFrame(PerfRecordSample& record, uint64_t ip,
                          pid_t serverPid, perf_callchain_context context);
    void MakeCallFrame(uint64_t ip, DfxSymbol& symbol, DfxFrame& frame);
#if defined(is_ohos) && is_ohos
    CallStack callstack_;
#endif
    ProcessStackMap processStackMap_;
    SymbolManager& symbolManager_;
    ThreadManager& threadManager_;
    [[maybe_unused]] const RuntimeContext& ctx_;
    bool disableUnwind_ = true;
    bool dedupStack_ = false;
    bool needKernelCallChain_ = false;
    size_t callstackMergeLevel_ = 1;
    RecordCallBack recordCallBack_;
    CollectSymbolCallBack collectSymbolCallBack_;
};

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_CALLSTACK_PROCESSOR_H
