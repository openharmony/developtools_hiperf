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
#ifndef HIPERF_MEMORY_MAP_MANAGER_H
#define HIPERF_MEMORY_MAP_MANAGER_H

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "dfx_map.h"
#include "perf_event_record.h"
#include "runtime_context.h"
#include "thread_manager.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {

class MemoryMapManager {
public:
    using RecordCallBack = std::function<bool(PerfEventRecord&)>;

    explicit MemoryMapManager(ThreadManager& threadManager, const RuntimeContext& ctx);
    ~MemoryMapManager() = default;
    std::shared_ptr<DfxMap> UpdateThreadMaps(pid_t pid, pid_t tid, const std::string& filename,
                                             uint64_t begin, uint64_t len, uint64_t offset,
                                             uint32_t prot = 0);
    void UpdateKernelMap(uint64_t begin, uint64_t end, uint64_t offset, const std::string& filename);
    void UpdateKernelThreadMap(pid_t pid, uint64_t begin, uint64_t len,
                               uint64_t offset, const std::string& filename);
    void UpdateKernelSpaceMaps();
    void UpdateKernelModulesSpaceMaps();
    void UpdateServiceSpaceMaps();
    void UpdateDevhostSpaceMaps();
    const std::vector<DfxMap>& GetKernelMaps() const { return kernelSpaceMemMaps_; }
    void SetRecordMode(const RecordCallBack& recordCallBack) { recordCallBack_ = recordCallBack; }
    void Clear();

private:
    ThreadManager& threadManager_;
    const RuntimeContext& ctx_;
    std::vector<DfxMap> kernelSpaceMemMaps_;
    RecordCallBack recordCallBack_;
};

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_MEMORY_MAP_MANAGER_H
