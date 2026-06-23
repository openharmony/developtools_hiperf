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
#define HILOG_TAG "MemoryMapManager"

#include "memory_map_manager.h"

#include <algorithm>
#include <cinttypes>
#include <fstream>
#include <limits>

#include "debug_logger.h"
#include "hiperf_hilog.h"
#include "utilities.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {

MemoryMapManager::MemoryMapManager(ThreadManager& threadManager, const RuntimeContext& ctx)
    : threadManager_(threadManager), ctx_(ctx)
{
}

std::shared_ptr<DfxMap> MemoryMapManager::UpdateThreadMaps(const pid_t pid, const pid_t tid,
                                                           const std::string& filename,
                                                           const uint64_t begin, const uint64_t len,
                                                           const uint64_t offset, const uint32_t prot)
{
    VirtualThread& thread = threadManager_.GetThread(pid, tid);
    std::shared_ptr<DfxMap> map = thread.CreateMapItem(filename, begin, len, offset, prot);
    if (ctx_.isHM) {
        thread.FixHMBundleMap();
    }
    return map;
}

void MemoryMapManager::UpdateKernelMap(const uint64_t begin, const uint64_t end,
                                       const uint64_t offset, const std::string& filename)
{
    HLOGV("update kernel map name:'%s' 0x%" PRIx64 " - 0x%" PRIx64 "@0x%08" PRIx64 "",
          filename.c_str(), begin, end, offset);

    HLOG_ASSERT(!filename.empty());
    auto it = find(kernelSpaceMemMaps_.begin(), kernelSpaceMemMaps_.end(), filename);
    if (it == kernelSpaceMemMaps_.end()) {
        kernelSpaceMemMaps_.emplace_back(begin, end, offset, "", filename);
    } else {
        it->begin = begin;
        it->end = end;
        it->offset = offset;
        it->name = filename;
    }
}

void MemoryMapManager::UpdateKernelThreadMap(const pid_t pid, const uint64_t begin,
                                             const uint64_t len, const uint64_t offset,
                                             const std::string& filename)
{
    HLOGV("update kernel thread map pid %u offset 0x%" PRIx64 " name:'%s'", pid, offset, filename.c_str());

    VirtualThread& thread = threadManager_.GetThread(pid, pid);
    thread.CreateMapItem(filename, begin, len, offset);
}

void MemoryMapManager::UpdateKernelSpaceMaps()
{
    // add kernel first
    auto& map = kernelSpaceMemMaps_.emplace_back(0, std::numeric_limits<uint64_t>::max(), 0, "", KERNEL_MMAP_NAME);
    if (recordCallBack_) {
        auto record = std::make_unique<PerfRecordMmap>(true, 0, 0, map.begin,
                                                       map.end - map.begin, 0, map.name);
        recordCallBack_(*record);
    }
}

void MemoryMapManager::UpdateKernelModulesSpaceMaps()
{
    // found the kernel modules
    std::vector<DfxMap> koMaps;
    std::ifstream ifs("/proc/modules", std::ifstream::in);
    if (!ifs.is_open()) {
        perror("kernel modules read failed(/proc/modules)\n");
        return;
    }
    std::string line;
    while (getline(ifs, line)) {
        uint64_t addr = 0;
        uint64_t size = 0;
        uint64_t lineSize = line.size();
        if (lineSize > 4096) { // 4096: line length
            continue;
        }
        char* module = new char[lineSize + 1];
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
                           lineSize, &size, &addr);
        constexpr int numSlices {3};
        if (ret == numSlices) {
            auto& map = koMaps.emplace_back(addr, addr + size, 0, "", std::string(module));
            HLOGV("add ko map %s", map.ToString().c_str());
        } else {
            HLOGE("unknown line %d: '%s'", ret, line.c_str());
        }
        delete[] module;
    }

    if (std::all_of(koMaps.begin(), koMaps.end(),
                    [](const DfxMap& item) { return item.begin == 0; })) {
        koMaps.clear();
        HLOGW("no addr found in /proc/modules. remove all the ko");
    }
    if (recordCallBack_) {
        for (const auto& map : koMaps) {
            auto record = std::make_unique<PerfRecordMmap>(true, 0, 0, map.begin,
                                                           map.end - map.begin, 0, map.name);
            recordCallBack_(*record);
        }
    }
    std::move(koMaps.begin(), koMaps.end(), std::back_inserter(kernelSpaceMemMaps_));
}

void MemoryMapManager::UpdateServiceSpaceMaps()
{
    VirtualThread& kthread = threadManager_.GetThread(SYSMGR_PID, SYSMGR_PID);
    kthread.ParseServiceMap(SYSMGR_FILE_NAME);
    if (recordCallBack_) {
        if (ctx_.isRoot) {
            for (const auto& map : kthread.GetMaps()) {
                PerfRecordMmap record(true, SYSMGR_PID, SYSMGR_PID,
                                      map->begin, map->end - map->begin,
                                      0, SYSMGR_FILE_NAME);
                recordCallBack_(record);
            }
        }
    }
}

void MemoryMapManager::UpdateDevhostSpaceMaps()
{
    pid_t devhostPid = ctx_.devhostPid;
    VirtualThread& kthread = threadManager_.GetThread(devhostPid, devhostPid);
    kthread.ParseDevhostMap(devhostPid);
    if (recordCallBack_) {
        for (const auto& map : kthread.GetMaps()) {
            auto record = std::make_unique<PerfRecordMmap>(false, devhostPid, devhostPid,
                                                           map->begin, map->end - map->begin,
                                                           map->offset, map->name);
            recordCallBack_(*record);
        }
    }
}

void MemoryMapManager::Clear()
{
    kernelSpaceMemMaps_.clear();
}

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
