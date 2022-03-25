/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef HIPERF_VIRTUAL_THREAD_H
#define HIPERF_VIRTUAL_THREAD_H

#include <cinttypes>
#include <functional>
#include <unordered_set>

#include "debug_logger.h"
#include "mem_map_item.h"
#include "perf_event_record.h"
#include "symbols_file.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
/*
03284000-03289000 r--p 00000000 b3:05 289        /system/bin/sh
032b7000-032b9000 rw-p 00000000 00:00 0
aff60000-aff96000 r--p 00000000 b3:05 923        /system/lib/libc++.so
affeb000-affed000 rw-p 00000000 00:00 0
b0023000-b0024000 r--p 00000000 b3:05 959        /system/lib/libdl.so
*/
const std::string MMAP_NAME_HEAP = "[heap]";
const std::string MMAP_NAME_ANON = "[anon]";

class VirtualThread {
public:
    VirtualThread(const VirtualThread &) = delete;
    VirtualThread &operator=(const VirtualThread &) = delete;

    VirtualThread(pid_t pid, const std::vector<std::unique_ptr<SymbolsFile>> &symbolsFiles)
        : pid_(pid),
          tid_(pid),
          symbolsFiles_(symbolsFiles),
          processMemMaps_(),
          memMaps_(processMemMaps_),
          parent_(*this) {}

    VirtualThread(pid_t pid, pid_t tid, VirtualThread &thread,
                  const std::vector<std::unique_ptr<SymbolsFile>> &symbolsFiles)
        : pid_(pid),
          tid_(tid),
          symbolsFiles_(symbolsFiles),
          processMemMaps_(),
          memMaps_(thread.processMemMaps_),
          parent_(thread)
    {
        HLOG_ASSERT(pid != tid);
        HLOGV("%d %d map from parent size is %zu", pid, tid, memMaps_.size());
    };

    pid_t pid_;
    pid_t tid_;
    std::string name_;

    const std::vector<MemMapItem> &GetMaps() const
    {
        return memMaps_;
    }

    void ParseMap();
    void CreateMapItem(const std::string filename, uint64_t begin, uint64_t len, uint64_t offset);
    const MemMapItem *FindMapByAddr(uint64_t addr) const;
    const MemMapItem *FindMapByAddr2(uint64_t addr) const;
    const MemMapItem *FindMapByFileInfo(const std::string name, uint64_t offset) const;
    SymbolsFile *FindSymbolsFileByMap(const MemMapItem &inMap) const;
    bool ReadRoMemory(uint64_t vaddr, uint8_t *data, size_t size) const;
#ifdef HIPERF_DEBUG
    void ReportVaddrMapMiss(uint64_t vaddr) const;
#endif
    // caller want to check if new mmap is legal
    static bool IsLegalFileName(const std::string &filename);

private:
    void SortMemMaps();
#ifdef DEBUG_TIME
    bool IsSorted() const;
#endif
    const std::vector<std::unique_ptr<SymbolsFile>> &symbolsFiles_;

    // proc/xx/map
    // use to put the parent thread's map
    // only process have memmap
    std::vector<MemMapItem> processMemMaps_;
    // thread must use ref from process
    std::vector<MemMapItem> &memMaps_;
    VirtualThread &parent_;
#ifdef HIPERF_DEBUG
    mutable std::unordered_set<uint64_t> missedRuntimeVaddr_;
#endif
#ifdef DEBUG_MISS_SYMBOL
    mutable std::vector<std::string> missedSymbolFile_;
#endif
    FRIEND_TEST(VirtualThreadTest, ReadRoMemory);
};
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_VIRTUAL_THREAD_H
