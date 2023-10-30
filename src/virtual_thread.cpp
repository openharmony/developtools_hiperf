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
#define HILOG_TAG "RuntimeThread"

#include "virtual_thread.h"

#include <cinttypes>
#include <iostream>
#include <sstream>
#if !is_mingw
#include <sys/mman.h>
#endif

#include "symbols_file.h"
#include "utilities.h"
#include "virtual_runtime.h"
namespace OHOS {
namespace Developtools {
namespace HiPerf {
#ifdef DEBUG_TIME

bool VirtualThread::IsSorted() const
{
    for (std::size_t index = 1; index < memMaps_.size(); ++index) {
        if (memMaps_[memMapsIndexs_[index - 1]]->end > memMaps_[memMapsIndexs_[index]]->begin) {
            std::cout << "memMaps_ order error:\n"
                      << "    " << memMaps_[memMapsIndexs_[index - 1]]->begin << "-"
                      << memMaps_[memMapsIndexs_[index - 1]]->end
                      << "    " << memMaps_[memMapsIndexs_[index]]->begin << "-"
                      << memMaps_[memMapsIndexs_[index]]->end;
            return false;
        }
    }
    return true;
}
#endif

int64_t VirtualThread::FindMapIndexByAddr(uint64_t addr) const
{
    HLOGM("try found vaddr 0x%" PRIx64 "in maps %zu", addr, memMaps_.size());
    const int64_t illegal = -1;
    if (memMaps_.size() == 0) {
        return illegal;
    }
    if (memMaps_[memMapsIndexs_[0]]->begin > addr) {
        return illegal;
    }
    if (memMaps_[memMapsIndexs_[memMapsIndexs_.size() -  1]]->end <= addr) {
        return illegal;
    }
    constexpr int divisorNum {2};
    std::size_t left {0};
    std::size_t right {memMapsIndexs_.size()};
    std::size_t mid = (right - left) / divisorNum + left;
    while (left < right) {
        if (addr < memMaps_[memMapsIndexs_[mid]]->end) {
            right = mid;
            mid = (right - left) / divisorNum + left;
            continue;
        }
        if (addr >= memMaps_[memMapsIndexs_[mid]]->end) {
            left = mid + 1;
            mid = (right - left) / divisorNum + left;
            continue;
        }
    }
    if (addr >= memMaps_[memMapsIndexs_[left]]->begin && addr < memMaps_[memMapsIndexs_[left]]->end) {
        return static_cast<int64_t>(memMapsIndexs_[left]);
    }
    return illegal;
}

std::shared_ptr<DfxMap> VirtualThread::FindMapByAddr(uint64_t addr) const
{
    HLOGM("try found vaddr 0x%" PRIx64 "in maps %zu", addr, memMaps_.size());
    if (memMaps_.size() == 0) {
        return nullptr;
    }
    if (memMaps_[memMapsIndexs_[0]]->begin > addr) {
        return nullptr;
    }
    if (memMaps_[memMapsIndexs_[memMapsIndexs_.size() - 1]]->end <= addr) {
        return nullptr;
    }
    constexpr int divisorNum {2};
    std::size_t left {0};
    std::size_t right {memMapsIndexs_.size()};
    std::size_t mid = (right - left) / divisorNum + left;
    while (left < right) {
        if (addr < memMaps_[memMapsIndexs_[mid]]->end) {
            right = mid;
            mid = (right - left) / divisorNum + left;
            continue;
        }
        if (addr >= memMaps_[memMapsIndexs_[mid]]->end) {
            left = mid + 1;
            mid = (right - left) / divisorNum + left;
            continue;
        }
    }
    if (addr >= memMaps_[memMapsIndexs_[left]]->begin && addr < memMaps_[memMapsIndexs_[left]]->end) {
        return memMaps_[memMapsIndexs_[left]];
    }
    return nullptr;
}

std::shared_ptr<DfxMap> VirtualThread::FindMapByFileInfo(const std::string name, uint64_t offset) const
{
    for (auto &map : memMaps_) {
        if (name != map->name) {
            continue;
        }
        // check begin and length
        if (offset >= map->offset && (offset - map->offset) < (map->end - map->begin)) {
            HLOGMMM("found fileoffset 0x%" PRIx64 " in map (0x%" PRIx64 " - 0x%" PRIx64
                    " pageoffset 0x%" PRIx64 ")  from %s",
                    offset, map->begin, map->end, map->offset, map->name.c_str());
            return map;
        }
    }
    HLOGM("NOT found offset 0x%" PRIx64 " in maps %zu ", offset, memMaps_.size());
    return nullptr;
}

SymbolsFile *VirtualThread::FindSymbolsFileByMap(std::shared_ptr<DfxMap> inMap) const
{
    for (auto &symbolsFile : symbolsFiles_) {
        if (symbolsFile->filePath_ == inMap->name) {
            HLOGM("found symbol for map '%s'", inMap->name.c_str());
            if (symbolsFile->LoadDebugInfo()) {
                HLOGM("found symbol for map '%s'", inMap->name.c_str());
                return symbolsFile.get();
            }
            break;
        }
    }

#ifdef DEBUG_MISS_SYMBOL
    if (find(missedSymbolFile_.begin(), missedSymbolFile_.end(), inMap.name) ==
        missedSymbolFile_.end()) {
        missedSymbolFile_.emplace_back(inMap.name);
        HLOGW("NOT found symbol for map '%s'", inMap.name.c_str());
        for (const auto &file : symbolsFiles_) {
            HLOGW(" we have '%s'", file->filePath_.c_str());
        }
    }
#endif
    return nullptr;
}
void VirtualThread::ReportVaddrMapMiss(uint64_t vaddr) const
{
#ifdef HIPERF_DEBUG
    if (DebugLogger::GetInstance()->GetLogLevel() <= LEVEL_VERBOSE) {
        if (missedRuntimeVaddr_.find(vaddr) == missedRuntimeVaddr_.end()) {
            missedRuntimeVaddr_.insert(vaddr);
            HLOGV("vaddr %" PRIx64 " not found in any map", vaddr);
            for (auto &map : memMaps_) {
                HLOGV("map %s ", map->ToString().c_str());
            }
        }
    }
#endif
}

bool VirtualThread::ReadRoMemory(uint64_t vaddr, uint8_t *data, size_t size) const
{
    uint64_t pageIndex = vaddr >> 12;
    uint64_t memMapIndex = -1;
    const int64_t exceptRet = -1;
    const uint64_t illegal = -1;
    auto pageFile = vaddr4kPageCache_.find(pageIndex);
    if (pageFile != vaddr4kPageCache_.end()) {
        memMapIndex = pageFile->second;
    } else {
        int64_t retIndex = FindMapIndexByAddr(vaddr);
        memMapIndex = static_cast<uint64_t>(retIndex);
        // add to 4k page cache table
        if (retIndex != exceptRet && memMapIndex < memMaps_.size()) {
            const_cast<VirtualThread *>(this)->vaddr4kPageCache_[pageIndex] = memMapIndex;
        }
    }
    if (memMapIndex != illegal) {
        auto map = memMaps_[memMapIndex];
        if (map->elf == nullptr) {
            SymbolsFile* symFile = FindSymbolsFileByMap(map);
            if (symFile == nullptr) {
                return false;
            }
            map->elf = symFile->GetElfFile();
        }
        if (map->elf != nullptr) {
            uint64_t foff = vaddr - map->begin + map->offset;
            if (map->elf->Read(foff, data, size)) {
                return true;
            } else {
                return false;
            }
        } else {
            HLOGW("find addr %" PRIx64 "in map but not loaded symbole %s", vaddr, map->name.c_str());
        }
    } else {
#ifdef HIPERF_DEBUG
        ReportVaddrMapMiss(vaddr);
#endif
    }
    return false;
}

#if is_mingw
void VirtualThread::ParseMap()
{
    // only linux support read maps in runtime
    return;
}
#else
void VirtualThread::ParseMap()
{
    if (!(OHOS::HiviewDFX::DfxMaps::Create(pid_, memMaps_, memMapsIndexs_))) {
        HLOGE("VirtualThread Failed to Parse Map.");
    }
    SortMemMaps();
}
#endif

constexpr const int MMAP_LINE_TOKEN_INDEX_NAME = 5;
constexpr const int MMAP_LINE_MAX_TOKEN = 6;
void VirtualThread::ParseServiceMap(const std::string &filename)
{
    std::string mapPath = StringPrintf("/proc/%d/maps", pid_);
    std::string mapContent = ReadFileToString(mapPath);
    uint64_t begin = 0;
    uint64_t end = 0;
    if (mapContent.size() == 0) {
        HLOGW("Parse %s failed, content empty", mapPath.c_str());
        return;
    }
    std::istringstream s(mapContent);
    std::string line;
    while (std::getline(s, line)) {
        std::vector<std::string> mapTokens = StringSplit(line, " ");
        if (mapTokens.size() == MMAP_LINE_MAX_TOKEN &&
            mapTokens[MMAP_LINE_TOKEN_INDEX_NAME] == name_) {
            HLOGM("map line: %s", line.c_str());
            std::vector<std::string> addrRanges = StringSplit(mapTokens[0], "-");
            begin = std::stoull(addrRanges[0], nullptr, NUMBER_FORMAT_HEX_BASE);
            end = std::stoull(addrRanges[1], nullptr, NUMBER_FORMAT_HEX_BASE);
            break;
        }
    }
    CreateMapItem(filename, begin, end - begin, 0);
}

void VirtualThread::SortMemMaps()
{
    for (int currPos = 1; currPos < static_cast<int>(memMaps_.size()); ++currPos) {
        int targetPos = currPos - 1;
        while (targetPos >= 0 and memMaps_[memMapsIndexs_[currPos]]->end < memMaps_[memMapsIndexs_[targetPos]]->end) {
            --targetPos;
        }
        if (targetPos < currPos - 1) {
            auto target = memMapsIndexs_[currPos];
            for (int k = currPos - 1; k > targetPos; --k) {
                memMapsIndexs_[k + 1] = memMapsIndexs_[k];
            }
            memMapsIndexs_[targetPos + 1] = target;
        }
    }
}

void VirtualThread::CreateMapItem(const std::string filename, uint64_t begin, uint64_t len,
                                  uint64_t offset)
{
    if (!OHOS::HiviewDFX::DfxMaps::IsLegalMapItem(filename)) {
        return; // skip some memmap
    }
    std::shared_ptr<DfxMap> map = memMaps_.emplace_back(std::make_shared<DfxMap>(begin, begin + len, offset,
        "", filename));
    memMapsIndexs_.emplace_back(memMaps_.size() - 1);
    HLOGD(" %u:%u create a new map(total %zu) at '%s' (0x%" PRIx64 "-0x%" PRIx64 ")@0x%" PRIx64 " ",
          pid_, tid_, memMaps_.size(), map->name.c_str(), map->begin, map->end, map->offset);
    SortMemMaps();
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
