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
        if (memMaps_[index - 1].end_ > memMaps_[index].begin_) {
            std::cout << "memMaps_ order error:\n"
                      << "    " << memMaps_[index - 1].begin_ << "-" << memMaps_[index - 1].end_
                      << "    " << memMaps_[index].begin_ << "-" << memMaps_[index].end_;
            return false;
        }
    }
    return true;
}
#endif

const MemMapItem *VirtualThread::FindMapByAddr2(uint64_t addr) const
{
    HLOGM("try found vaddr 0x%" PRIx64 " in maps %zu ", addr, memMaps_.size());
    if (memMaps_.size() == 0) {
        return nullptr;
    }
    auto foundIt =
        std::upper_bound(memMaps_.begin(), memMaps_.end(), addr, MemMapItem::ValueLessThan);
    if (foundIt == memMaps_.begin()) {
        // have map 2 3 4 5
        // find 1 , will return 2 (index 0, begin elem)
        // this same as not found any thins
    } else {
        // include memMaps_.end()
        foundIt = std::prev(foundIt);
        if (foundIt->Contain(addr)) {
            HLOGM("found '%s' for vaddr 0x%016" PRIx64 "", foundIt->ToString().c_str(), addr);
            return &(*foundIt);
        }
    }
    return nullptr;
}

const MemMapItem *VirtualThread::FindMapByAddr(uint64_t addr) const
{
    HLOGM("try found vaddr 0x%" PRIx64 " in maps %zu ", addr, memMaps_.size());
    if (memMaps_.size() == 0) {
        return nullptr;
    }
    if (memMaps_.front().begin_ > addr) {
        return nullptr;
    }
    if (memMaps_.back().end_ <= addr) {
        return nullptr;
    }
    constexpr int two {2};
    std::size_t left {0};
    std::size_t right {memMaps_.size()};
    std::size_t mid = (right - left) / two + left;
    while (left < right) {
        if (addr < memMaps_[mid].end_) {
            right = mid;
            mid = (right - left) / two + left;
            continue;
        }
        if (addr >= memMaps_[mid].end_) {
            left = mid + 1;
            mid = (right - left) / two + left;
            continue;
        }
    }
    if (addr >= memMaps_[left].begin_ and addr < memMaps_[left].end_) {
        return &memMaps_[left];
    }
    return nullptr;
}

const MemMapItem *VirtualThread::FindMapByFileInfo(const std::string name, uint64_t offset) const
{
    for (auto &map : memMaps_) {
        if (name != map.name_) {
            continue;
        }
        // check begin and length
        if (offset >= map.pageoffset_ && (offset - map.pageoffset_) < (map.end_ - map.begin_)) {
            HLOGMMM("found fileoffset 0x%" PRIx64 " in map (0x%" PRIx64 " - 0x%" PRIx64
                    " pageoffset 0x%" PRIx64 ")  from %s",
                    offset, map.begin_, map.end_, map.pageoffset_, map.name_.c_str());
            return &map;
        }
    }
    HLOGM("NOT found offset 0x%" PRIx64 " in maps %zu ", offset, memMaps_.size());
    return nullptr;
}

SymbolsFile *VirtualThread::FindSymbolsFileByMap(const MemMapItem &inMap) const
{
    for (auto &symbolsFile : symbolsFiles_) {
        if (symbolsFile->filePath_ == inMap.name_) {
            HLOGM("found symbol for map '%s'", inMap.name_.c_str());
            // LoadDebugInfo() could be failed when dump or report
            if (symbolsFile->LoadDebugInfo() || !SymbolsFile::onRecording_) {
                HLOGM("found symbol for map '%s'", inMap.name_.c_str());
                return symbolsFile.get();
            }
            break;
        }
    }
#ifdef DEBUG_MISS_SYMBOL
    if (find(missedSymbolFile_.begin(), missedSymbolFile_.end(), inMap.name_) ==
        missedSymbolFile_.end()) {
        missedSymbolFile_.emplace_back(inMap.name_);
        HLOGW("NOT found symbol for map '%s'", inMap.name_.c_str());
        for (auto &file : symbolsFiles_) {
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
                HLOGV("map %s ", map.ToString().c_str());
            }
        }
    }
#endif
}

bool VirtualThread::ReadRoMemory(uint64_t vaddr, uint8_t *data, size_t size) const
{
    const MemMapItem *map = FindMapByAddr(vaddr);
    if (map != nullptr) {
        // found symbols by file name
        SymbolsFile *symbolsFile = FindSymbolsFileByMap(*map);
        if (symbolsFile != nullptr) {
            HLOGM("read vaddr from addr is 0x%" PRIx64 " at '%s'", vaddr - map->begin_,
                  map->name_.c_str());
            if (size == symbolsFile->ReadRoMemory(map->FileOffsetFromAddr(vaddr), data, size)) {
                return true;
            } else {
                return false;
            }
        } else {
            HLOGW("found addr %" PRIx64 " in map but not loaded symbole %s", vaddr,
                  map->name_.c_str());
        }
    } else {
#ifdef HIPERF_DEBUG
        ReportVaddrMapMiss(vaddr);
#endif
    }
    return false;
}

bool VirtualThread::IsLegalFileName(const std::string &fileName)
{
    // some special
    if (fileName == "[vdso]") {
        return true;
    }
    if (fileName.empty() or fileName.find(':') != std::string::npos or fileName.front() == '[' or
        fileName.back() == ']' or std::strncmp(fileName.c_str(), "/dev/", sizeof("/dev/")) == 0 or
        std::strncmp(fileName.c_str(), "/memfd:", sizeof("/memfd:")) == 0 or
        std::strncmp(fileName.c_str(), "//anon", sizeof("//anon")) == 0 or
        StringEndsWith(fileName, ".ttf")) {
        return false;
    }
    return true;
}

#if is_mingw
void VirtualThread::ParseMap()
{
    // only linux support read maps in runtime
    return;
}
#else
constexpr const int MMAP_LINE_MIN_TOKEN = 5;
constexpr const int MMAP_LINE_TOKEN_INDEX_FLAG = 1;
constexpr const int MMAP_LINE_TOKEN_INDEX_OFFSET = 2;
constexpr const int MMAP_LINE_TOKEN_INDEX_MM = 3;
constexpr const int MMAP_LINE_TOKEN_INDEX_INODE = 4;
constexpr const int MMAP_LINE_TOKEN_INDEX_NAME = 5;
constexpr const int MMAP_LINE_MAX_TOKEN = 6;

void VirtualThread::ParseMap()
{
    std::string mapPath = StringPrintf("/proc/%d/maps", pid_);
    std::string mapContent = ReadFileToString(mapPath);
    if (mapContent.size() > 0) {
        std::istringstream s(mapContent);
        std::string line;
        while (std::getline(s, line)) {
            HLOGM("map line: %s", line.c_str());
            // b0023000-b0024000 r--p 00000000 b3:05 959        /system/lib/libdl.so
            // 0                 1    2        3     4          5
            MemMapItem memMapItem;
            std::vector<std::string> mapTokens = StringSplit(line, " ");

            if (mapTokens.size() < MMAP_LINE_MIN_TOKEN) {
                // maybe file name is empty
                continue;
            }

            // b0023000-b0024000
            constexpr const int MMAP_ADDR_RANGE_TOKEN = 2;
            std::vector<std::string> addrRanges = StringSplit(mapTokens[0], "-");
            if (addrRanges.size() != MMAP_ADDR_RANGE_TOKEN) {
                continue;
            }

            // b0023000 / b0024000
            try {
                memMapItem.begin_ = std::stoull(addrRanges[0], nullptr, NUMBER_FORMAT_HEX_BASE);
                memMapItem.end_ = std::stoull(addrRanges[1], nullptr, NUMBER_FORMAT_HEX_BASE);
            } catch (...) {
                // next line
                continue;
            }

            constexpr const int MMAP_PROT_CHARS = 4;
            int index = 0;
            // rwxp
            memMapItem.type_ = 0;
            if (mapTokens[MMAP_LINE_TOKEN_INDEX_FLAG].size() != MMAP_PROT_CHARS) {
                continue;
            }
            if (mapTokens[MMAP_LINE_TOKEN_INDEX_FLAG][index++] == 'r') {
                memMapItem.type_ |= PROT_READ;
            }
            if (mapTokens[MMAP_LINE_TOKEN_INDEX_FLAG][index++] == 'w') {
                memMapItem.type_ |= PROT_WRITE;
            }
            if (mapTokens[MMAP_LINE_TOKEN_INDEX_FLAG][index++] == 'x') {
                memMapItem.type_ |= PROT_EXEC;
            }

            if ((memMapItem.type_ & PROT_EXEC) or (memMapItem.type_ | PROT_READ)) {
                /*
                we need record the read hen exec map address
                callstackk need r map to check the ehframe addrssss
                Section Headers:
                [Nr] Name              Type             Address           Offset
                    Size              EntSize          Flags  Link  Info  Align

                [12] .eh_frame_hdr     PROGBITS         00000000002929a0  000929a0
                    00000000000071fc  0000000000000000   A       0     0     4
                [13] .eh_frame         PROGBITS         0000000000299ba0  00099ba0
                    000000000002a8f4  0000000000000000   A       0     0     8
                [14] .text             PROGBITS         00000000002c5000  000c5000
                    00000000001caa4a  0000000000000000  AX       0     0     16

                00200000-002c5000 r--p 00000000 08:02 46400311
                002c5000-00490000 r-xp 000c5000 08:02 46400311
                */
            } else {
                continue;
            }

            // MAP_PRIVATE or MAP_SHARED
            constexpr const int MAP_FLAG_ATTR_INDEX = 3;
            if (mapTokens[MMAP_LINE_TOKEN_INDEX_FLAG][MAP_FLAG_ATTR_INDEX] == 'p') {
                memMapItem.flags = MAP_PRIVATE;
            } else if (mapTokens[MMAP_LINE_TOKEN_INDEX_FLAG][MAP_FLAG_ATTR_INDEX] == 's') {
                memMapItem.flags = MAP_SHARED;
            }

            try {
                // 00000000
                memMapItem.pageoffset_ = std::stoull(mapTokens[MMAP_LINE_TOKEN_INDEX_OFFSET],
                                                     nullptr, NUMBER_FORMAT_HEX_BASE);

                // major:minor
                std::vector<std::string> mm = StringSplit(mapTokens[MMAP_LINE_TOKEN_INDEX_MM], ":");

                // b3:05
                memMapItem.major_ = std::stoull(mm.at(0), nullptr, NUMBER_FORMAT_HEX_BASE);
                memMapItem.minor_ = std::stoull(mm.at(1), nullptr, NUMBER_FORMAT_HEX_BASE);

                // 959
                memMapItem.inode = std::stoull(mapTokens[MMAP_LINE_TOKEN_INDEX_INODE], nullptr,
                                               NUMBER_FORMAT_HEX_BASE);
            } catch (...) {
                // next line
                continue;
            }
            if (memMapItem.major_ == 0) {
                HLOGM("map line: exit %s", line.c_str());
                continue;
            }
            // system/lib/libdl.so
            if (mapTokens.size() == MMAP_LINE_MAX_TOKEN) {
                memMapItem.name_ = mapTokens[MMAP_LINE_TOKEN_INDEX_NAME];
                if (memMapItem.name_.find("/data/storage") == 0 && access(memMapItem.name_.c_str(), F_OK) != 0) {
                    memMapItem.name_ = "/proc/" + std::to_string(pid_) + "/root" + memMapItem.name_;
                }
            }
            if (!IsLegalFileName(memMapItem.name_)) {
                continue;
            }
            HLOGD("%d %d memMap add '%s'", pid_, tid_, memMapItem.name_.c_str());
            memMaps_.emplace_back(std::move(memMapItem));
        }
    }
    SortMemMaps();
}
#endif

void VirtualThread::SortMemMaps()
{
    for (int currPos = 1; currPos < static_cast<int>(memMaps_.size()); ++currPos) {
        int targetPos = currPos - 1;
        while (targetPos >= 0 and memMaps_[currPos].end_ < memMaps_[targetPos].end_) {
            --targetPos;
        }
        if (targetPos < currPos - 1) {
            auto target = memMaps_[currPos];
            for (int k = currPos - 1; k > targetPos; --k) {
                memMaps_[k + 1] = memMaps_[k];
            }
            memMaps_[targetPos + 1] = target;
        }
    }
    return;
}

void VirtualThread::CreateMapItem(const std::string filename, uint64_t begin, uint64_t len,
                                  uint64_t offset)
{
    if (!IsLegalFileName(filename)) {
        return; // skip some memmap
    }
    MemMapItem &map = memMaps_.emplace_back(begin, begin + len, offset, filename);
    HLOGD(" %u:%u create a new map(total %zu) at '%s' (0x%" PRIx64 "-0x%" PRIx64 ")@0x%" PRIx64 " ",
          pid_, tid_, memMaps_.size(), map.name_.c_str(), map.begin_, map.end_, map.pageoffset_);
    SortMemMaps();
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
