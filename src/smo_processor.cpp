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
#define HILOG_TAG "SmoProcessor"

#include "smo_processor.h"

#include <algorithm>
#include <cinttypes>
#include <cstring>

#include "dfx_elf.h"
#include "string_util.h"

#include "debug_logger.h"
#include "hiperf_hilog.h"
#include "mingw_adapter.h"
#include "utilities.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {

namespace {
const std::unordered_set<std::string> MERGED_SO_NAMES = {
    "libadlt_app.so",
};
const uint16_t RECORD_HEADER_SIZE = 8;
const uint16_t SMO_MERGE_SO_HEADER_SIZE = 20;
}

SmoProcessor::SmoProcessor(const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles,
                           SymbolManager& symbolManager, const SymbolsFileRegisterFunc& registerFunc)
    : symbolsFiles_(symbolsFiles), symbolManager_(symbolManager), registerFunc_(registerFunc)
{
}

void SmoProcessor::UpdateSmoList(const VirtualThread& thread,
                                 std::vector<std::shared_ptr<DfxElf>>& elfList,
                                 std::vector<std::string>& filePathList)
{
    for (auto& dfxMap : thread.GetMaps()) {
        if (MERGED_SO_NAMES.find(dfxMap->name.substr(dfxMap->name.rfind('/') + 1)) != MERGED_SO_NAMES.end() &&
            savedSmoPathList_.find(dfxMap->name) == savedSmoPathList_.end()) {
            filePathList.push_back(dfxMap->name);
            elfList.push_back(GetElfByMap(dfxMap));
            savedSmoPathList_.insert(dfxMap->name);
        }
    }
}

bool SmoProcessor::UpdateProcessSmoInfo(const VirtualThread& thread)
{
    std::vector<std::shared_ptr<DfxElf>> elfList;
    std::vector<std::string> filePathList;
    UpdateSmoList(thread, elfList, filePathList);
    if (elfList.size() == 0) {
        return false;
    }
    SmoHeaderFragment smoHeader = {0, elfList.size()};
    std::vector<SmoMergeSoHeaderFragment> smoMergeSoHeaderList;
    std::vector<AdltMapFragment> adltMapList;
    std::vector<std::string> strtabList;
    std::vector<std::string> soNameList;
    u32 mapOffset = RECORD_HEADER_SIZE + elfList.size() * SMO_MERGE_SO_HEADER_SIZE;
    std::string strtab = "";
    for (size_t i = 0; i < elfList.size(); i++) {
        std::vector<AdltMapInfo> adltMap = elfList[i]->GetAdltMap();
        std::string adltStrtab = elfList[i]->GetAdltStrtab();
        if (!std::is_sorted(adltMap.begin(), adltMap.end(),
            [](AdltMapInfo a, AdltMapInfo b) {return a.pcBegin < b.pcBegin;})) {
            std::sort(adltMap.begin(), adltMap.end(), [](AdltMapInfo a, AdltMapInfo b) {return a.pcBegin < b.pcBegin;});
        }
        smoMergeSoHeaderList.push_back({mapOffset, adltMap.size() * sizeof(AdltMapFragment), 0, adltStrtab.size(), 0});
        for (AdltMapInfo adMap : adltMap) {
            adltMapList.push_back({adMap.pcBegin, adMap.pcEnd, adMap.psodIndex, adMap.nameOffset});
        }
        strtabList.push_back(adltStrtab);
        soNameList.push_back(filePathList[i]);
        mapOffset += adltMap.size() * sizeof(AdltMapFragment);
    }
    for (auto i = 0u; i < strtabList.size(); i++) {
        strtab += strtabList[i];
        smoMergeSoHeaderList[i].strtabOffset = mapOffset;
        mapOffset += strtabList[i].size();
    }
    for (auto i = 0u; i < soNameList.size(); i++) {
        strtab += (soNameList[i] + "\0");
        smoMergeSoHeaderList[i].soOffset = mapOffset;
        mapOffset += (soNameList[i].size() + 1);
    }
    PerfRecordSmoDataFragment perfRecordSmoDataFragment = {smoHeader, smoMergeSoHeaderList, adltMapList, strtab};
    PutSmoDataToRecord(perfRecordSmoDataFragment, mapOffset);
    return true;
}

void SmoProcessor::PutSmoDataToRecord(PerfRecordSmoDataFragment& perfRecordSmoDataFragment, u32 mapOffset)
{
    std::vector<uint8_t> binaryData(mapOffset);
    uint8_t* ptr = binaryData.data();
    if (memcpy_s(ptr, mapOffset, &(perfRecordSmoDataFragment.smoHeader),
        sizeof(perfRecordSmoDataFragment.smoHeader)) != 0) {
        HLOGE("memcpy_s return failed in PutSmoDataToRecord with smoHeader");
        return;
    }
    ptr += sizeof(SmoHeaderFragment);
    for (SmoMergeSoHeaderFragment smoMergeSoHeader : perfRecordSmoDataFragment.smoMergeSoHeaderList) {
        if (memcpy_s(ptr, mapOffset-(ptr - binaryData.data()), &(smoMergeSoHeader), sizeof(smoMergeSoHeader)) != 0) {
            HLOGE("memcpy_s return failed in PutSmoDataToRecord with smoMergeSoHeader");
            return;
        }
        ptr += sizeof(smoMergeSoHeader);
    }
    for (AdltMapFragment adltMap : perfRecordSmoDataFragment.adltMapList) {
        if (memcpy_s(ptr, mapOffset-(ptr - binaryData.data()), &(adltMap), sizeof(adltMap)) != 0) {
            HLOGE("memcpy_s return failed in PutSmoDataToRecord with adltMap");
            return;
        }
        ptr += sizeof(adltMap);
    }
    std::copy(perfRecordSmoDataFragment.strtab.begin(), perfRecordSmoDataFragment.strtab.end(), ptr);
    ptr += perfRecordSmoDataFragment.strtab.size();
    uint16_t fragmentLength_ = PerfRecordSmoDetachingEvent::fragmentLength_;
    uint16_t fragmentNum_ = (mapOffset + fragmentLength_ - 1) / fragmentLength_;
    for (uint16_t i = 0; i < fragmentNum_; i++) {
        std::vector<uint8_t> subData(i == (fragmentNum_ - 1) ? mapOffset % fragmentLength_ : fragmentLength_);
        std::copy(binaryData.begin() + i*fragmentLength_,
            ((i == (fragmentNum_ - 1)) ? binaryData.end() : (binaryData.begin() + (i + 1) * fragmentLength_)),
            subData.begin());
        std::shared_ptr<PerfRecordSmoDetachingEvent> perfRecordSmo =
            std::make_shared<PerfRecordSmoDetachingEvent>(subData, fragmentNum_, i);
        recordCallBack_(*perfRecordSmo);
    }
}

std::vector<uint8_t> SmoProcessor::UpdateBinaryDataFromRecord(PerfRecordSmoDetachingEvent& record)
{
    std::vector<uint8_t> binaryData;
    if (binaryDataMap_.size() == record.allFragmentNum_) {
        return binaryData;
    }
    binaryDataMap_.emplace(record.fragmentNum_, record.binaryData);
    if (binaryDataMap_.size() != record.allFragmentNum_) {
        return binaryData;
    }

    for (uint16_t i = 0; i < binaryDataMap_.size(); i++) {
        if (binaryDataMap_[i].empty()) {
            return binaryData;
        }
        binaryData.insert(binaryData.end(), binaryDataMap_[i].begin(), binaryDataMap_[i].end());
    }
    return binaryData;
}

void SmoProcessor::UpdateFromRecord(PerfRecordSmoDetachingEvent& record)
{
    std::vector<uint8_t> binaryData = UpdateBinaryDataFromRecord(record);
    if (binaryData.empty()) {
        return;
    }
    uint8_t* data = binaryData.data();
    SmoHeaderFragment* smoHeaderPtr = reinterpret_cast<SmoHeaderFragment*>(data);
    for (uint32_t i = 0; i < smoHeaderPtr->soNumber; i++) {
        std::vector<AdltMapDataFragment> adltMapDataList;
        std::unordered_set<std::string> soNames;
        if (RECORD_HEADER_SIZE + i * SMO_MERGE_SO_HEADER_SIZE > record.allFragmentNum_ * record.fragmentLength_) {
            return;
        }
        SmoMergeSoHeaderFragment* smoMergeSoHeaderPtr =
            reinterpret_cast<SmoMergeSoHeaderFragment*>(data + RECORD_HEADER_SIZE + i * SMO_MERGE_SO_HEADER_SIZE);
        if (smoMergeSoHeaderPtr->mapOffset > record.allFragmentNum_ * record.fragmentLength_ ||
            smoMergeSoHeaderPtr->soOffset > record.allFragmentNum_ * record.fragmentLength_) {
            return;
        }
        AdltMapFragment* adltMapListPtr = reinterpret_cast<AdltMapFragment*>(data + smoMergeSoHeaderPtr->mapOffset);
        for (uint32_t j = 0; j < smoMergeSoHeaderPtr->mapSize / sizeof(AdltMapFragment); j++) {
            if (smoMergeSoHeaderPtr->strtabOffset + adltMapListPtr[j].nameOffset >
                record.allFragmentNum_ * record.fragmentLength_) {
                return;
            }
            std::string soName = std::string(reinterpret_cast<char*>(data) +
                smoMergeSoHeaderPtr->strtabOffset + adltMapListPtr[j].nameOffset);
            adltMapDataList.push_back({adltMapListPtr[j].pcBegin, adltMapListPtr[j].
                pcEnd, adltMapListPtr[j].psodIndex, soName});
            soNames.insert(soName);
        }
        std::sort(adltMapDataList.begin(), adltMapDataList.end(),
            [](AdltMapDataFragment a, AdltMapDataFragment b) {
                return a.pcBegin < b.pcBegin;
            });
        std::string filePath = std::string(reinterpret_cast<char*>(data) + smoMergeSoHeaderPtr->soOffset);
        soMappingMap_.emplace(filePath, adltMapDataList);
        originSoMap_.emplace(filePath, soNames);
    }
    UpdateFilesFromSmoRecordData();

    symbolManager_.SetSoMappingMap(soMappingMap_);
}

void SmoProcessor::UpdateFilesFromSmoRecordData()
{
    HLOGV("symbolsFiles_ origin size:%zu, mapsize:%zu", symbolsFiles_.size(), originSoMap_.size());
    for (const auto& mapEntry : originSoMap_) {
        const std::string& soName = mapEntry.first;
        const std::unordered_set<std::string>& originSoList = mapEntry.second;
        HLOGV("originSoList size:%zu", originSoList.size());
        for (const auto& data : originSoList) {
            std::string extendFilePath = soName + ":" + data;
            auto it = std::find_if(symbolsFiles_.begin(), symbolsFiles_.end(),
                [&extendFilePath](const std::unique_ptr<SymbolsFile>& file) {
                return file->filePath_ == extendFilePath;
            });
            if (it != symbolsFiles_.end()) {
                continue;
            }
            std::unique_ptr<SymbolsFile> symbolsFile = SymbolsFile::CreateSymbolsFile(extendFilePath);
            registerFunc_(std::move(symbolsFile));
            HLOGV("add new symbolsFile:%s", extendFilePath.c_str());
        }
    }
    HLOGV("symbolsFiles_ new size:%zu", symbolsFiles_.size());
}

void SmoProcessor::Clear()
{
    soMappingMap_.clear();
    originSoMap_.clear();
    binaryDataMap_.clear();
    savedSmoPathList_.clear();
}

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
