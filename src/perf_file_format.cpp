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
#include "perf_file_format.h"

#include "debug_logger.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
std::string PerfFileSection::GetFeatureName(FEATURE featureId)
{
    unsigned int index = static_cast<unsigned int>(featureId);
    if (featureId >= FEATURE::HIPERF_FIRST_FEATURE) {
        index -= static_cast<unsigned int>(FEATURE::HIPERF_FIRST_FEATURE);
        if (index >= extFeatureNames.size()) {
            return featureNames[0];
        }
        return extFeatureNames[index];
    } else {
        if (index >= featureNames.size()) {
            return featureNames[0];
        }
        return featureNames[index];
    }
}

// for read
void PerfFileSection::Init(const char *buffer, size_t maxSize)
{
    rBuffer_ = buffer;
    maxSize_ = maxSize;
    offset_ = 0;
}

// for write
void PerfFileSection::Init(char *buffer, size_t maxSize)
{
    wBuffer_ = buffer;
    maxSize_ = maxSize;
    offset_ = 0;
}

bool PerfFileSection::Write(uint32_t u32)
{
    uint32_t value = u32;
    return Write((char *)&value, sizeof(uint32_t));
}

bool PerfFileSection::Write(uint64_t u64)
{
    uint64_t value = u64;
    return Write((char *)&value, sizeof(uint64_t));
}

bool PerfFileSection::Write(const std::string &str)
{
    if (Write((uint32_t)str.size() + 1)) { // include the ending \0
        return Write(str.c_str(), str.size(), str.size() + 1);
    } else {
        return false;
    }
}

bool PerfFileSection::Write(const char *buf, size_t size)
{
    return Write(buf, size, size);
}

bool PerfFileSection::Write(const char *buf, size_t size, size_t max)
{
    if (offset_ + size > maxSize_) {
        HLOGE("write out of size!!! offset_ %zu size %zu max %zu", offset_, size, maxSize_);
        return false;
    }
    if (offset_ + max > maxSize_) {
        HLOGE("write out of size!!! offset_ %zu size %zu max %zu", offset_, size, maxSize_);
        return false;
    }
    std::copy(buf, buf + size, wBuffer_ + offset_);
    if (size >= max) {
        offset_ += size;
    } else {
        offset_ += max;
    }
    return true;
}

bool PerfFileSection::Read(uint32_t &value)
{
    static_assert(sizeof(uint32_t) == 4);
    return Read((char *)&value, sizeof(uint32_t));
}

bool PerfFileSection::Read(uint64_t &value)
{
    static_assert(sizeof(uint64_t) == 8);

    return Read((char *)&value, sizeof(uint64_t));
}

bool PerfFileSection::Read(std::string &value)
{
    uint32_t size = 0;
    if (!Read(size)) {
        return false;
    }
    // if size large than buf size or 0 size ?
    // don't assert for fuzz test
    if (size == 0 or size > maxSize_) {
        return false;
    }
    char buf[size];
    if (!Read(buf, size)) {
        return false;
    }
    if (buf[size - 1] != 0) {
        return false;
    }
    value = buf;
    HLOGDUMMY("Read String size %u buf : %s", size, value.c_str());
    return true;
}
void PerfFileSection::Skip(size_t size)
{
    offset_ += size;
}

bool PerfFileSection::Read(char *buf, size_t size)
{
    HLOG_ASSERT(buf != nullptr);
    if (size == 0) {
        HLOGE("read zero size!!! offset_ %zu size %zu max %zu", offset_, size, maxSize_);
        return false;
    } else if (offset_ + size > maxSize_) {
        HLOGE("read out of size!!! offset_ %zu size %zu max %zu", offset_, size, maxSize_);
        if (memset_s(buf, size, 0, size) != EOK) { // make sure the content return is 0 when failed
            HLOGE("memset_s failed in PerfFileSection::Read");
            return false;
        }
        return false;
    }
    HLOGD("PerfFileSection::Read offset_ %zu size %zu maxSize_ %zu", offset_, size, maxSize_);
    std::copy((rBuffer_ + offset_), (rBuffer_ + offset_ + size), buf);
    offset_ += size;
    HLOGDUMMY("after read offset_ %zx size %zu buf %x", offset_, size, buf[0]);
    return true;
}

uint32_t PerfFileSection::SizeOf(std::string &string)
{
    return sizeof(uint32_t) + string.size() + 1; /* '\0' */
}

PerfFileSectionString::PerfFileSectionString(FEATURE id, const char *buf, size_t size)
    : PerfFileSection(id)
{
    Init(buf, size);
    if (!Read(stdString_)) {
        return; // or throw ...
    }
}

PerfFileSectionString::PerfFileSectionString(FEATURE id, const std::string &charString)
    : PerfFileSection(id)
{
    stdString_ = charString;
}

bool PerfFileSectionString::GetBinary(char *buf, size_t size)
{
    if (size < GetSize()) {
        return false;
    }

    Init(buf, size);
    Write(stdString_);
    return true;
}

size_t PerfFileSectionString::GetSize()
{
    return SizeOf(stdString_);
}

const std::string PerfFileSectionString::toString() const
{
    return stdString_;
}

size_t PerfFileSectionSymbolsFiles::GetSize()
{
    size_t size = 0;

    size += sizeof(uint32_t); // how many SymbolFileStruct
    for (auto &symbolFileStruct : symbolFileStructs_) {
        size += SizeOf(symbolFileStruct.filePath_);
        size += sizeof(symbolFileStruct.symbolType_);
        size += sizeof(symbolFileStruct.textExecVaddr_);
        size += sizeof(symbolFileStruct.textExecVaddrFileOffset_);
        size += SizeOf(symbolFileStruct.buildId_);

        size += sizeof(uint32_t); // how many SymbolStruct
        for (auto &symbolStruct : symbolFileStruct.symbolStructs_) {
            size += sizeof(symbolStruct.vaddr_);
            size += sizeof(symbolStruct.len_);
            size += SizeOf(symbolStruct.symbolName_);
        }
    }
    return size;
}

PerfFileSectionSymbolsFiles::PerfFileSectionSymbolsFiles(FEATURE id, const char *buf, size_t size)
    : PerfFileSection(id)
{
    Init(buf, size);
    uint32_t symbolFileNumber = 0;
    if (!Read(symbolFileNumber)) {
        HLOGE(" symbolFileNumber read failed");
        return;
    } else if (symbolFileNumber > MAX_SYMBOLS_FILE_NUMBER) {
        HLOGE(" symbolFileNumber %u too large", symbolFileNumber);
        return;
    } else {
        HLOGV(" symbolFileNumber %u", symbolFileNumber);
    }

    for (uint32_t i = symbolFileNumber; i > 0; i--) {
        auto &symbolFileStruct = symbolFileStructs_.emplace_back();

        Read(symbolFileStruct.filePath_);
        HLOGV(" symbolFileStruct.filePath_ %s", symbolFileStruct.filePath_.c_str());

        Read(symbolFileStruct.symbolType_);
        Read(symbolFileStruct.textExecVaddr_);
        Read(symbolFileStruct.textExecVaddrFileOffset_);
        Read(symbolFileStruct.buildId_);

        uint32_t symbolsNumber = 0;
        if (!Read(symbolsNumber)) {
            HLOGE(" symbols read failed");
            return;
        } else if (symbolsNumber > MAX_SYMBOLS_NUMBER) {
            HLOGE(" symbols %u too large", symbolsNumber);
            return;
        } else {
            HLOGV(" symbols %u", symbolsNumber);
        }
        for (; symbolsNumber > 0; symbolsNumber--) {
            auto &symbolStruct = symbolFileStruct.symbolStructs_.emplace_back();
            Read(symbolStruct.vaddr_);
            Read(symbolStruct.len_);
            Read(symbolStruct.symbolName_);
        }
        HLOGV(" %zu SymbolStruct read.", symbolFileStruct.symbolStructs_.size());
    }
    HLOGV(" %zu SymbolFileStruct read.", symbolFileStructs_.size());
}

bool PerfFileSectionSymbolsFiles::GetBinary(char *buf, size_t size)
{
    HLOGV("PerfFileSectionSymbolsFiles get buffer size %zu.", size);
    HLOG_ASSERT(size >= GetSize());

    Init(buf, size);
    if (!Write((uint32_t)symbolFileStructs_.size())) {
        HLOGE("PerfFileSectionSymbolsFiles write failed with %zu.", symbolFileStructs_.size());
        return false;
    }
    for (auto &symbolFileStruct : symbolFileStructs_) {
        Write(symbolFileStruct.filePath_);
        Write(symbolFileStruct.symbolType_);
        Write(symbolFileStruct.textExecVaddr_);
        Write(symbolFileStruct.textExecVaddrFileOffset_);
        Write(symbolFileStruct.buildId_);

        Write((uint32_t)symbolFileStruct.symbolStructs_.size());
        for (auto &symbolStruct : symbolFileStruct.symbolStructs_) {
            Write(symbolStruct.vaddr_);
            Write(symbolStruct.len_);
            Write(symbolStruct.symbolName_);
        }
        HLOGV(" %zu SymbolStruct writed. for %s at 0x%016" PRIx64 "@0x%08" PRIx64 ": %s",
              symbolFileStruct.symbolStructs_.size(), symbolFileStruct.filePath_.c_str(),
              symbolFileStruct.textExecVaddr_, symbolFileStruct.textExecVaddrFileOffset_,
              symbolFileStruct.buildId_.c_str());
    }
    HLOGV("%zu SymbolFileStruct writed.", symbolFileStructs_.size());

    return true;
}

PerfFileSectionNrCpus::PerfFileSectionNrCpus(FEATURE id, const char *buf, size_t size)
    : PerfFileSection(id)
{
    Init(buf, size);
    if (!Read(nrCpusAvailable_) || !Read(nrCpusOnline_)) {
        return;
    }
}

PerfFileSectionNrCpus::PerfFileSectionNrCpus(FEATURE id, uint32_t nrCpusAvailable,
                                             uint32_t nrCpusOnline)
    : PerfFileSection(id), nrCpusAvailable_(nrCpusAvailable), nrCpusOnline_(nrCpusOnline)
{
}

bool PerfFileSectionNrCpus::GetBinary(char *buf, size_t size)
{
    if (size < GetSize()) {
        return false;
    }

    Init(buf, size);
    Write(nrCpusAvailable_);
    Write(nrCpusOnline_);
    return true;
}

size_t PerfFileSectionNrCpus::GetSize()
{
    return (sizeof(nrCpusAvailable_) + sizeof(nrCpusOnline_));
}

void PerfFileSectionNrCpus::GetValue(uint32_t &nrCpusAvailable, uint32_t &nrCpusOnline) const
{
    nrCpusAvailable = nrCpusAvailable_;
    nrCpusOnline = nrCpusOnline_;
}

PerfFileSectionU64::PerfFileSectionU64(FEATURE id, const char *buf, size_t size)
    : PerfFileSection(id)
{
    Init(buf, size);
    if (!Read(value_)) {
        return;
    }
}

PerfFileSectionU64::PerfFileSectionU64(FEATURE id, uint64_t v) : PerfFileSection(id)
{
    value_ = v;
}

bool PerfFileSectionU64::GetBinary(char *buf, size_t size)
{
    if (size < GetSize()) {
        return false;
    }

    Init(buf, size);
    Write(value_);
    return true;
}

size_t PerfFileSectionU64::GetSize()
{
    return sizeof(value_);
}

void PerfFileSectionU64::GetValue(uint64_t &v) const
{
    v = value_;
}

PerfFileSectionEventDesc::PerfFileSectionEventDesc(FEATURE id,
                                                   const std::vector<AttrWithId> &eventDesces)
    : PerfFileSection(id)
{
    eventDesces_ = eventDesces;
}

PerfFileSectionEventDesc::PerfFileSectionEventDesc(FEATURE id, const char *buf, size_t size)
    : PerfFileSection(id)
{
    constexpr uint32_t maxIds = 600;
    Init(buf, size);
    uint32_t nr = 0;
    if (!Read(nr)) {
        return;
    }
    uint32_t attrSize = 0;
    if (!Read(attrSize)) {
        return;
    }
    if (attrSize != sizeof(perf_event_attr)) { // only for log or debug
        HLOGW("perf_event_attr version is different, attrSize %d vs %zu", attrSize,
              sizeof(perf_event_attr));
    }

    for (; nr > 0; nr--) {
        AttrWithId eventDesc;
        // compatible with the different version of 'perf_event_attr'
        if (attrSize > sizeof(perf_event_attr)) {
            if (!Read((char *)&(eventDesc.attr), sizeof(perf_event_attr))) {
                return;
            }
            // skip tail bytes
            HLOGW("skip %zu byte for diff attr size", attrSize - sizeof(perf_event_attr));
            Skip(attrSize - sizeof(perf_event_attr));
        } else if (!Read((char *)&(eventDesc.attr), attrSize)) {
            return;
        }

        uint32_t nrIds = 0;
        if (!Read(nrIds)) {
            return;
        } else if (nrIds == 0) {
            HLOGW("nrIds is not correct ! %u", nrIds);
            return;
        } else if (nrIds > maxIds) {
            HLOGW("nrIds is too large ! %u", nrIds);
        }
        if (!Read(eventDesc.name)) {
            return;
        }
        eventDesc.ids.resize(nrIds, 0);
        if (!Read((char *)eventDesc.ids.data(), sizeof(uint64_t) * nrIds)) {
            return;
        }
        eventDesces_.emplace_back(std::move(eventDesc));
    }
    HLOGV("read complete. %zu events", eventDesces_.size());
}

bool PerfFileSectionEventDesc::GetBinary(char *buf, size_t size)
{
    if (size < GetSize()) {
        return false;
    }
    Init(buf, size);

    if (!Write((uint32_t)eventDesces_.size())) {
        return false;
    }
    if (!Write((uint32_t)sizeof(perf_event_attr))) {
        return false;
    }
    for (auto &eventDesc : eventDesces_) {
        if (!Write((char *)&(eventDesc.attr), sizeof(perf_event_attr))) {
            return false;
        }
        if (!Write((uint32_t)eventDesc.ids.size())) {
            return false;
        }
        if (!Write(eventDesc.name)) {
            return false;
        }
        // clang-format off
        if (!Write((char *)eventDesc.ids.data(),
                   sizeof(uint64_t) * eventDesc.ids.size())) {
            // clang-format on
            return false;
        }
    }
    return true;
}

size_t PerfFileSectionEventDesc::GetSize()
{
    size_t size = sizeof(uint32_t); // nr
    size += sizeof(uint32_t);       // attr_size

    size += (eventDesces_.size() * sizeof(perf_event_attr));
    size += (eventDesces_.size() * sizeof(uint32_t)); // nr_ids
    for (auto &eventDesc : eventDesces_) {
        size += SizeOf(eventDesc.name);
        size += (sizeof(uint64_t) * eventDesc.ids.size());
    }
    return size;
}

void PerfFileSectionEventDesc::GetValue(std::vector<AttrWithId> &eventDesces) const
{
    eventDesces = eventDesces_;
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
