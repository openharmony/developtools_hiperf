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
#include "perf_file_writer.h"

#include <cinttypes>
#include <cstdlib>
#include <unistd.h>

#include "utilities.h"
using namespace std::chrono;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
PerfFileWriter::~PerfFileWriter()
{
    // if file was not closed properly, remove it before exit
    if (fp_ != nullptr) {
        fclose(fp_);
        fp_ = nullptr;
        if (remove(fileName_.c_str()) != 0) {
            HLOGE("fail to remove file(%s).", fileName_.c_str());
        }
    }
}

bool PerfFileWriter::Open(const std::string &fileName, bool compressData)
{
    // check file existence, if exist, remove it
    if (access(fileName.c_str(), F_OK) == 0) {
        // file exists
        if (remove(fileName.c_str()) != 0) {
			char errInfo[ERRINFOLEN] = { 0 };
            strerror_r(errno, errInfo, ERRINFOLEN);
            printf("can't remove exist file(%s). %d:%s\n", fileName.c_str(), errno,
                   errInfo);
            return false;
        }
    }
    std::string resolvedPath = CanonicalizeSpecPath(fileName.c_str());
    fp_ = fopen(resolvedPath.c_str(), "web+");
    if (fp_ == nullptr) {
        char errInfo[ERRINFOLEN] = { 0 };
        strerror_r(errno, errInfo, ERRINFOLEN);
        printf("can't create file(%s). %d:%s\n", fileName.c_str(), errno, errInfo);
        return false;
    }

    fileName_ = fileName;
    compressData_ = compressData;
    attrSection_.offset = 0;
    attrSection_.size = 0;
    dataSection_ = attrSection_;
    header_.size = sizeof(header_);
    fileBuffer_.resize(WRITER_BUFFER_SIZE);
    if (setvbuf(fp_, fileBuffer_.data(), _IOFBF, WRITER_BUFFER_SIZE) != 0) {
        HLOGD("setvbuf failed");
    }

    return true;
}

bool PerfFileWriter::Close()
{
    HLOG_ASSERT(fp_ != nullptr);
    bool rc = true;

    if (!WriteHeader()) {
        rc = false;
    }
    if (!WriteFeatureData()) {
        rc = false;
    }

    if (fclose(fp_) != 0) {
        HLOGD("fail to close fp ");
        rc = false;
    }
    fp_ = nullptr;

    // compress and rename .perf.data to gzip file
    if (compressData_) {
        std::string gzName = fileName_ + ".gz";
        if (CompressFile(fileName_, gzName)) {
            if (remove(fileName_.c_str()) != 0) {
                char errInfo[ERRINFOLEN] = { 0 };
                strerror_r(errno, errInfo, ERRINFOLEN);
                printf("can't remove file(%s). %d:%s\n",
                    fileName_.c_str(), errno, errInfo);
            }
            if (rename(gzName.c_str(), fileName_.c_str()) != 0) {
                char errInfo[ERRINFOLEN] = { 0 };
                strerror_r(errno, errInfo, ERRINFOLEN);
                printf("can't rename file(%s) to (%s). %d:%s\n", gzName.c_str(), fileName_.c_str(),
                       errno, errInfo);
            }
        } else {
            char errInfo[ERRINFOLEN] = { 0 };
            strerror_r(errno, errInfo, ERRINFOLEN);
            printf("failed to compress file(%s). %d:%s\n", fileName_.c_str(), errno,
                   errInfo);
        }
    }

    return rc;
}

bool PerfFileWriter::WriteRecord(const PerfEventRecord &record)
{
    if (!isWritingRecord) {
        HLOGV("need write <attrs> first");
        return false;
    }

    HLOGV("write '%s'", record.GetName().c_str());

    if (record.GetSize() > RECORD_SIZE_LIMIT) {
        HLOGD("%s record size exceed limit", record.GetName().c_str());
        return false;
    }
    // signal 7 (SIGBUS), code 1 (BUS_ADRALN), fault addr 0xb64eb195
    static std::vector<u8> buf(RECORD_SIZE_LIMIT);

    if (!record.GetBinary(buf)) {
        return false;
    }

    if (!Write(buf.data(), record.GetSize())) {
        return false;
    }
    dataSection_.size += record.GetSize();

    ++recordCount_;

    return true;
}

bool PerfFileWriter::ReadDataSection(ProcessRecordCB &callback)
{
    HLOG_ASSERT(fp_ != nullptr);
    if (fseek(fp_, dataSection_.offset, SEEK_SET) != 0) {
        HLOGE("fseek() failed");
        return false;
    }
    HLOGD("dataSection_ at offset %" PRIu64 " + %" PRIu64 "", dataSection_.offset,
          dataSection_.size);

    return ReadRecords(callback);
}

bool PerfFileWriter::ReadRecords(ProcessRecordCB &callback)
{
    // record size can not exceed 64K
    HIPERF_BUF_ALIGN uint8_t buf[RECORD_SIZE_LIMIT];
    // diff with reader
    uint64_t remainingSize = dataSection_.size;
    size_t recordNumber = 0;
    while (remainingSize > 0) {
        if (remainingSize < sizeof(perf_event_header)) {
            HLOGW("not enough sizeof(perf_event_header).");
            return false;
        } else if (Read(buf, sizeof(perf_event_header)) <= 0) {
            HLOGW("read perf_event_header failed.");
            return false;
        } else {
            perf_event_header *header = reinterpret_cast<perf_event_header *>(buf);
            HLOG_ASSERT(header->size < sizeof(buf));
            if (remainingSize >= header->size) {
                size_t headerSize = sizeof(perf_event_header);
                if (Read(buf + headerSize, header->size - headerSize)) {
                    uint8_t *data = buf;
                    auto record = GetPerfEventRecord(static_cast<perf_event_type>(header->type),
                                                     data, defaultEventAttr_);
                    // skip unknown record
                    if (record == nullptr)
                        return true;
                    remainingSize -= header->size;
                    // call callback to process, then destroy record
                    callback(std::move(record));
                    recordNumber++;
                }
            } else {
                HLOGW("not enough header->size.");
            }
        }
    }
    HLOGD("read back %zu records", recordNumber);
    return true;
}

bool PerfFileWriter::Read(void *buf, size_t len)
{
    HLOG_ASSERT(buf != nullptr);
    HLOG_ASSERT(fp_ != nullptr);
    HLOG_ASSERT(len > 0);

    if (fread(buf, len, 1, fp_) != 1) {
        HLOGD("failed to read file");
        return false;
    }
    return true;
}

uint64_t PerfFileWriter::GetDataSize() const
{
    return dataSection_.size;
}

uint PerfFileWriter::GetRecordCount() const
{
    return recordCount_;
}

bool PerfFileWriter::GetFilePos(uint64_t &pos) const
{
    off_t offset = ftello(fp_);
    if (offset == -1) {
        HLOGD("RecordFileWriter ftello fail");
        return false;
    }
    pos = static_cast<uint64_t>(offset);
    return true;
}

bool PerfFileWriter::Write(const void *buf, size_t len)
{
#ifdef HIPERF_DEBUG_TIME
    const auto startTime = steady_clock::now();
#endif
    if (len != 0u && fwrite(buf, len, 1, fp_) != 1) {
        HLOGD("PerfFileWriter fwrite fail ");
        return false;
    }
#ifdef HIPERF_DEBUG_TIME
    writeTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif
    return true;
}

bool PerfFileWriter::WriteAttrAndId(const std::vector<AttrWithId> &attrIds)
{
    if (attrIds.empty()) {
        return false;
    }

    // Skip file header part.
    if (fp_ == nullptr) {
        return false;
    } else if (fseek(fp_, header_.size, SEEK_SET) == -1) {
        return false;
    }

    // Write id section.
    uint64_t idSectionOffset;
    if (!GetFilePos(idSectionOffset)) {
        return false;
    }

    HLOGD("attrIds %zu", attrIds.size());
    for (auto &attrId : attrIds) {
        HLOGD(" attrIds ids %zu", attrId.ids.size());
        if (!Write(attrId.ids.data(), attrId.ids.size() * sizeof(uint64_t))) {
            return false;
        }
    }

    // Write attr section.
    uint64_t attrSectionOffset;
    if (!GetFilePos(attrSectionOffset)) {
        return false;
    }
    for (auto &attrId : attrIds) {
        perf_file_attr fileAttr;
        fileAttr.attr = attrId.attr;
        fileAttr.ids.offset = idSectionOffset;
        fileAttr.ids.size = attrId.ids.size() * sizeof(uint64_t);
        idSectionOffset += fileAttr.ids.size;

        if (!Write(&fileAttr, sizeof(fileAttr))) {
            return false;
        }
    }

    uint64_t dataSectionOffset;
    if (!GetFilePos(dataSectionOffset)) {
        return false;
    }

    attrSection_.offset = attrSectionOffset;
    attrSection_.size = dataSectionOffset - attrSectionOffset;
    dataSection_.offset = dataSectionOffset;

    defaultEventAttr_ = attrIds[0].attr;

    isWritingRecord = true;

    return true;
}

static bool LeftLessRight(const std::unique_ptr<PerfFileSection> &l,
                          const std::unique_ptr<PerfFileSection> &r)
{
    return l->featureId_ < r->featureId_;
}
// to write perf_file_header to file
// can only be called after all attr and records has been written.
bool PerfFileWriter::WriteHeader()
{
    header_.attrSize = sizeof(perf_file_attr);
    header_.attrs = attrSection_;
    header_.data = dataSection_;

    // ignore event_types
    header_.eventTypes.size = 0;
    header_.eventTypes.offset = 0;

    // save header
    if (fseek(fp_, 0, SEEK_SET) == -1) {
        HLOGD("fseek return error ");
        return false;
    }
    if (!Write(&header_, sizeof(header_))) {
        return false;
    }
    return true;
}

bool PerfFileWriter::WriteFeatureData()
{
    long featureOffset = 0;
    if (fseek(fp_, 0, SEEK_END) != 0) {
        HLOGD("fseek SEEK_END return error ");
        return false;
    }
    if ((featureOffset = ftell(fp_)) == -1) {
        HLOGD("ftell return error ");
        return false;
    }

    for (size_t i = 0; i < sizeof(header_.features); i++) {
        if (header_.features[i] != 0) {
            HLOGV(" features['%zu'] '0x%x'", i, header_.features[i]);
        }
    }

    unsigned long contentOffset = featureOffset + featureSections_.size() * sizeof(perf_file_section);
    HLOGV("features start at file '0x%lx' content at '0x%lx'", featureOffset, contentOffset);

    // reorder
    std::sort(featureSections_.begin(), featureSections_.end(), LeftLessRight);
    // save features head
    int i = 0;
    for (auto &featureSection : featureSections_) {
        featureSection->header.offset = contentOffset;
        featureSection->header.size = featureSection->GetSize();
        contentOffset += featureSection->header.size;
        HLOGV("save features[%d] head offset '0x%" PRIx64 "' size '0x%" PRIx64 "'", i,
              featureSection->header.offset, featureSection->header.size);
        i++;

        // write features heads
        if (!Write(&featureSection->header, sizeof(featureSection->header))) {
            return false;
        }
    }
    long offset = ftell(fp_);
    if (offset < 0) {
        return false;
    }
    HLOGV("features data at file '0x%lx'", offset);

    i = 0;
    for (auto &featureSection : featureSections_) {
        std::vector<char> buf(featureSection->header.size);
        featureSection->GetBinary(&buf[0], featureSection->header.size);
        HLOGV("save features[%d] content size '0x%" PRIx64 "'", i, featureSection->header.size);
        i++;

        // write features content
        if (!Write(&buf[0], featureSection->header.size)) {
            HLOGE("write failed %" PRIu64 ".", featureSection->header.size);
            return false;
        }
    }

    return true;
}

bool PerfFileWriter::AddNrCpusFeature(FEATURE feature, uint32_t nrCpusAvailable,
                                      uint32_t nrCpusOnline)
{
    HLOGV("add feature '%s': nrCpusAvailable %u, nrCpusOnline %u",
          PerfFileSection::GetFeatureName(FEATURE::NRCPUS).c_str(), nrCpusAvailable, nrCpusOnline);
    featureSections_.emplace_back(
        std::make_unique<PerfFileSectionNrCpus>(feature, nrCpusAvailable, nrCpusOnline));

    // update header feature bits
    header_.features[(int)FEATURE::NRCPUS / BITS_IN_BYTE] |=
        1 << ((int)FEATURE::NRCPUS % BITS_IN_BYTE); // bit
    return true;
}

bool PerfFileWriter::AddEventDescFeature(FEATURE feature,
                                         const std::vector<AttrWithId> &eventDesces)
{
    HLOGV("add feature '%s' %zu", PerfFileSection::GetFeatureName(FEATURE::EVENT_DESC).c_str(),
          eventDesces.size());
    featureSections_.emplace_back(std::make_unique<PerfFileSectionEventDesc>(feature, eventDesces));

    header_.features[(int)FEATURE::EVENT_DESC / BITS_IN_BYTE] |=
        1 << ((int)FEATURE::EVENT_DESC % BITS_IN_BYTE); // bit
    return true;
}

bool PerfFileWriter::AddStringFeature(FEATURE feature, std::string string)
{
    HLOGV("add feature '%s' string '%s'", PerfFileSection::GetFeatureName(feature).c_str(),
          string.c_str());
    featureSections_.emplace_back(std::make_unique<PerfFileSectionString>(feature, string));

    // update header feature bits
    header_.features[(int)feature / BITS_IN_BYTE] |= 1 << ((int)feature % BITS_IN_BYTE); // bit
    return true;
}

bool PerfFileWriter::AddBoolFeature(FEATURE feature)
{
    // same as u64, just use 1 as value
    return AddU64Feature(feature, 1u);
}

bool PerfFileWriter::AddU64Feature(FEATURE feature, uint64_t v)
{
    HLOGV("add feature '%s' uint64_t '%" PRIu64 "'",
          PerfFileSection::GetFeatureName(feature).c_str(), v);
    featureSections_.emplace_back(std::make_unique<PerfFileSectionU64>(feature, v));

    // update header feature bits
    header_.features[(int)feature / BITS_IN_BYTE] |= 1 << ((int)feature % BITS_IN_BYTE); // bit
    return true;
}

bool PerfFileWriter::AddSymbolsFeature(
    const std::vector<std::unique_ptr<SymbolsFile>> &symbolsFiles)
{
    const FEATURE feature = FEATURE::HIPERF_FILES_SYMBOL;
    HLOGV("add feature symbolsFiles %zu", symbolsFiles.size());
    std::vector<SymbolFileStruct> symbolFileStructs {};
    for (auto &symbolsFile : symbolsFiles) {
        if (symbolsFile->SymbolsLoaded()) {
            auto &symbolsFileStruct = symbolFileStructs.emplace_back();
            symbolsFile->ExportSymbolToFileFormat(symbolsFileStruct);
        }
    }
    featureSections_.emplace_back(
        std::make_unique<PerfFileSectionSymbolsFiles>(feature, symbolFileStructs));
    // update header feature bits
    header_.features[(int)feature / BITS_IN_BYTE] |= 1 << ((int)feature % BITS_IN_BYTE); // bit
    return true;
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
