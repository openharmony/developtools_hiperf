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
#include "perf_file_reader.h"

#include <bitset>
#include <cinttypes>
#include <cstdlib>
#include <memory>

#include <sys/stat.h>
#include <unistd.h>

#include "utilities.h"

using namespace std::chrono;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
const int FETURE_MAX = 256;
const int SIZE_FETURE_COUNT = 8;

std::unique_ptr<PerfFileReader> PerfFileReader::Instance(const std::string &fileName)
{
    std::string resolvedPath = CanonicalizeSpecPath(fileName.c_str());
    FILE *fp = fopen(resolvedPath.c_str(), "rb");
    if (fp == nullptr) {
        HLOGE("fail to open file %s", fileName.c_str());
        return nullptr;
    }

    std::unique_ptr<PerfFileReader> reader = std::make_unique<PerfFileReader>(fileName, fp);
    if (!reader->ReadFileHeader()) {
        // Fail to read header, maybe its compressed
        if (reader->IsGzipFile()) {
            fclose(fp);
            reader->fp_ = nullptr;

            if (!UncompressFile(fileName, ".perf.data")) {
                HLOGE("Fail to UncompressFile(%s)", fileName.c_str());
                return nullptr;
            }

            // open the uncompressed hidden file .perf.data
            FILE *fp2 = fopen(".perf.data", "rb");
            if (fp2 == nullptr) {
                HLOGE("fail to open uncompressed file .perf.data");
                return nullptr;
            }

            reader->fp_ = fp2;
            reader->compressData_ = true;

            if (!reader->ReadFileHeader()) {
                HLOGE("fail to read header of file .perf.data");
                return nullptr;
            }
            goto end;
        }
        return nullptr;
    }
end:
    if (!reader->ReadAttrSection()) {
        return nullptr;
    }
    return reader;
}

PerfFileReader::PerfFileReader(const std::string &fileName, FILE *fp) : fp_(fp), fileName_(fileName)
{
    featureSectionOffset_ = 0;
    struct stat fileStat;
    if (fp != nullptr) {
        if (fstat(fileno(fp), &fileStat) != -1 and fileStat.st_size > 0) {
            fileSize_ = fileStat.st_size;
        }
    }
}

PerfFileReader::~PerfFileReader()
{
    // if file was not closed properly
    if (fp_ != nullptr) {
        fclose(fp_);
        fp_ = nullptr;
    }

    // remove the uncompressed .perf.data
    if (compressData_) {
        if (remove(".perf.data") != 0) {
            HLOGE("Fail to remove uncompressed file .perf.data");
            perror("Fail to remove temp file");
        }
    }
}

bool PerfFileReader::IsValidDataFile()
{
    return (memcmp(header_.magic, PERF_MAGIC, sizeof(header_.magic)) == 0);
}

bool PerfFileReader::IsGzipFile()
{
    return header_.magic[0] == '\x1f' and header_.magic[1] == '\x8b';
}

bool PerfFileReader::ReadFileHeader()
{
    if (Read(&header_, sizeof(header_))) {
        dataSectionSize_ = header_.data.size;
        if (IsValidDataFile()) {
            featureSectionOffset_ = header_.data.offset + header_.data.size;
            for (int i = 0; i < FETURE_MAX / SIZE_FETURE_COUNT; i++) {
                std::bitset<SIZE_FETURE_COUNT> features(header_.features[i]);
                for (int j = 0; j < SIZE_FETURE_COUNT; j++) {
                    if (features.test(j)) {
                        features_.emplace_back((FEATURE)(((uint64_t)i) * SIZE_FETURE_COUNT + j));
                    }
                }
            }
            return true;
        }
    }
    return false;
}

bool PerfFileReader::ReadAttrSection()
{
    if (header_.attrSize != sizeof(perf_file_attr)) {
        // 4.19 and 5.1 use diff size , 128 vs 136
        HLOGW("attr size %" PRId64 " doesn't match expected size %zu", header_.attrSize,
              sizeof(perf_file_attr));
    }

    int attrCount = header_.attrs.size / header_.attrSize;
    if (attrCount == 0) {
        HLOGE("no attr in file");
        return false;
    }
    if (fseek(fp_, header_.attrs.offset, SEEK_SET) != 0) {
        HLOGE("fseek() failed");
        return false;
    }
    for (int i = 0; i < attrCount; ++i) {
        std::vector<char> buf(header_.attrSize);
        if (!Read(buf.data(), buf.size())) {
            return false;
        }
        // size of perf_event_attr change between different linux kernel versions.
        // can not memcpy to perf_file_attr as a whole
        perf_file_attr attr {};
        size_t attr_size = header_.attrSize - sizeof(attr.ids);

        // If the size is smaller, you can use a pointer to point directly.
        // Our UAPI is 4.19. is less than 5.1
        if (sizeof(perf_event_attr) > header_.attrSize) {
            HLOGE("size not match, ptr of perf_event_attr maybe overfollow %zu vs %zu",
                  sizeof(perf_event_attr), attr_size);
        }

        attr.attr = *(reinterpret_cast<perf_event_attr *>(&buf[0]));
        attr.ids = *(reinterpret_cast<perf_file_section *>(&buf[attr_size]));
        vecAttr_.push_back(attr);
    }

    // read ids for attr
    for (size_t i = 0; i < vecAttr_.size(); ++i) {
        std::vector<uint64_t> ids;
        if (!ReadIdsForAttr(vecAttr_[i], &ids)) {
            return false;
        }
        vecAttrIds_.push_back(ids);

        // map ids to attr index
        for (auto id : ids) {
            mapId2Attr_[id] = i;
        }
    }

    return true;
}

bool PerfFileReader::ReadIdsForAttr(const perf_file_attr &attr, std::vector<uint64_t> *ids)
{
    if (attr.ids.size > 0) {
        size_t count = attr.ids.size / sizeof(uint64_t);
        if (fseek(fp_, attr.ids.offset, SEEK_SET) != 0) {
            HLOGE("fseek() failed");
            return false;
        }

        ids->resize(count);
        if (!Read(ids->data(), attr.ids.size)) {
            return false;
        }
    }
    return true;
}

std::vector<AttrWithId> PerfFileReader::GetAttrSection() const
{
    std::vector<AttrWithId> result(vecAttr_.size());

    for (size_t i = 0; i < vecAttr_.size(); ++i) {
        result[i].attr = vecAttr_[i].attr;
        result[i].ids = vecAttrIds_[i];
    }
    return result;
}

bool PerfFileReader::ReadDataSection(ProcessRecordCB &callback)
{
    if (fseek(fp_, header_.data.offset, SEEK_SET) != 0) {
        HLOGE("fseek() failed");
        return false;
    }

    HLOGD("dataSection_ at offset %" PRId64 " + %" PRId64 "", header_.data.offset,
          header_.data.size);

    if (!ReadRecord(callback)) {
        printf("some record format is error!\n");
        return false;
    };

#ifdef HIPERF_DEBUG_TIME
    printf("readRecordTime: %" PRId64 " ms\n",
           duration_cast<milliseconds>(readRecordTime_).count());
    printf("readCallbackTime: %" PRId64 " ms\n",
           duration_cast<milliseconds>(readCallbackTime_).count());
#endif
    return dataSectionSize_ == 0;
}

const perf_event_attr *PerfFileReader::GetDefaultAttr()
{
    if (vecAttr_.empty())
        return nullptr;

    return &(vecAttr_[0].attr);
}

bool PerfFileReader::ReadRecord(ProcessRecordCB &callback)
{
#ifdef HIPERF_DEBUG_TIME
    const auto startReadTime = steady_clock::now();
#endif
    // record size can not exceed 64K
    HIPERF_BUF_ALIGN uint8_t buf[RECORD_SIZE_LIMIT];
    // diff with reader
    uint64_t remainingSize = header_.data.size;
    size_t recordNumber = 0;
    while (remainingSize > 0) {
        if (remainingSize < sizeof(perf_event_header)) {
            HLOGW("not enough sizeof perf_event_header");
            return false;
        } else if (!Read(buf, sizeof(perf_event_header))) {
            HLOGW("read perf_event_header failed.");
            return false;
        } else {
            perf_event_header *header = reinterpret_cast<perf_event_header *>(buf);
            if (header->size > sizeof(buf)) {
                HLOGE("read record header size error %hu", header->size);
                return false;
            }
            if (remainingSize >= header->size) {
                size_t headerSize = sizeof(perf_event_header);
                if (Read(buf + headerSize, header->size - headerSize)) {
                    uint8_t *data = buf;
                    std::unique_ptr<PerfEventRecord> record = GetPerfEventRecord(
                        static_cast<perf_event_type>(header->type), data, *GetDefaultAttr());
                    // unknown record , break the process
                    if (!record) {
                        return false;
                    } else {
                        HLOGV("record type %u", record->GetType());
                    }
                    remainingSize -= header->size;
#ifdef HIPERF_DEBUG_TIME
                    const auto startCallbackTime = steady_clock::now();
#endif
                    // call callback to process, then destroy record
                    callback(std::move(record));
                    recordNumber++;
#ifdef HIPERF_DEBUG_TIME
                    readCallbackTime_ +=
                        duration_cast<microseconds>(steady_clock::now() - startCallbackTime);
#endif
                } else {
                    HLOGE("read record data size failed %zu", header->size - headerSize);
                    return false;
                }
            } else {
                HLOGE("not enough header->size.");
                return false;
            }
        }
    }
    HLOGD("read back %zu records", recordNumber);
#ifdef HIPERF_DEBUG_TIME
    readRecordTime_ += duration_cast<microseconds>(steady_clock::now() - startReadTime);
#endif
    return true;
}

bool PerfFileReader::Read(void *buf, size_t len)
{
    if (buf == nullptr || len == 0) {
        HLOG_ASSERT(buf != nullptr);
        HLOG_ASSERT(len > 0);
        return false;
    }

    if (fread(buf, len, 1, fp_) != 1) {
        printf("failed to read file: %d", errno);
        return false;
    }
    return true;
}

const perf_file_header &PerfFileReader::GetHeader() const
{
    return header_;
}

bool PerfFileReader::Read(char *buf, uint64_t offset, size_t len)
{
    if (buf == nullptr || len == 0) {
        HLOG_ASSERT(buf != nullptr);
        HLOG_ASSERT(len > 0);
        return false;
    }
    if (fseek(fp_, offset, SEEK_SET) != 0) {
        HLOGE("fseek() failed");
        return false;
    }

    if (fread(buf, len, 1, fp_) != 1) {
        printf("failed to read file: %d", errno);
        return false;
    }
    HLOGM("offset %" PRIx64 " len %zu buf %x %x %x %x", offset, len, buf[0], buf[1], buf[2],
          buf[3]);
    return true;
}
const std::vector<FEATURE> &PerfFileReader::GetFeatures() const
{
    return features_;
}

const std::vector<std::unique_ptr<PerfFileSection>> &PerfFileReader::GetFeatureSections() const
{
    return perfFileSections_;
}

const std::string PerfFileReader::GetFeatureString(const FEATURE feature) const
{
    std::string featureName = PerfFileSection::GetFeatureName(feature);
    HLOGV("GetFeatureSection %s", featureName.c_str());
    if (!IsFeatrureStringSection(feature)) {
        HLOGV("not a string feature: %s", featureName.c_str());
    } else {
        const PerfFileSection *featureSection = GetFeatureSection(feature);
        if (featureSection != nullptr) {
            const PerfFileSectionString *sectionString =
                static_cast<const PerfFileSectionString *>(featureSection);
            return sectionString->toString();
        } else {
            HLOGV("have not found: %s", featureName.c_str());
        }
    }
    return EMPTY_STRING;
}

const PerfFileSection *PerfFileReader::GetFeatureSection(FEATURE feature) const
{
    HLOGV("enter");
    for (auto const &it : perfFileSections_) {
        HLOGV("perfFileSections %p", it.get());
        if (it->featureId_ == feature) {
            return it.get();
        }
    }
    return nullptr;
}

bool PerfFileReader::ReadFeatureSection()
{
    uint64_t featureSectionOffsetRead = featureSectionOffset_;
    HLOGV(" ReadDataSection data offset '0x%" PRIx64 " ", featureSectionOffset_);

    for (FEATURE feature : features_) {
        perf_file_section sectionHeader;
        if (!Read((char *)&sectionHeader, featureSectionOffsetRead, sizeof(sectionHeader))) {
            // read failed ??
            printf("file format not correct. featureSectionOffsetRead '0x%" PRIx64 "\n",
                   featureSectionOffsetRead);
            return false;
        }

        HLOGV("process feature %d:%s", feature, PerfFileSection::GetFeatureName(feature).c_str());
        HLOGV(" sectionHeader -> read offset '0x%" PRIx64 " size '0x%" PRIx64 "'",
              sectionHeader.offset, sectionHeader.size);
        if (sectionHeader.size == 0 or sectionHeader.size > fileSize_) {
            HLOGE("sectionHeader.size %" PRIu64 " is not correct", sectionHeader.size);
            return false;
        }

        std::vector<char> buf(sectionHeader.size);
        if (!Read(&buf[0], sectionHeader.offset, buf.size())) {
            // read failed ??
            printf("file format not correct. featureSectionDataOffset '0x%" PRIx64 "\n",
                   sectionHeader.offset);
            return false;
        }
        if (IsFeatrureStringSection(feature)) {
            perfFileSections_.emplace_back(
                std::make_unique<PerfFileSectionString>(feature, (char *)&buf[0], buf.size()));
        } else if (feature == FEATURE::HIPERF_FILES_SYMBOL) {
            perfFileSections_.emplace_back(std::make_unique<PerfFileSectionSymbolsFiles>(
                feature, (char *)&buf[0], buf.size()));
        } else if (feature == FEATURE::EVENT_DESC) {
            perfFileSections_.emplace_back(
                std::make_unique<PerfFileSectionEventDesc>(feature, (char *)&buf[0], buf.size()));
        } else {
            HLOGW("still not imp how to process with feature %d", feature);
        }

        featureSectionOffsetRead += sizeof(sectionHeader); // next feaure
    }
    return true;
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
