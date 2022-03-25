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
#include "hiperf_libreport.h"

#if !is_ohos
// this is not good enough
#include <../musl/include/elf.h>
#endif

#include "debug_logger.h"
#include "elf_parser.h"
#include "perf_file_reader.h"
#include "subcommand_dump.h"
#include "subcommand_report.h"
#include "utilities.h"

using namespace OHOS::Developtools::HiPerf;
using namespace OHOS::Developtools::HiPerf::ELF;
extern "C" {
// this is a demo function
const char *EchoLoopBack(const char *echo)
{
    HLOGD("EchoLoopBack:%s\n", echo);
    return echo;
}

int SetDebug(bool enable)
{
#ifdef HIPERF_DEBUG
    if (enable) {
        DebugLogger::GetInstance()->SetLogLevel(LEVEL_VERBOSE);
        DebugLogger::GetInstance()->Disable(false);
    } else {
        DebugLogger::GetInstance()->Disable(true);
    }
#endif
    return 0;
}

int Report(const char *perfFile, const char *reportFile, const char *reportOptions)
{
    std::unique_ptr<SubCommandReport> report = std::make_unique<SubCommandReport>();
    HLOGD("report the file %s to %s\n", perfFile, reportFile);
    if (perfFile != nullptr and reportFile != nullptr) {
        std::vector<std::string> args;
        args.emplace_back("-i");
        args.emplace_back(perfFile);
        args.emplace_back("-o");
        args.emplace_back(reportFile);
        if (reportOptions != nullptr) {
            std::vector<std::string> options = StringSplit(reportOptions);
            for (std::string &option : options) {
                args.emplace_back(option);
            }
        }
        if (report->ParseOption(args)) {
            return report->OnSubCommand(args) ? 0 : -1;
        }
    } else {
        printf("path is nullptr\n");
    }
    return -1;
}

int ReportJson(const char *perfFile, const char *reportFile)
{
    return ReportUnwindJson(perfFile, reportFile, nullptr);
}

int ReportUnwindJson(const char *perfFile, const char *reportFile, const char *symbolsDir)
{
    std::unique_ptr<SubCommandReport> report = std::make_unique<SubCommandReport>();
    HLOGD("report the file %s to json file %s symbols from %s\n", perfFile, reportFile, symbolsDir);
    if (perfFile != nullptr and reportFile != nullptr) {
        std::vector<std::string> args;
        args.emplace_back("-i");
        args.emplace_back(perfFile);
        args.emplace_back("-o");
        args.emplace_back(reportFile);
        args.emplace_back("--json");
        if (symbolsDir != nullptr) {
            args.emplace_back("--symbol-dir");
            args.emplace_back(symbolsDir);
        }
        if (report->ParseOption(args)) {
            return report->OnSubCommand(args) ? 0 : -1;
        }
    }
    return -1;
}

static std::unique_ptr<PerfFileReader> GetReader(const std::string &fileName)
{
    // check if file exist
    if (access(fileName.c_str(), F_OK) != 0) {
        // file not exists
        printf("Can not access data file %s\n", fileName.c_str());
        return nullptr;
    }

    auto reader = PerfFileReader::Instance(fileName);
    if (reader == nullptr) {
        printf("%s format not correct\n", fileName.c_str());
        return nullptr;
    } else {
        return reader;
    }
}

const char *ReportGetSymbolFiles(const char *perfFile)
{
    HLOGD("report the file %s for symbols \n", perfFile);
    static std::string result; // statci for hold the c_str buffer
    result.clear();
    if (perfFile == nullptr) {
        return result.c_str();
    }

    auto reader = GetReader(perfFile);
    if (reader == nullptr) {
        return result.c_str();
    }
    // found symbols in file
    reader->ReadFeatureSection();
    for (auto &featureSection : reader->GetFeatureSections()) {
        if (featureSection.get()->featureId_ == FEATURE::HIPERF_FILES_SYMBOL) {
            const PerfFileSectionSymbolsFiles *sectionSymbolsFiles =
                static_cast<const PerfFileSectionSymbolsFiles *>(featureSection.get());
            auto it = sectionSymbolsFiles->symbolFileStructs_.begin();
            while (it != sectionSymbolsFiles->symbolFileStructs_.end()) {
                if (it != sectionSymbolsFiles->symbolFileStructs_.begin()) {
                    result.append(",");
                }
                HLOGD("%s buildId:%s\n", it->filePath_.c_str(), it->buildId_.c_str());
                result.append("[");
                result.append(it->filePath_.c_str());
                result.append(",");
                result.append(it->buildId_.c_str());
                result.append("]");
                it++;
            }
        }
    }
    return result.c_str();
}

static std::string CovertByteBufferToHexString(const unsigned char *buffer, size_t size)
{
    if (buffer == nullptr) {
        HLOGE("param is null");
        return "";
    }
    std::string descString;
    size_t i = 0;
    while (i < size) {
        descString.append(ToHex(buffer[i]));
        i++; // move to next char
    }
    return descString;
}

static std::string ElfGetBuildId(const unsigned char *buffer, size_t size)
{
    if (buffer == nullptr) {
        HLOGE("buffer is nullptr");
        return EMPTY_STRING;
    }
    const unsigned char *end = buffer + size;
    HLOGV("size:%zu", size);
    static constexpr const int elfNoteSectionLens = sizeof(uint32_t) * 3;

    while (end - buffer >= elfNoteSectionLens) {
        uint32_t namesz;
        uint32_t descsz;
        uint32_t type;
        CopyFromBufferAndMove(buffer, &namesz);
        CopyFromBufferAndMove(buffer, &descsz);
        CopyFromBufferAndMove(buffer, &type);

        // to ensure 4-byte alignment for the descriptor.
        constexpr const int elfNoteSectionNameAlign = 4;

        namesz = RoundUp(namesz, elfNoteSectionNameAlign);
        descsz = RoundUp(descsz, elfNoteSectionNameAlign);
        HLOGD("namesz:%u descsz:%u type:%u", namesz, descsz, type);

        // size enough ?
        if (buffer >= end) {
            return EMPTY_STRING;
        }
        if (type == NT_GNU_BUILD_ID) {
            char name[namesz + 1];
            CopyFromBufferAndMove(buffer, &name[0], namesz);
            name[namesz] = 0;
            HLOGD("found buildid name:%s", name);
            if (strcmp(name, ELF_NOTE_GNU) == 0) {
                std::string descString = CovertByteBufferToHexString(buffer, descsz);
                HLOGD("found buildid:%s", descString.c_str());
                return descString;
            } else {
                // next
                buffer += descsz;
            }
        } else {
            // next
            buffer += namesz + descsz;
        }
    }
    return EMPTY_STRING; // found nothing
}

const char *ReportGetBuildId(const char *elfPath)
{
    static std::string buildId; // statci for hold the c_str buffer
    buildId.clear();
    std::unique_ptr<ElfFile> elfFile = ElfFile::MakeUnique(elfPath);
    if (elfFile == nullptr) {
        printf("elf '%s' load failed\n", elfPath);
    } else {
        for (const auto &shdrPair : elfFile->shdrs_) {
            const auto &shdr = shdrPair.second;
            if (shdr->secType_ == SHT_NOTE) {
                const unsigned char *data = elfFile->GetSectionData(shdr->secIndex_);
                buildId = ElfGetBuildId(data, shdr->secSize_);
                if (!buildId.empty()) {
                    HLOGD("%s buildId:%s\n", elfPath, buildId.c_str());
                    return buildId.c_str();
                }
            }
        }
        printf("elf '%s' have not found buildId\n", elfPath);
    }
    return buildId.c_str();
}

const char *ReportGetElfArch(const char *elfPath)
{
    const char *machineName = "unknown";
    static std::string buildId; // statci for hold the c_str buffer
    std::unique_ptr<ElfFile> elfFile = ElfFile::MakeUnique(elfPath);
    static std::string result; // statci for hold the c_str buffer
    result.clear();
    if (elfFile == nullptr or elfFile->ehdr_ == nullptr) {
        printf("elf '%s' load failed\n", elfPath);
    } else {
        switch (elfFile->ehdr_->machine_) {
            case EM_ARM:
                machineName = "arm";
                break;
            case EM_AARCH64:
                machineName = "arm64";
                break;
            case EM_386:
                machineName = "x86";
                break;
            case EM_X86_64:
                machineName = "x86_64";
                break;
            default:
                machineName = "unknown";
                break;
        }
        HLOGD("elf '%s' mache value is '%x'(%s) \n", elfPath, elfFile->ehdr_->machine_,
              machineName);
    }
    return machineName;
}

int Dump(const char *fileName)
{
    std::unique_ptr<SubCommandDump> dump = std::make_unique<SubCommandDump>();
    HLOGD("dump the file %s\n", fileName);
    if (fileName != nullptr) {
        std::vector<std::string> args;
        args.emplace_back(fileName);
        if (dump->ParseOption(args)) {
            return dump->OnSubCommand(args) ? 0 : -1;
        }
    }
    return -1;
}

} // extern "C"
