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
#define HILOG_TAG "Dump"

#include "subcommand_dump.h"

#include <cerrno>
#include <cinttypes>
#include <cstring>
#include <iostream>
#include <memory>

#include "debug_logger.h"
#include "option.h"
#include "perf_event_record.h"
#include "perf_events.h"
#include "symbols_file.h"
#include "utilities.h"
#include "virtual_runtime.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
#define LEVEL1 (indent + 1)
#define LEVEL2 (indent + 2)
#define LEVEL3 (indent + 3)

bool SubCommandDump::CheckInputFile()
{
    if (!dumpFileName_.empty()) {
        if (elfFileName_.empty() && protobufDumpFileName_.empty()) {
            return true;
        }
    } else if (!elfFileName_.empty()) {
        if (protobufDumpFileName_.empty()) {
            return true;
        }
    } else if (!protobufDumpFileName_.empty()) {
        return true;
    } else { // all is empty
        dumpFileName_ = DEFAULT_DUMP_FILENAME;
        return true;
    }

    printf("options conflict, please check usage\n");
    return false;
}

bool SubCommandDump::ParseOption(std::vector<std::string> &args)
{
    HLOGV("enter");

    if (!Option::GetOptionValue(args, "--head", dumpHeader_)) {
        HLOGD("get option --head failed");
        return false;
    }
    if (!Option::GetOptionValue(args, "-f", dumpFeatures_)) {
        HLOGD("get option -f failed");
        return false;
    }
    if (!Option::GetOptionValue(args, "-d", dumpData_)) {
        HLOGD("get option -d failed");
        return false;
    }
    if (!Option::GetOptionValue(args, "--sympath", dumpSymbolsPaths_)) {
        HLOGD("get option --sympath failed");
        return false;
    }
    if (!Option::GetOptionValue(args, "--elf", elfFileName_)) {
        HLOGD("get option --elf failed");
        return false;
    }
#if HAVE_PROTOBUF
    if (!Option::GetOptionValue(args, "--proto", protobufDumpFileName_)) {
        HLOGD("get option --proto failed");
        return false;
    }
#endif
    if (!Option::GetOptionValue(args, "--export", exportSampleIndex_)) {
        HLOGD("get option --export failed");
        return false;
    }

    if (dumpHeader_ || dumpFeatures_ || dumpData_) {
        dumpAll_ = false;
    }

    if (args.size() > 1) {
        printf("unknown option %s\n", args[0].c_str());
        return false;
    }
    if (args.size() == 1) {
        dumpFileName_ = args[0];
        args.clear();
    }

    return CheckInputFile();
}

SubCommandDump::~SubCommandDump()
{
    SymbolsFile::onRecording_ = true; // back to default for UT
}

bool SubCommandDump::OnSubCommand(std::vector<std::string> &args)
{
    HLOGV("enter");

    if (!elfFileName_.empty()) {
        return DumpElfFile();
    }

#if HAVE_PROTOBUF
    if (!protobufDumpFileName_.empty()) {
        return DumpProtoFile();
    }
#endif

    if (access(dumpFileName_.c_str(), F_OK) != 0) {
        printf("Can not access data file %s\n", dumpFileName_.c_str());
        return false;
    }
    // only one file should created
    HLOG_ASSERT_MESSAGE(reader_ == nullptr, " reader_ %p\n", reader_.get());
    reader_ = PerfFileReader::Instance(dumpFileName_);
    if (reader_ == nullptr) {
        HLOGE("HiperfFileReader::Instance(%s) return null", dumpFileName_.c_str());
        return false;
    }

    // any way tell symbols this is not on device
    SymbolsFile::onRecording_ = false;
    // we need unwind it (for function name match) even not give us path
    vr_.SetDisableUnwind(false);

    if (!dumpSymbolsPaths_.empty()) {
        // user give us path , we enable unwind
        if (!vr_.SetSymbolsPaths(dumpSymbolsPaths_)) {
            printf("Failed to set symbol path(%s)\n", VectorToString(dumpSymbolsPaths_).c_str());
            return false;
        }
    }

    if (dumpHeader_ || dumpAll_) {
        DumpPrintFileHeader(indent_);
        DumpAttrPortion(indent_);
    }

    if (dumpAll_ || dumpData_) {
        DumpDataPortion(indent_);
    }

    if (dumpFeatures_ || dumpAll_) {
        DumpFeaturePortion(indent_);
    }

    return true;
}

bool SubCommandDump::DumpElfFile()
{
    printf("dump elf: '%s'\n", elfFileName_.c_str());
    auto elf = SymbolsFile::CreateSymbolsFile(elfFileName_);
    if (!elf->LoadSymbols("")) {
        printf("load elf failed.\n");
        return false;
    } else {
        printf("load elf succeed.\n");
    }
    return true;
}
#if HAVE_PROTOBUF
bool SubCommandDump::DumpProtoFile()
{
    printf("dump protobuf file: '%s'\n", protobufDumpFileName_.c_str());
    protobufInputFileReader_ = std::make_unique<ReportProtobufFileReader>();
    if (!protobufInputFileReader_->Dump(protobufDumpFileName_)) {
        printf("load proto failed.\n");
        return false;
    }
    return true;
}
#endif

void SubCommandDump::PrintHeaderInfo(const int &indent)
{
    const perf_file_header &header = reader_->GetHeader();
    // magic
    PrintIndent(indent, "magic: ");
    for (size_t i = 0; i < sizeof(header.magic); ++i) {
        PrintIndent(indent, "%c", header.magic[i]);
    }
    PrintIndent(indent, "\n");
    PrintIndent(indent, "header_size: %" PRId64 "\n", header.size);
    if (header.size != sizeof(header)) {
        HLOGW("record file header size doesn't match");
    }
    PrintIndent(indent, "attr_size: %" PRId64 "\n", header.attrSize);
    if (header.attrSize != sizeof(perf_file_attr)) {
        HLOGW("attr size doesn't match");
    }
    // attr
    PrintIndent(indent, "attrs[file section]: offset %" PRId64 ", size %" PRId64 "\n",
                header.attrs.offset, header.attrs.size);
    // data
    PrintIndent(indent, "data[file section]: offset %" PRId64 ", size %" PRId64 "\n",
                header.data.offset, header.data.size);
    PrintIndent(indent, "event_types[file section]: offset %" PRId64 ", size %" PRId64 "\n",
                header.eventTypes.offset, header.eventTypes.size);
    // feature
    PrintIndent(indent,
                "adds_features[]: 0x%" PRIX64 " 0x%" PRIX64 " 0x%" PRIX64 " 0x%" PRIX64 "\n",
                *(reinterpret_cast<const uint64_t *>(&header.features[0])),
                *(reinterpret_cast<const uint64_t *>(&header.features[8])),
                *(reinterpret_cast<const uint64_t *>(&header.features[16])),
                *(reinterpret_cast<const uint64_t *>(&header.features[24])));
}

void SubCommandDump::DumpPrintFileHeader(int indent)
{
    // print header
    PrintHeaderInfo(indent);

    // print feature
    auto features = reader_->GetFeatures();
    for (auto feature : features) {
        PrintIndent(indent, "feature: %s\n", PerfFileSection::GetFeatureName(feature).c_str());
    }

    // read here , because we need found symbols
    reader_->ReadFeatureSection();

    SetDeviceArch(GetArchTypeFromUname(reader_->GetFeatureString(FEATURE::ARCH)));

    // found symbols in file
    for (auto &featureSection : reader_->GetFeatureSections()) {
        if (featureSection.get()->featureId_ == FEATURE::HIPERF_FILES_SYMBOL) {
            const PerfFileSectionSymbolsFiles *sectionSymbolsFiles =
                static_cast<const PerfFileSectionSymbolsFiles *>(featureSection.get());
            vr_.UpdateFromPerfData(sectionSymbolsFiles->symbolFileStructs_);
        }
    }
}

static std::map<int, std::string> g_sampleTypeNames = {
    {PERF_SAMPLE_IP, "ip"},
    {PERF_SAMPLE_TID, "tid"},
    {PERF_SAMPLE_TIME, "time"},
    {PERF_SAMPLE_ADDR, "addr"},
    {PERF_SAMPLE_READ, "read"},
    {PERF_SAMPLE_CALLCHAIN, "callchain"},
    {PERF_SAMPLE_ID, "id"},
    {PERF_SAMPLE_CPU, "cpu"},
    {PERF_SAMPLE_PERIOD, "period"},
    {PERF_SAMPLE_STREAM_ID, "stream_id"},
    {PERF_SAMPLE_RAW, "raw"},
    {PERF_SAMPLE_BRANCH_STACK, "stack"},
    {PERF_SAMPLE_REGS_USER, "regs_user"},
    {PERF_SAMPLE_STACK_USER, "stack_user"},
    {PERF_SAMPLE_WEIGHT, "weight"},
    {PERF_SAMPLE_DATA_SRC, "data_src"},
    {PERF_SAMPLE_IDENTIFIER, "identifier"},
    {PERF_SAMPLE_TRANSACTION, "transaction"},
    {PERF_SAMPLE_REGS_INTR, "reg_intr"},
};

void SubCommandDump::DumpSampleType(uint64_t sampleType, int indent)
{
    std::string names;
    for (auto &pair : g_sampleTypeNames) {
        if (sampleType & pair.first) {
            if (!names.empty()) {
                names.append(",");
            }
            names.append(pair.second);
        }
    }
    PrintIndent(LEVEL1, "sample_type names: %s\n", names.c_str());
}

void SubCommandDump::DumpPrintEventAttr(const perf_event_attr &attr, int indent)
{
    PrintIndent(indent, "event_attr: \n");

    PrintIndent(LEVEL1, "type %u, size %u, config %llu\n", attr.type, attr.size, attr.config);

    if (attr.freq != 0) {
        PrintIndent(LEVEL1, "sample_freq %llu\n", attr.sample_freq);
    } else {
        PrintIndent(LEVEL1, "sample_period %llu\n", attr.sample_period);
    }

    PrintIndent(LEVEL1, "sample_type (0x%llx) \n", attr.sample_type);
    DumpSampleType(attr.sample_type, indent);

    PrintIndent(LEVEL1, "read_format (0x%llx) \n", attr.read_format);

    PrintIndent(LEVEL1, "disabled %u, inherit %u, pinned %u, exclusive %u\n", attr.disabled,
                attr.inherit, attr.pinned, attr.exclusive);

    PrintIndent(LEVEL1, "exclude_user %u, exclude_kernel %u, exclude_hv %u, exclude_idle %u\n",
                attr.exclude_user, attr.exclude_kernel, attr.exclude_hv, attr.exclude_idle);

    PrintIndent(LEVEL1, "mmap %u, mmap2 %u, comm %u, comm_exec %u, freq %u\n", attr.mmap,
                attr.mmap2, attr.comm, attr.comm_exec, attr.freq);

    PrintIndent(LEVEL1, "inherit_stat %u, enable_on_exec %u, task %u, use_clockid %u\n",
                attr.inherit_stat, attr.enable_on_exec, attr.task, attr.use_clockid);

    PrintIndent(LEVEL1, "watermark %u, precise_ip %u, mmap_data %u, clockid %d\n", attr.watermark,
                attr.precise_ip, attr.mmap_data, attr.clockid);

    PrintIndent(LEVEL1, "sample_id_all %u, exclude_host %u, exclude_guest %u\n", attr.sample_id_all,
                attr.exclude_host, attr.exclude_guest);
    PrintIndent(LEVEL1, "branch_sample_type 0x%llx\n", attr.branch_sample_type);
    PrintIndent(LEVEL1, "exclude_callchain_kernel %u, exclude_callchain_user %u\n",
                attr.exclude_callchain_kernel, attr.exclude_callchain_user);
    PrintIndent(LEVEL1, "sample_regs_user 0x%llx\n", attr.sample_regs_user);
    PrintIndent(LEVEL1, "sample_stack_user 0x%x\n", attr.sample_stack_user);
}

void SubCommandDump::DumpAttrPortion(int indent)
{
    attrIds_ = reader_->GetAttrSection();
    for (size_t i = 0; i < attrIds_.size(); ++i) {
        const AttrWithId &attr = attrIds_[i];
        PrintIndent(indent, "attr %zu:\n", i + 1);
        DumpPrintEventAttr(attr.attr, indent_ + 1);
        if (!attr.ids.empty()) {
            PrintIndent(indent, "  ids:");
            for (const auto &id : attr.ids) {
                PrintIndent(indent, " %" PRId64, id);
            }
            PrintIndent(indent, "\n");
        }
    }
}

void SubCommandDump::ExprotUserStack(const PerfRecordSample &recordSample)
{
    if (recordSample.data_.reg_nr > 0 and recordSample.data_.dyn_size > 0) {
        // <pid>_<tid>_user_regs_<time>
        std::string userRegs =
            StringPrintf("hiperf_%d_%d_user_regs_%zu.dump", recordSample.data_.pid,
                         recordSample.data_.tid, exportSampleIndex_);
        std::string resolvedPath = CanonicalizeSpecPath(userRegs.c_str());
        std::unique_ptr<FILE, decltype(&fclose)> fpUserRegs(fopen(resolvedPath.c_str(), "wb"), fclose);
        fwrite(recordSample.data_.user_regs, sizeof(u64), recordSample.data_.reg_nr,
               fpUserRegs.get());

        std::string userData =
            StringPrintf("hiperf_%d_%d_user_data_%zu.dump", recordSample.data_.pid,
                         recordSample.data_.tid, exportSampleIndex_);
        std::string resolvePath = CanonicalizeSpecPath(userData.c_str());
        std::unique_ptr<FILE, decltype(&fclose)> fpUserData(fopen(resolvePath.c_str(), "wb"), fclose);
        fwrite(recordSample.data_.stack_data, sizeof(u8), recordSample.data_.dyn_size,
               fpUserData.get());
    }
}

void SubCommandDump::ExprotUserData(std::unique_ptr<PerfEventRecord> &record)
{
    if (record->GetType() == PERF_RECORD_SAMPLE) {
        if (currectSampleIndex_++ != exportSampleIndex_) {
            return;
        }
        PerfRecordSample *recordSample = static_cast<PerfRecordSample *>(record.get());
        ExprotUserStack(*recordSample);

        std::string userData =
            StringPrintf("hiperf_%d_%d_sample_record_%zu_%" PRIu64 ".dump", recordSample->data_.pid,
                         recordSample->data_.tid, exportSampleIndex_, recordSample->data_.time);
        std::string resolvedPath = CanonicalizeSpecPath(userData.c_str());
        std::unique_ptr<FILE, decltype(&fclose)> fpUserData(fopen(resolvedPath.c_str(), "wb"), fclose);
        std::vector<u8> buf(RECORD_SIZE_LIMIT);
        if (!recordSample->GetBinary(buf)) {
            HLOGE("export user sample data failed");
            return;
        }
        fwrite(buf.data(), sizeof(u8), recordSample->GetSize(), fpUserData.get());

        HLOGD("export user data index %d time %llu", exportSampleIndex_, recordSample->data_.time);
    }
}
void SubCommandDump::DumpCallChain(int indent, std::unique_ptr<PerfRecordSample> &sample)
{
    PrintIndent(indent, "\n callchain: %zu\n", sample->callFrames_.size());
    if (sample->callFrames_.size() > 0) {
        indent += LEVEL1;
        for (auto frameIt = sample->callFrames_.begin(); frameIt != sample->callFrames_.end();
             frameIt++) {
            PrintIndent(indent, "%02zd:%s\n", std::distance(frameIt, sample->callFrames_.end()),
                        frameIt->ToSymbolString().c_str());
        }
    }
}

void SubCommandDump::DumpDataPortion(int indent)
{
    int recordCount = 0;
    auto record_callback = [&](std::unique_ptr<PerfEventRecord> record) {
        if (record == nullptr) {
            // return false in callback can stop the read process
            return false;
        }

        // for UT
        if (exportSampleIndex_ > 0) {
            ExprotUserData(record);
        }

        // tell process tree what happend for rebuild symbols
        vr_.UpdateFromRecord(*record);

        recordCount++;
        record->Dump(indent);

        if (record->GetType() == PERF_RECORD_SAMPLE) {
            std::unique_ptr<PerfRecordSample> sample(
                static_cast<PerfRecordSample *>(record.release()));
            DumpCallChain(indent, sample);
        }

        return true;
    };

    reader_->ReadDataSection(record_callback);

    PrintIndent(indent, "\n ======= there are %d records ======== \n", recordCount);
}

void SubCommandDump::PrintSymbolFile(const int &indent, const SymbolFileStruct &symbolFileStruct)
{
    PrintIndent(LEVEL2, "filePath:%s\n", symbolFileStruct.filePath_.c_str());
    PrintIndent(LEVEL2, "symbolType:%u\n", symbolFileStruct.symbolType_);
    PrintIndent(LEVEL2, "minExecAddr:0x%" PRIx64 "\n", symbolFileStruct.textExecVaddr_);
    PrintIndent(LEVEL2, "minExecAddrFileOffset:0x%08" PRIx64 "\n",
                symbolFileStruct.textExecVaddrFileOffset_);
    if (!symbolFileStruct.buildId_.empty()) {
        PrintIndent(LEVEL2, "buildId:'%s'\n", symbolFileStruct.buildId_.c_str());
    }
    PrintIndent(LEVEL2, "symbol number: %zu\n", symbolFileStruct.symbolStructs_.size());
    int symbolid = 0;
    for (auto &symbolStruct : symbolFileStruct.symbolStructs_) {
        PrintIndent(LEVEL3, "%05d [0x%016" PRIx64 "@0x%08x]  %s\n", symbolid, symbolStruct.vaddr_,
                    symbolStruct.len_, symbolStruct.symbolName_.c_str());
        symbolid++;
    }
}

void SubCommandDump::PrintFeatureEventdesc(int indent,
                                           const PerfFileSectionEventDesc &sectionEventdesc)
{
    PrintIndent(LEVEL2, "Event descriptions: %zu\n", sectionEventdesc.eventDesces_.size());
    for (size_t i = 0; i < sectionEventdesc.eventDesces_.size(); i++) {
        const AttrWithId &desc = sectionEventdesc.eventDesces_[i];
        PrintIndent(LEVEL2, "event name[%zu]: %s ids: %s\n", i, desc.name.c_str(),
                    VectorToString(desc.ids).c_str());

        // attr is duplicated the attrs section
    }
    PrintIndent(LEVEL2, "\n");
}

void SubCommandDump::DumpFeaturePortion(int indent)
{
    PrintIndent(indent, "\n ==== features ====\n");
    auto features = reader_->GetFeatures();
    for (auto feature : features) {
        PrintIndent(LEVEL1, "feature %d:%s\n", feature,
                    PerfFileSection::GetFeatureName(feature).c_str());
    }

    const auto &featureSections = reader_->GetFeatureSections();
    HLOGV("featureSections: %zu ", featureSections.size());

    PrintIndent(indent, "\n ==== feature sections ====\n");

    for (auto &featureSection : featureSections) {
        PrintIndent(LEVEL1, "feature %d:%s content: \n", featureSection.get()->featureId_,
                    PerfFileSection::GetFeatureName(featureSection.get()->featureId_).c_str());
        if (reader_->IsFeatrureStringSection(featureSection.get()->featureId_)) {
            const PerfFileSectionString *sectionString =
                static_cast<const PerfFileSectionString *>(featureSection.get());
            PrintIndent(LEVEL2, "%s\n", sectionString->toString().c_str());
            continue;
        } else if (featureSection.get()->featureId_ == FEATURE::EVENT_DESC) {
            PrintFeatureEventdesc(
                indent, *static_cast<const PerfFileSectionEventDesc *>(featureSection.get()));
            continue;
        }

        const PerfFileSectionSymbolsFiles *sectionSymbolsFiles =
            static_cast<const PerfFileSectionSymbolsFiles *>(featureSection.get());
        if (sectionSymbolsFiles != nullptr) {
            PrintIndent(LEVEL2, "SymbolFiles:%zu\n",
                        sectionSymbolsFiles->symbolFileStructs_.size());

            int fileid = 0;
            for (auto &symbolFileStruct : sectionSymbolsFiles->symbolFileStructs_) {
                PrintIndent(LEVEL2, "\n");
                PrintIndent(LEVEL2, "fileid:%d\n", fileid);
                fileid++;
                // symbol file info
                PrintSymbolFile(indent, symbolFileStruct);
            }
            continue;
        }

        PrintIndent(LEVEL2, "not support dump this feature.\n");
    }
}

bool SubCommandDump::RegisterSubCommandDump()
{
    HLOGV("enter");
    return SubCommand::RegisterSubCommand("dump", std::make_unique<SubCommandDump>());
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
