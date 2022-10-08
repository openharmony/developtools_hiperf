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
#define HILOG_TAG "Protobuf"

#include "report_protobuf_file.h"
#include "utilities.h"

using namespace Proto;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
// output
ReportProtobufFileWriter::~ReportProtobufFileWriter()
{
    Close();
}

void ReportProtobufFileWriter::BeforeClose()
{
    HiperfRecord record;
    SampleStatistic *message = record.mutable_statistic();

    message->set_count(recordCount_);
    message->set_lost(recordLost_);
    protpbufCodedOutputStream_->WriteLittleEndian32(record.ByteSizeLong());
    record.SerializeToCodedStream(protpbufCodedOutputStream_.get());
}

void ReportProtobufFileWriter::Close()
{
    if (protobufFileStream_->is_open()) {
        BeforeClose();
        // write 0 as end
        protpbufCodedOutputStream_->WriteLittleEndian32(0);
        protpbufCodedOutputStream_.reset(nullptr);
        protpbufOutputStream_.reset(nullptr);
        protobufFileStream_->close();
        printf("%" PRIu64 " sample record export to protobuf\n", recordCount_);
    }
}

bool ReportProtobufFileWriter::Write(const void *buffer, int size)
{
    if (protobufFileStream_->is_open()) {
        try {
            protobufFileStream_->write((const char *)buffer, size);
            HLOGM("writed %d bytes", size);
            return true;
        } catch (std::ofstream::failure &writeErr) {
            HLOGE("write file failed %s", fileName_.c_str());
        }
    } else {
        printf("no file open for write (request %d bytes).\n", size);
    }
    return false;
}

bool ReportProtobufFileWriter::Create(std::string fileName)
{
    fileName_ = fileName;
    try {
        protobufFileStream_->exceptions(std::ofstream::failbit | std::ofstream::badbit |
                                        std::ofstream::eofbit);
        std::string resolvedPath = CanonicalizeSpecPath(fileName_.c_str());
        protobufFileStream_->open(resolvedPath.c_str(),
                                  std::fstream::out | std::fstream::trunc | std::fstream::binary);
        protpbufOutputStream_ =
            std::make_unique<google::protobuf::io::CopyingOutputStreamAdaptor>(this);
        protpbufCodedOutputStream_ =
            std::make_unique<google::protobuf::io::CodedOutputStream>(protpbufOutputStream_.get());

        printf("open proto buf file succeed.\n");

        Write(FILE_MAGIC, sizeof(FILE_MAGIC) - 1);
        Write(&FILE_VERSION, sizeof(FILE_VERSION));

        printf("create proto buf file succeed.\n");
        return true;
    } catch (const std::fstream::failure &e) {
        printf("open proto buf file faild. %s\n", e.what());
    }
    return false;
}

bool ReportProtobufFileWriter::isOpen()
{
    return protobufFileStream_->is_open();
}

bool ReportProtobufFileWriter::ProcessRecord(const PerfEventRecord &record)
{
    HLOGM("ProcessRecord %d", record.GetType());
    if (record.GetType() == PERF_RECORD_SAMPLE) {
        HLOGF("record.GetType() == PERF_RECORD_SAMPLE");
    } else if (record.GetType() == PERF_RECORD_LOST_SAMPLES) {
        ProcessRecord(*static_cast<const PerfRecordLost *>(&record));
    } else if (record.GetType() == PERF_RECORD_COMM) {
        ProcessRecord(*static_cast<const PerfRecordComm *>(&record));
    } else {
        HLOGM("skip record type %d", record.GetType());
        return false;
    }
    return true;
}

bool ReportProtobufFileWriter::ProcessSampleRecord(
    const PerfRecordSample &recordSample, uint32_t configIndex,
    const std::vector<std::unique_ptr<SymbolsFile>> &symbolsFiles)
{
    HiperfRecord record;
    CallStackSample *sample = record.mutable_sample();
    sample->set_time(recordSample.data_.time);
    sample->set_tid(recordSample.data_.tid);
    for (const CallFrame &frame : recordSample.callFrames_) {
        auto callframe = sample->add_callstackframe();
        callframe->set_symbols_vaddr(frame.vaddrInFile_);
        callframe->set_loaded_vaddr(frame.ip_ - frame.offsetToVaddr_);
        if (frame.symbolFileIndex_ >= 0) {
            callframe->set_symbols_file_id(frame.symbolFileIndex_);
            callframe->set_function_name_id(frame.symbolIndex_);
        }
    }
    sample->set_event_count(recordSample.data_.period);
    sample->set_config_name_id(configIndex);

    protpbufCodedOutputStream_->WriteLittleEndian32(record.ByteSizeLong());
    record.SerializeToCodedStream(protpbufCodedOutputStream_.get());
    recordCount_++;

    return true;
}
bool ReportProtobufFileWriter::ProcessReportInfo(const std::vector<std::string> &configNames,
                                                 const std::string &workloadCmd)
{
    HiperfRecord record;
    ReportInfo *info = record.mutable_info();
    HLOGV("configNames:%zu", configNames.size());
    for (auto configName : configNames) {
        info->add_config_name(configName);
    }
    info->set_workload_cmd(workloadCmd);

    protpbufCodedOutputStream_->WriteLittleEndian32(record.ByteSizeLong());
    record.SerializeToCodedStream(protpbufCodedOutputStream_.get());
    return true;
}

bool ReportProtobufFileWriter::ProcessRecord(const PerfRecordLost &recordLost)
{
    recordLost.DumpLog(__FUNCTION__);
    recordLost_ += recordLost.data_.lost;
    return true;
}

bool ReportProtobufFileWriter::ProcessRecord(const PerfRecordComm &recordComm)
{
    recordComm.DumpLog(__FUNCTION__);
    HiperfRecord record;
    VirtualThreadInfo *thread = record.mutable_thread();

    thread->set_tid(recordComm.data_.tid);
    thread->set_pid(recordComm.data_.pid);
    thread->set_name(recordComm.data_.comm);

    protpbufCodedOutputStream_->WriteLittleEndian32(record.ByteSizeLong());
    record.SerializeToCodedStream(protpbufCodedOutputStream_.get());
    return true;
}

bool ReportProtobufFileWriter::ProcessSymbolsFiles(
    const std::vector<std::unique_ptr<SymbolsFile>> &symbolsFiles)
{
    uint32_t id = 0;
    for (auto &symbolsFile : symbolsFiles) {
        HiperfRecord record;
        SymbolTableFile *message = record.mutable_file();

        message->set_id(id++);
        message->set_path(symbolsFile->filePath_);

        for (auto &symbol : symbolsFile->GetSymbols()) {
            message->add_function_name(symbol.Name().data());
        }

        protpbufCodedOutputStream_->WriteLittleEndian32(record.ByteSizeLong());
        record.SerializeToCodedStream(protpbufCodedOutputStream_.get());
    }
    return true;
}

// input
int ReportProtobufFileReader::Read(void *buffer, int size)
{
    if (protobufFileStream_->is_open()) {
        try {
            protobufFileStream_->read(static_cast<char *>(buffer), size);
            HLOGM("readed %d bytes", size);
            return size;
        } catch (std::ifstream::failure &readErr) {
            if (protobufFileStream_->eof()) {
                // this is not a issue
                HLOGW("read file %d bytes failed eof. only return %zu\n", size,
                      protobufFileStream_->gcount());

                return protobufFileStream_->gcount();
            }
            printf("read file %d bytes failed %s : %s\n", size, fileName_.c_str(), readErr.what());
        }
    } else {
        printf("no file open for read (request %d bytes).\n", size);
    }
    return 0;
}

bool ReportProtobufFileReader::CheckFileMagic()
{
    char fileMagic[sizeof(FILE_MAGIC)] = {0};
    Read(fileMagic, sizeof(FILE_MAGIC) - 1);
    if (memcmp(fileMagic, FILE_MAGIC, sizeof(FILE_MAGIC) - 1) != 0) {
        printf("file magic is NOT correct. %s: %x\n", fileMagic, fileMagic[0]);
        return false;
    }

    uint16_t version = 0;
    Read(&version, sizeof(version));
    if (version != FILE_VERSION) {
        printf("file version is NOT correct.\n");
        return false;
    }

    return true;
}

bool ReportProtobufFileReader::Dump(std::string fileName, ProtobufReadBack readBack)
{
    const int defaultIndent = 0;
    fileName_ = fileName;
    try {
        protobufFileStream_->exceptions(std::ifstream::failbit | std::ifstream::badbit);
        std::string resolvedPath = CanonicalizeSpecPath(fileName_.c_str());
        protobufFileStream_->open(resolvedPath.c_str(), std::fstream::in | std::fstream::binary);
        printf("open proto buf file succeed.\n");
        if (!CheckFileMagic()) {
            return false;
        }
        protpbufInputStream_ = std::make_unique<google::protobuf::io::CopyingInputStreamAdaptor>(this);
        protpbufCodedInputStream_ =
            std::make_unique<google::protobuf::io::CodedInputStream>(protpbufInputStream_.get());
        uint32_t recordLength = 0;
        do {
            protpbufCodedInputStream_->ReadLittleEndian32(&recordLength);
            if (recordLength != 0) {
                PrintIndent(defaultIndent, "record length:%u (%x)\n", recordLength, recordLength);
                HiperfRecord record;
                std::string recordBuf;
                recordBuf.resize(recordLength);
                if (!protpbufCodedInputStream_->ReadString(&recordBuf, recordLength)) {
                    printf("read record error\n");
                    return false;
                }
                if (!record.ParseFromString(recordBuf)) {
                    printf("parse format error\n");
                    return false;
                } else {
                    if (readBack == nullptr) {
                        PrintIndent(defaultIndent, "\n");
                        Dump(record, defaultIndent);
                    } else {
                        readBack(record);
                    }
                }
            } else {
                if (readBack == nullptr) {
                    printf("no more record\n");
                }
                break;
            }
        } while (recordLength != 0);
        return true;
    } catch (const std::fstream::failure &e) {
        HLOGE("open proto buf file faild. %s\n", e.what());
    }
    return false;
}

bool ReportProtobufFileReader::Dump(const CallStackSample &message, int indent)
{
    PrintIndent(indent, "%s:\n", message.GetTypeName().c_str());
    if (message.has_time()) {
        PrintIndent(INDENT_ONE_LEVEL, "time:%" PRId64 "\n", message.time());
    }
    if (message.has_tid()) {
        PrintIndent(INDENT_ONE_LEVEL, "tid:%u\n", message.tid());
    }
    for (int i = 0; i < message.callstackframe_size(); i++) {
        PrintIndent(INDENT_ONE_LEVEL, "%d:\n", i);
        auto &callframe = message.callstackframe(i);
        if (callframe.has_symbols_vaddr()) {
            PrintIndent(INDENT_TWO_LEVEL, "symbols_vaddr: 0x%" PRIx64 " \n",
                        callframe.symbols_vaddr());
        }
        if (callframe.has_symbols_file_id()) {
            PrintIndent(INDENT_TWO_LEVEL, "symbols_file_id: %u\n", callframe.symbols_file_id());
        }
        if (callframe.has_function_name_id()) {
            PrintIndent(INDENT_TWO_LEVEL, "function_name_id: %d\n", callframe.function_name_id());
        }
    }
    if (message.has_event_count()) {
        PrintIndent(INDENT_ONE_LEVEL, "event_count:%" PRIu64 "\n", message.event_count());
    }
    if (message.has_config_name_id()) {
        PrintIndent(INDENT_ONE_LEVEL, "config_name_id:%u\n", message.config_name_id());
    }
    return true;
}

bool ReportProtobufFileReader::Dump(const SampleStatistic &message, int indent)
{
    PrintIndent(indent, "%s:\n", message.GetTypeName().c_str());
    if (message.has_count()) {
        PrintIndent(INDENT_ONE_LEVEL, "count:%" PRIu64 "\n", message.count());
    }
    if (message.has_lost()) {
        PrintIndent(INDENT_ONE_LEVEL, "lost:%" PRIu64 "\n", message.lost());
    }
    return false;
}

bool ReportProtobufFileReader::Dump(const SymbolTableFile &message, int indent)
{
    PrintIndent(indent, "%s:\n", message.GetTypeName().c_str());
    if (message.has_id()) {
        PrintIndent(INDENT_ONE_LEVEL, "id: %u\n", message.id());
    }
    if (message.has_path()) {
        PrintIndent(INDENT_ONE_LEVEL, "path: %s\n", message.path().c_str());
    }
    for (int i = 0; i < message.function_name_size(); i++) {
        PrintIndent(INDENT_TWO_LEVEL, "%d:%s\n", i, message.function_name(i).c_str());
    }
    return false;
}
bool ReportProtobufFileReader::Dump(const VirtualThreadInfo &message, int indent)
{
    PrintIndent(indent, "%s:\n", message.GetTypeName().c_str());
    if (message.has_pid()) {
        PrintIndent(INDENT_ONE_LEVEL, "pid:%u\n", message.pid());
    }
    if (message.has_tid()) {
        PrintIndent(INDENT_ONE_LEVEL, "tid:%u\n", message.tid());
    }
    if (message.has_pid()) {
        PrintIndent(INDENT_ONE_LEVEL, "name:%s\n", message.name().c_str());
    }
    return false;
}
bool ReportProtobufFileReader::Dump(const ReportInfo &message, int indent)
{
    PrintIndent(indent, "%s:\n", message.GetTypeName().c_str());
    for (int i = 0; i < message.config_name_size(); i++) {
        PrintIndent(INDENT_ONE_LEVEL, "config_name:%d:%s\n", i, message.config_name(i).c_str());
    }
    if (message.has_workload_cmd()) {
        PrintIndent(INDENT_ONE_LEVEL, "workload:%s\n", message.workload_cmd().c_str());
    }
    return true;
}
bool ReportProtobufFileReader::Dump(const HiperfRecord &record, int indent)
{
    PrintIndent(indent, "%s:\n", record.GetTypeName().c_str());
    if (record.has_sample()) {
        return Dump(record.sample(), INDENT_ONE_LEVEL);
    } else if (record.has_statistic()) {
        return Dump(record.statistic(), INDENT_ONE_LEVEL);
    } else if (record.has_file()) {
        return Dump(record.file(), INDENT_ONE_LEVEL);
    } else if (record.has_thread()) {
        return Dump(record.thread(), INDENT_ONE_LEVEL);
    } else if (record.has_info()) {
        return Dump(record.info(), INDENT_ONE_LEVEL);
    } else {
        printf("unknow proto buf format\n");
        return false;
    }
}
bool ReportProtobufFileReader::isOpen()
{
    return protobufFileStream_->is_open();
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
