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

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "report_protobuf_file.h"
#include "report_protobuf_file_test.h"

using namespace Proto;
using namespace testing::ext;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class ReportProtobufFileTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::unique_ptr<ReportProtobufFileWriter> protobufOutputFileWriter_ = nullptr;
    std::unique_ptr<ReportProtobufFileReader> protobufInputFileReader_ = nullptr;
    std::vector<std::unique_ptr<SymbolsFile>> symbolsFiles_;
    void PrepareSymbolsFile();
};
void ReportProtobufFileTest::PrepareSymbolsFile()
{
    symbolsFiles_.clear();

    std::string userSymbol = "user_symbol";
    std::unique_ptr<SymbolsFile> user = SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE);
    user->symbols_.emplace_back(0x1, 1u, "first_user_func", user->filePath_);
    user->symbols_.emplace_back(0x2, 1u, "second_user_func", user->filePath_);
    user->filePath_ = userSymbol;
    symbolsFiles_.emplace_back(std::move(user));

    std::string userSymbol2 = "user_symbol2";
    std::unique_ptr<SymbolsFile> user2 = SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE);
    user2->symbols_.emplace_back(0x1, 1u, "first_user2_func", user2->filePath_);
    user2->symbols_.emplace_back(0x2, 1u, "second_user2_func", user2->filePath_);
    user2->symbols_.emplace_back(0x3, 1u, "third_user2_func", user2->filePath_);
    user2->filePath_ = userSymbol2;
    symbolsFiles_.emplace_back(std::move(user2));
}

void ReportProtobufFileTest::SetUpTestCase() {}

void ReportProtobufFileTest::TearDownTestCase() {}

void ReportProtobufFileTest::SetUp()
{
    protobufOutputFileWriter_ = std::make_unique<ReportProtobufFileWriter>();
    protobufInputFileReader_ = std::make_unique<ReportProtobufFileReader>();
    PrepareSymbolsFile();
}
void ReportProtobufFileTest::TearDown() {}

// build a protobuf data file with the same on-disk format as ReportProtobufFileWriter,
// but with caller controlled (partial) records.
static void MakeRawProtobufFile(const std::string &fileName,
                                const std::vector<HiperfRecord> &records)
{
    std::ofstream fs(fileName, std::ios::binary | std::ios::trunc);
    fs.write(FILE_MAGIC, sizeof(FILE_MAGIC) - 1);
    uint16_t version = FILE_VERSION;
    fs.write(reinterpret_cast<const char *>(&version), sizeof(version));
    for (const auto &record : records) {
        std::string bytes;
        record.SerializeToString(&bytes);
        uint32_t len = static_cast<uint32_t>(bytes.size());
        fs.write(reinterpret_cast<const char *>(&len), sizeof(len));
        fs.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }
    uint32_t zero = 0;
    fs.write(reinterpret_cast<const char *>(&zero), sizeof(zero));
}

/**
 * @tc.name: Create
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, Create, TestSize.Level2)
{
    std::string fileName = "perf.proto";
    ASSERT_EQ(protobufOutputFileWriter_->Create(fileName), true);
    EXPECT_EQ(access(fileName.c_str(), F_OK), 0);

    std::string errorFileName = "!@#$%^";
    EXPECT_EQ(protobufOutputFileWriter_->Create(fileName), false);
    EXPECT_EQ(access(errorFileName.c_str(), F_OK), -1);
}

/**
 * @tc.name: Close
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, Close, TestSize.Level1)
{
    std::string fileName = "perf.proto";
    EXPECT_EQ(protobufOutputFileWriter_->IsOpen(), false);
    ASSERT_EQ(protobufOutputFileWriter_->Create(fileName), true);
    EXPECT_EQ(protobufOutputFileWriter_->IsOpen(), true);
    protobufOutputFileWriter_->Close();
    EXPECT_EQ(protobufOutputFileWriter_->IsOpen(), false);
}

/**
 * @tc.name: ProcessRecord
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, ProcessRecord, TestSize.Level0)
{
    std::string fileName = "perf.proto";
    class ReportProtobufFileWriterMock : public ReportProtobufFileWriter {
    public:
        MOCK_METHOD1(ProcessRecord, bool(const PerfRecordComm &));
        MOCK_METHOD1(ProcessRecord, bool(const PerfRecordLost &));
    } protobufOutputFileWriter;

    const PerfRecordComm comm(false, 2, 3, "dummy");
    const PerfRecordLost lost(false, 1, 99);

    EXPECT_CALL(protobufOutputFileWriter, ProcessRecord(testing::Matcher<const PerfRecordComm &>(testing::_)))
        .Times(1);
    protobufOutputFileWriter.ProcessRecord(comm);

    EXPECT_CALL(protobufOutputFileWriter, ProcessRecord(testing::Matcher<const PerfRecordLost &>(testing::_)))
        .Times(2);
    protobufOutputFileWriter.ProcessRecord(lost);
    protobufOutputFileWriter.ProcessRecord(lost);
}

/**
 * @tc.name: ProcessRecordPerfRecordLost
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, ProcessRecordPerfRecordLost, TestSize.Level1)
{
    const PerfRecordLost lost(false, 1, 99);

    protobufOutputFileWriter_->ProcessRecord(lost);
    protobufOutputFileWriter_->ProcessRecord(lost);
    EXPECT_EQ(protobufOutputFileWriter_->recordLost_, lost.data_.lost * 2);
}

/**
 * @tc.name: ProcessRecordPerfRecordComm
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, ProcessRecordPerfRecordComm, TestSize.Level2)
{
    int expectRecord = 0;
    std::string fileName = "perf.proto";
    const PerfRecordComm comm(false, 2, 3, "dummy");
    ASSERT_EQ(protobufOutputFileWriter_->Create(fileName), true);

    protobufOutputFileWriter_->ProcessRecord(comm);

    protobufOutputFileWriter_->Close();

    auto protobufReadBack = [&](Proto::HiperfRecord &record) {
        printf("record name %s %d\n", std::string(record.GetTypeName()).c_str(), record.RecordType_case());
        // the SampleStatistic always write in close.
        // so there at least 2 record ,one is expect , one is statiistic
        if (record.has_thread()) {
            const VirtualThreadInfo &message = record.thread();
            ASSERT_EQ(message.tid(), comm.data_.tid);
            ASSERT_EQ(message.pid(), comm.data_.pid);
            ASSERT_STREQ(std::string(message.name()).c_str(), comm.data_.comm);
            expectRecord++;
        }
    };
    protobufInputFileReader_->Dump(fileName, protobufReadBack);

    EXPECT_EQ(expectRecord, 1);
}

/**
 * @tc.name: BeforeClose
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, BeforeClose, TestSize.Level1)
{
    int expectRecord = 0;
    std::string fileName = "perf.proto";
    ASSERT_EQ(protobufOutputFileWriter_->Create(fileName), true);
    protobufOutputFileWriter_->recordLost_ = 10;
    protobufOutputFileWriter_->recordCount_ = 20;
    protobufOutputFileWriter_->Close();

    auto protobufReadBack = [&](Proto::HiperfRecord &record) {
        printf("record name %s %d\n", std::string(record.GetTypeName()).c_str(), record.RecordType_case());
        // the SampleStatistic always write in close.
        // so there at least 2 record ,one is expect , one is statiistic
        if (record.has_statistic()) {
            const SampleStatistic &message = record.statistic();
            ASSERT_EQ(message.count(), protobufOutputFileWriter_->recordCount_);
            ASSERT_EQ(message.lost(), protobufOutputFileWriter_->recordLost_);
            expectRecord++;
        }
    };

    protobufInputFileReader_->Dump(fileName, protobufReadBack);

    EXPECT_EQ(expectRecord, 1);
}

/**
 * @tc.name: ProcessSymbolsFiles
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, ProcessSymbolsFiles, TestSize.Level0)
{
    unsigned int expectRecord = 0;
    std::string fileName = "perf.proto";
    ASSERT_EQ(protobufOutputFileWriter_->Create(fileName), true);

    protobufOutputFileWriter_->ProcessSymbolsFiles(symbolsFiles_);
    protobufOutputFileWriter_->Close();

    auto protobufReadBack = [&](Proto::HiperfRecord &record) {
        printf("record name %s %d\n", std::string(record.GetTypeName()).c_str(), record.RecordType_case());
        // the SampleStatistic always write in close.
        // so there at least 2 record ,one is expect , one is statiistic
        if (record.has_file()) {
            expectRecord++;
            const SymbolTableFile &message = record.file();
            ASSERT_EQ(message.id() >= 0, true);
            ASSERT_EQ(message.id() < symbolsFiles_.size(), true);
            const std::unique_ptr<SymbolsFile> &symbolFile = symbolsFiles_.at(message.id());
            ASSERT_STREQ(std::string(message.path()).c_str(), symbolFile->filePath_.c_str());
            ASSERT_EQ(static_cast<size_t>(message.function_name_size()),
                      symbolFile->GetSymbols().size());
            for (int i = 0; i < message.function_name_size(); i++) {
                EXPECT_STREQ(std::string(message.function_name(i)).c_str(),
                             symbolFile->GetSymbols().at(i).name_.data());
            }
        }
    };

    protobufInputFileReader_->Dump(fileName, protobufReadBack);

    EXPECT_EQ(expectRecord, symbolsFiles_.size());
}

/**
 * @tc.name: ProcessReportInfo
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, ProcessReportInfo, TestSize.Level2)
{
    int expectRecord = 0;
    std::string fileName = "perf.proto";
    std::vector<std::string> configNames = {"config1", "config2", "config3"};
    std::string workloadCmd = "workcommand";

    ASSERT_EQ(protobufOutputFileWriter_->Create(fileName), true);
    protobufOutputFileWriter_->ProcessReportInfo(configNames, workloadCmd);
    protobufOutputFileWriter_->Close();

    auto protobufReadBack = [&](Proto::HiperfRecord &record) {
        printf("record name %s %d\n", std::string(record.GetTypeName()).c_str(), record.RecordType_case());
        // the SampleStatistic always write in close.
        // so there at least 2 record ,one is expect , one is statiistic
        if (record.has_info()) {
            const ReportInfo &message = record.info();
            ASSERT_EQ(message.config_name_size() > 0, true);
            ASSERT_EQ(static_cast<size_t>(message.config_name_size()), configNames.size());
            for (int i = 0; i < message.config_name_size(); i++) {
                EXPECT_STREQ(std::string(message.config_name(i)).c_str(), configNames.at(i).c_str());
            }
            if (message.has_workload_cmd()) {
                EXPECT_STREQ(std::string(message.workload_cmd()).c_str(), workloadCmd.c_str());
            }
            expectRecord++;
        }
    };
    protobufInputFileReader_->Dump(fileName, protobufReadBack);

    EXPECT_EQ(expectRecord, 1);
}

/**
 * @tc.name: ProcessSampleRecord
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, ProcessSampleRecord, TestSize.Level1)
{
    int expectRecord = 0;
    std::string fileName = "perf.proto";
    PerfRecordSample sample(false, 1, 2, 100, 200u);
    sample.callFrames_.emplace_back(0x1, 0x1234, "user_symbol", "first_user_func");
    sample.callFrames_.emplace_back(0x2, 0x1234, "user_symbol2", "first_user2_func");
    sample.callFrames_.emplace_back(0x3, 0x1234, "user_symbol2", "second_user2_func");

    sample.callFrames_.at(0).symbolFileIndex = 0;
    sample.callFrames_.at(1).symbolFileIndex = 1;
    sample.callFrames_.at(2).symbolFileIndex = 1;
    sample.callFrames_.at(0).index = 0;
    sample.callFrames_.at(1).index = 0;
    sample.callFrames_.at(2).index = 1;

    ASSERT_EQ(protobufOutputFileWriter_->Create(fileName), true);
    protobufOutputFileWriter_->ProcessSampleRecord(sample, 0u, symbolsFiles_);

    protobufOutputFileWriter_->Close();

    auto protobufReadBack = [&](Proto::HiperfRecord &record) {
        printf("record name %s %d\n", std::string(record.GetTypeName()).c_str(), record.RecordType_case());
        // the SampleStatistic always write in close.
        // so there at least 2 record ,one is expect , one is statiistic
        if (record.has_sample()) {
            const CallStackSample &message = record.sample();
            ASSERT_EQ(message.has_time(), true);
            ASSERT_EQ(message.time(), 200u);

            ASSERT_EQ(message.has_tid(), true);
            ASSERT_EQ(message.tid(), 2u);

            ASSERT_EQ(message.callstackframe_size() > 0, true);
            ASSERT_EQ(static_cast<size_t>(message.callstackframe_size()),
                      sample.callFrames_.size());

            for (int i = 0; i < message.callstackframe_size(); i++) {
                auto &callframe = message.callstackframe(i);
                ASSERT_EQ(callframe.has_symbols_vaddr(), true);
                ASSERT_EQ(callframe.symbols_vaddr(), sample.callFrames_.at(i).funcOffset);

                ASSERT_EQ(callframe.has_symbols_file_id(), true);
                printf("symbols file id %d\n", callframe.symbols_file_id());
                ASSERT_EQ(callframe.symbols_file_id() < symbolsFiles_.size(), true);
                const std::unique_ptr<SymbolsFile> &symbolsFile =
                    symbolsFiles_.at(callframe.symbols_file_id());

                ASSERT_EQ(callframe.has_function_name_id(), true);
                printf("function id %d\n", callframe.function_name_id());
                ASSERT_EQ(callframe.function_name_id() >= 0, true);
                int funcNameId = callframe.function_name_id();
                ASSERT_EQ(static_cast<size_t>(funcNameId) < symbolsFile->GetSymbols().size(), true);
                ASSERT_STREQ(sample.callFrames_.at(i).funcName.data(),
                             symbolsFile->GetSymbols().at(funcNameId).name_.data());
            }
            ASSERT_EQ(message.has_event_count(), true);
            ASSERT_EQ(message.event_count(), 100u);

            ASSERT_EQ(message.has_config_name_id(), true);
            ASSERT_EQ(message.config_name_id(), 0u);
            expectRecord++;
        }
    };
    protobufInputFileReader_->Dump(fileName, protobufReadBack);

    EXPECT_EQ(expectRecord, 1);
}

/**
 * @tc.name: ReadCallBackWithNull
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, ReadCallBackWithNull, TestSize.Level2)
{
    std::string fileName = "perf.proto";
    std::vector<std::string> configNames = {"config1", "config2", "config3"};
    std::string workloadCmd = "workcommand";

    ASSERT_EQ(protobufOutputFileWriter_->Create(fileName), true);
    protobufOutputFileWriter_->ProcessReportInfo(configNames, workloadCmd);
    protobufOutputFileWriter_->Close();

    EXPECT_EQ(protobufInputFileReader_->Dump(fileName, nullptr), true);
}

/**
 * @tc.name: WriterWithNullStream
 * @tc.desc: Close/Write/Create with a null file stream
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, WriterWithNullStream, TestSize.Level2)
{
    protobufOutputFileWriter_->protobufFileStream_.reset(nullptr);
    char buffer[4] = {0};
    EXPECT_EQ(protobufOutputFileWriter_->Write(buffer, sizeof(buffer)), false);
    EXPECT_EQ(protobufOutputFileWriter_->Create("perf.proto"), false);
    protobufOutputFileWriter_->Close();
}

/**
 * @tc.name: WriteWithoutOpen
 * @tc.desc: Write before any file is opened
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, WriteWithoutOpen, TestSize.Level2)
{
    char buffer[4] = {0};
    EXPECT_EQ(protobufOutputFileWriter_->Write(buffer, sizeof(buffer)), false);
}

/**
 * @tc.name: ProcessRecordSampleType
 * @tc.desc: ProcessRecord with a PERF_RECORD_SAMPLE record
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, ProcessRecordSampleType, TestSize.Level2)
{
    // HLOGF is LEVEL_FATAL and would call exit(-1); disable fatal-exit temporarily
    // so the SAMPLE branch can be exercised without killing the test process.
    DebugLogger::GetInstance()->exitOnFatal_ = false;
    PerfRecordSample sample(false, 1, 2, 100, 200u);
    EXPECT_EQ(protobufOutputFileWriter_->ProcessRecord(sample), true);
    DebugLogger::GetInstance()->exitOnFatal_ = true;
}

/**
 * @tc.name: ProcessSampleRecordNegativeSymbolIndex
 * @tc.desc: ProcessSampleRecord with a negative symbolFileIndex callframe
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, ProcessSampleRecordNegativeSymbolIndex, TestSize.Level2)
{
    std::string fileName = "perf.proto";
    PerfRecordSample sample(false, 1, 2, 100, 200u);
    sample.callFrames_.emplace_back(0x1, 0x1234, "user_symbol", "first_user_func");
    sample.callFrames_.at(0).symbolFileIndex = -1;
    ASSERT_EQ(protobufOutputFileWriter_->Create(fileName), true);
    EXPECT_EQ(protobufOutputFileWriter_->ProcessSampleRecord(sample, 0u, symbolsFiles_), true);
    protobufOutputFileWriter_->Close();
}

/**
 * @tc.name: ReadNotOpenStream
 * @tc.desc: Read before any file is opened
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, ReadNotOpenStream, TestSize.Level2)
{
    char buffer[4] = {0};
    EXPECT_EQ(protobufInputFileReader_->Read(buffer, sizeof(buffer)), 0);
}

/**
 * @tc.name: CheckFileMagicWrongMagic
 * @tc.desc: Dump a file whose magic does not match
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, CheckFileMagicWrongMagic, TestSize.Level2)
{
    std::string fileName = "perf_bad_magic.proto";
    {
        std::ofstream fs(fileName, std::ios::binary | std::ios::trunc);
        std::string badMagic(sizeof(FILE_MAGIC) - 1, 'X');
        fs.write(badMagic.data(), badMagic.size());
        uint16_t version = FILE_VERSION;
        fs.write(reinterpret_cast<const char *>(&version), sizeof(version));
    }
    EXPECT_EQ(protobufInputFileReader_->Dump(fileName, nullptr), false);
}

/**
 * @tc.name: CheckFileMagicWrongVersion
 * @tc.desc: Dump a file whose version does not match
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, CheckFileMagicWrongVersion, TestSize.Level2)
{
    std::string fileName = "perf_bad_version.proto";
    {
        std::ofstream fs(fileName, std::ios::binary | std::ios::trunc);
        fs.write(FILE_MAGIC, sizeof(FILE_MAGIC) - 1);
        uint16_t badVersion = FILE_VERSION + 1;
        fs.write(reinterpret_cast<const char *>(&badVersion), sizeof(badVersion));
    }
    EXPECT_EQ(protobufInputFileReader_->Dump(fileName, nullptr), false);
}

/**
 * @tc.name: DumpTruncatedNoRecord
 * @tc.desc: Dump a file truncated before any record
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, DumpTruncatedNoRecord, TestSize.Level2)
{
    std::string fileName = "perf_truncated.proto";
    {
        std::ofstream fs(fileName, std::ios::binary | std::ios::trunc);
        fs.write(FILE_MAGIC, sizeof(FILE_MAGIC) - 1);
        uint16_t version = FILE_VERSION;
        fs.write(reinterpret_cast<const char *>(&version), sizeof(version));
    }
    EXPECT_EQ(protobufInputFileReader_->Dump(fileName, nullptr), false);
}

/**
 * @tc.name: DumpTruncatedRecord
 * @tc.desc: Dump a record whose body is shorter than its length
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, DumpTruncatedRecord, TestSize.Level2)
{
    std::string fileName = "perf_truncated_rec.proto";
    {
        std::ofstream fs(fileName, std::ios::binary | std::ios::trunc);
        fs.write(FILE_MAGIC, sizeof(FILE_MAGIC) - 1);
        uint16_t version = FILE_VERSION;
        fs.write(reinterpret_cast<const char *>(&version), sizeof(version));
        uint32_t len = 100; // declared length larger than the real body
        fs.write(reinterpret_cast<const char *>(&len), sizeof(len));
        std::string body(10, '\0');
        fs.write(body.data(), body.size());
    }
    EXPECT_EQ(protobufInputFileReader_->Dump(fileName, nullptr), false);
}

/**
 * @tc.name: DumpCorruptRecord
 * @tc.desc: Dump a record with an unparseable body
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, DumpCorruptRecord, TestSize.Level2)
{
    std::string fileName = "perf_corrupt.proto";
    {
        std::ofstream fs(fileName, std::ios::binary | std::ios::trunc);
        fs.write(FILE_MAGIC, sizeof(FILE_MAGIC) - 1);
        uint16_t version = FILE_VERSION;
        fs.write(reinterpret_cast<const char *>(&version), sizeof(version));
        uint32_t len = 8;
        fs.write(reinterpret_cast<const char *>(&len), sizeof(len));
        // 0xFF -> wire type 7 (invalid), ParseFromArray fails
        std::string body(8, '\xFF');
        fs.write(body.data(), body.size());
    }
    EXPECT_EQ(protobufInputFileReader_->Dump(fileName, nullptr), false);
}

/**
 * @tc.name: DumpPartialCallStackSample
 * @tc.desc: Dump a CallStackSample with no fields set
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, DumpPartialCallStackSample, TestSize.Level2)
{
    std::string fileName = "perf_partial_sample.proto";
    HiperfRecord record;
    CallStackSample *sample = record.mutable_sample();
    sample->add_callstackframe(); // empty frame, no symbols_vaddr
    MakeRawProtobufFile(fileName, {record});
    EXPECT_EQ(protobufInputFileReader_->Dump(fileName, nullptr), true);
}

/**
 * @tc.name: DumpPartialSampleStatistic
 * @tc.desc: Dump a SampleStatistic with no fields set
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, DumpPartialSampleStatistic, TestSize.Level2)
{
    std::string fileName = "perf_partial_statistic.proto";
    HiperfRecord record;
    record.mutable_statistic(); // no count, no lost
    MakeRawProtobufFile(fileName, {record});
    EXPECT_EQ(protobufInputFileReader_->Dump(fileName, nullptr), true);
}

/**
 * @tc.name: DumpPartialSymbolTableFile
 * @tc.desc: Dump a SymbolTableFile with no fields set
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, DumpPartialSymbolTableFile, TestSize.Level2)
{
    std::string fileName = "perf_partial_file.proto";
    HiperfRecord record;
    record.mutable_file(); // no id, no path
    MakeRawProtobufFile(fileName, {record});
    EXPECT_EQ(protobufInputFileReader_->Dump(fileName, nullptr), true);
}

/**
 * @tc.name: DumpPartialVirtualThreadInfo
 * @tc.desc: Dump a VirtualThreadInfo with no fields set
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, DumpPartialVirtualThreadInfo, TestSize.Level2)
{
    std::string fileName = "perf_partial_thread.proto";
    HiperfRecord record;
    record.mutable_thread(); // no pid, no tid, no name
    MakeRawProtobufFile(fileName, {record});
    EXPECT_EQ(protobufInputFileReader_->Dump(fileName, nullptr), true);
}

/**
 * @tc.name: DumpPartialReportInfo
 * @tc.desc: Dump a ReportInfo with no fields set
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, DumpPartialReportInfo, TestSize.Level2)
{
    std::string fileName = "perf_partial_info.proto";
    HiperfRecord record;
    record.mutable_info(); // no config names, no workload_cmd
    MakeRawProtobufFile(fileName, {record});
    EXPECT_EQ(protobufInputFileReader_->Dump(fileName, nullptr), true);
}

/**
 * @tc.name: DumpUnknownHiperfRecord
 * @tc.desc: Dump a HiperfRecord with no known message set
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, DumpUnknownHiperfRecord, TestSize.Level2)
{
    std::string fileName = "perf_unknown.proto";
    {
        std::ofstream fs(fileName, std::ios::binary | std::ios::trunc);
        fs.write(FILE_MAGIC, sizeof(FILE_MAGIC) - 1);
        uint16_t version = FILE_VERSION;
        fs.write(reinterpret_cast<const char *>(&version), sizeof(version));
        // a record carrying only an unknown field (field 100, varint 1)
        const unsigned char recordBytes[] = {0xA0, 0x06, 0x01};
        uint32_t len = sizeof(recordBytes);
        fs.write(reinterpret_cast<const char *>(&len), sizeof(len));
        fs.write(reinterpret_cast<const char *>(recordBytes), sizeof(recordBytes));
        uint32_t zero = 0;
        fs.write(reinterpret_cast<const char *>(&zero), sizeof(zero));
    }
    EXPECT_EQ(protobufInputFileReader_->Dump(fileName, nullptr), true);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
