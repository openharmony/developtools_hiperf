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

#include <iostream>
#include <string>

#include "report_protobuf_file.h"
#include "report_protobuf_file_test.h"

using namespace Proto;
using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
using namespace ::testing;
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

/**
 * @tc.name: Create
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, Create, TestSize.Level1)
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
    EXPECT_EQ(protobufOutputFileWriter_->isOpen(), false);
    ASSERT_EQ(protobufOutputFileWriter_->Create(fileName), true);
    EXPECT_EQ(protobufOutputFileWriter_->isOpen(), true);
    protobufOutputFileWriter_->Close();
    EXPECT_EQ(protobufOutputFileWriter_->isOpen(), false);
}

/**
 * @tc.name: ProcessRecord
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportProtobufFileTest, ProcessRecord, TestSize.Level1)
{
    std::string fileName = "perf.proto";
    class ReportProtobufFileWriterMock : public ReportProtobufFileWriter {
    public:
        MOCK_METHOD1(ProcessRecord, bool(const PerfRecordComm &));
        MOCK_METHOD1(ProcessRecord, bool(const PerfRecordLost &));
    } protobufOutputFileWriter;

    const PerfRecordComm comm(false, 2, 3, "dummy");
    const PerfRecordLost lost(false, 1, 99);

    EXPECT_CALL(protobufOutputFileWriter, ProcessRecord(Matcher<const PerfRecordComm &>(_)))
        .Times(1);
    protobufOutputFileWriter.ProcessRecord(comm);

    EXPECT_CALL(protobufOutputFileWriter, ProcessRecord(Matcher<const PerfRecordLost &>(_)))
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
HWTEST_F(ReportProtobufFileTest, ProcessRecordPerfRecordComm, TestSize.Level1)
{
    int expectRecord = 0;
    std::string fileName = "perf.proto";
    const PerfRecordComm comm(false, 2, 3, "dummy");
    ASSERT_EQ(protobufOutputFileWriter_->Create(fileName), true);

    protobufOutputFileWriter_->ProcessRecord(comm);

    protobufOutputFileWriter_->Close();

    auto protobufReadBack = [&](Proto::HiperfRecord &record) {
        printf("record name %s %d\n", record.GetTypeName().c_str(), record.RecordType_case());
        // the SampleStatistic always write in close.
        // so there at least 2 record ,one is expect , one is statiistic
        if (record.has_thread()) {
            const VirtualThreadInfo &message = record.thread();
            ASSERT_EQ(message.tid(), comm.data_.tid);
            ASSERT_EQ(message.pid(), comm.data_.pid);
            ASSERT_STREQ(message.name().c_str(), comm.data_.comm);
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
        printf("record name %s %d\n", record.GetTypeName().c_str(), record.RecordType_case());
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
HWTEST_F(ReportProtobufFileTest, ProcessSymbolsFiles, TestSize.Level1)
{
    unsigned int expectRecord = 0;
    std::string fileName = "perf.proto";
    ASSERT_EQ(protobufOutputFileWriter_->Create(fileName), true);

    protobufOutputFileWriter_->ProcessSymbolsFiles(symbolsFiles_);
    protobufOutputFileWriter_->Close();

    auto protobufReadBack = [&](Proto::HiperfRecord &record) {
        printf("record name %s %d\n", record.GetTypeName().c_str(), record.RecordType_case());
        // the SampleStatistic always write in close.
        // so there at least 2 record ,one is expect , one is statiistic
        if (record.has_file()) {
            expectRecord++;
            const SymbolTableFile &message = record.file();
            ASSERT_EQ(message.id() >= 0, true);
            ASSERT_EQ(message.id() < symbolsFiles_.size(), true);
            const std::unique_ptr<SymbolsFile> &symbolFile = symbolsFiles_.at(message.id());
            ASSERT_STREQ(message.path().c_str(), symbolFile->filePath_.c_str());
            ASSERT_EQ(static_cast<size_t>(message.function_name_size()),
                      symbolFile->GetSymbols().size());
            for (int i = 0; i < message.function_name_size(); i++) {
                EXPECT_STREQ(message.function_name(i).c_str(),
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
HWTEST_F(ReportProtobufFileTest, ProcessReportInfo, TestSize.Level1)
{
    int expectRecord = 0;
    std::string fileName = "perf.proto";
    std::vector<std::string> configNames = {"config1", "config2", "config3"};
    std::string workloadCmd = "workcommand";

    ASSERT_EQ(protobufOutputFileWriter_->Create(fileName), true);
    protobufOutputFileWriter_->ProcessReportInfo(configNames, workloadCmd);
    protobufOutputFileWriter_->Close();

    auto protobufReadBack = [&](Proto::HiperfRecord &record) {
        printf("record name %s %d\n", record.GetTypeName().c_str(), record.RecordType_case());
        // the SampleStatistic always write in close.
        // so there at least 2 record ,one is expect , one is statiistic
        if (record.has_info()) {
            const ReportInfo &message = record.info();
            ASSERT_EQ(message.config_name_size() > 0, true);
            ASSERT_EQ(static_cast<size_t>(message.config_name_size()), configNames.size());
            for (int i = 0; i < message.config_name_size(); i++) {
                EXPECT_STREQ(message.config_name(i).c_str(), configNames.at(i).c_str());
            }
            if (message.has_workload_cmd()) {
                EXPECT_STREQ(message.workload_cmd().c_str(), workloadCmd.c_str());
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
    sample.callFrames_.emplace_back(0x1, 0x1234, "first_user_func", "user_symbol");
    sample.callFrames_.emplace_back(0x2, 0x1234, "first_user2_func", "user_symbol2");
    sample.callFrames_.emplace_back(0x3, 0x1234, "second_user2_func", "user_symbol2");

    sample.callFrames_.at(0).symbolFileIndex_ = 0;
    sample.callFrames_.at(1).symbolFileIndex_ = 1;
    sample.callFrames_.at(2).symbolFileIndex_ = 1;
    sample.callFrames_.at(0).symbolIndex_ = 0;
    sample.callFrames_.at(1).symbolIndex_ = 0;
    sample.callFrames_.at(2).symbolIndex_ = 1;

    ASSERT_EQ(protobufOutputFileWriter_->Create(fileName), true);
    protobufOutputFileWriter_->ProcessSampleRecord(sample, 0u, symbolsFiles_);

    protobufOutputFileWriter_->Close();

    auto protobufReadBack = [&](Proto::HiperfRecord &record) {
        printf("record name %s %d\n", record.GetTypeName().c_str(), record.RecordType_case());
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
                ASSERT_EQ(callframe.symbols_vaddr(), sample.callFrames_.at(i).vaddrInFile_);

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
                ASSERT_STREQ(sample.callFrames_.at(i).symbolName_.data(),
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
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
