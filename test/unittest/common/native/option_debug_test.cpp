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
#define HILOG_TAG "OptionDebugTest"

#include "option_debug_test.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <random>

#include <hilog/log.h>

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class OptionDebugTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    const std::string TEST_LOG_MESSAGE = "<HELLO_TEST_LOG_MESSAGE>";
    void LogLevelTest(std::vector<std::string> args, DebugLevel level);
    default_random_engine rnd_;
};

void OptionDebugTest::SetUpTestCase()
{
    DebugLogger::GetInstance()->Reset();
}

void OptionDebugTest::TearDownTestCase()
{
    DebugLogger::GetInstance()->Reset();
}

void OptionDebugTest::SetUp()
{
    Option::ClearMainOptions();
    SubCommand::RegisterSubCommand(TEST_CMD_NOTHING,
                                   std::make_unique<SubCommandTest>(TEST_CMD_NOTHING));
    RegisterMainCommandDebug();
}

void OptionDebugTest::TearDown()
{
    SubCommand::ClearSubCommands();
    Option::ClearMainOptions();
}

void OptionDebugTest::LogLevelTest(std::vector<std::string> args, const DebugLevel testlevel)
{
    // backup
    DebugLevel oldLevel = DebugLogger::GetInstance()->GetLogLevel();
    EXPECT_EQ(Command::DispatchCommands(args), true);

    const std::string logMessage =
        TEST_LOG_MESSAGE + std::to_string(rnd_()) + "_" + std::to_string(testlevel);
    HLOGE("%s", logMessage.c_str());
    HLOGW("%s", logMessage.c_str());
    HLOGI("%s", logMessage.c_str());
    HLOGD("%s", logMessage.c_str());
    HLOGV("%s", logMessage.c_str());
    HLOGM("%s", logMessage.c_str());

    if (fflush(DebugLogger::GetInstance()->file_) != 0) {
        HLOGD("fflush failed.");
    }
    std::string log = ReadFileToString(DebugLogger::GetInstance()->logPath_);
    ASSERT_EQ(log.empty(), false);
    // we have 6 level log
    // so the logout line is : (all log level - curr log level) + curr log level self
    EXPECT_EQ(SubStringCount(log, logMessage),
              static_cast<size_t>(LEVEL_ERROR) - static_cast<size_t>(testlevel) + 1u);
    if (HasFailure()) {
        HLOGD("LogLevelTest failed.");
    }
    // restore
    DebugLogger::GetInstance()->SetLogLevel(oldLevel);
}

/**
 * @tc.name: TestRegisterMainCommandDebug
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionDebugTest, TestRegisterMainCommandDebug, TestSize.Level1)
{
    // see RegisterMainCommandDebug
#if is_ohos
    EXPECT_EQ(Option::GetMainOptions().size(), 8u);
#else
    EXPECT_EQ(Option::GetMainOptions().size(), 7u);
#endif
}

/**
 * @tc.name: debug
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionDebugTest, debug, TestSize.Level1)
{
    LogLevelTest({"--debug", TEST_CMD_NOTHING}, LEVEL_DEBUG);
}

/**
 * @tc.name: verbose
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionDebugTest, verbose, TestSize.Level1)
{
    LogLevelTest({"--verbose", TEST_CMD_NOTHING}, LEVEL_VERBOSE);
}

/**
 * @tc.name: verbose
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionDebugTest, much, TestSize.Level1)
{
    LogLevelTest({"--much", TEST_CMD_NOTHING}, LEVEL_MUCH);
}

/**
 * @tc.name: mixlog
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionDebugTest, mixlog, TestSize.Level1)
{
    StdoutRecord stdoutRecord;
    stdoutRecord.Start();
    EXPECT_EQ(Command::DispatchCommands({"--mixlog", TEST_CMD_NOTHING}), true);

    const std::string logMessage = TEST_LOG_MESSAGE + std::to_string(rnd_());
    HLOGD("%s", logMessage.c_str());
    std::string stringOut = stdoutRecord.Stop();
    EXPECT_NE(stringOut.find(logMessage), std::string::npos);

    // close it
    DebugLogger::GetInstance()->SetMixLogOutput(false);
}

/**
 * @tc.name: logpath
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionDebugTest, logpath, TestSize.Level1)
{
    EXPECT_EQ(Command::DispatchCommands({"--logpath", "./log.temp.txt", TEST_CMD_NOTHING}), true);
    EXPECT_EQ(Command::DispatchCommands({"--logpath", DEFAULT_LOG_PATH, TEST_CMD_NOTHING}), true);
}

/**
 * @tc.name: logtag
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionDebugTest, logtag, TestSize.Level1)
{
    LogLevelTest({"--logtag", "OptionDebugTest", TEST_CMD_NOTHING}, LEVEL_MUCH);
    LogLevelTest({"--logtag", "123", TEST_CMD_NOTHING}, DebugLogger::GetInstance()->GetLogLevel());
}

/**
 * @tc.name: logDisabled
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionDebugTest, logDisabled, TestSize.Level1)
{
    // no log will save in log file.
    LogLevelTest({"--nodebug", TEST_CMD_NOTHING}, LEVEL_FATAL);
    DebugLogger::GetInstance()->Disable(false);
}

/**
 * @tc.name: hilog
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionDebugTest, hilog, TestSize.Level1)
{
#if is_ohos
    // no log will save in log file.
    LogLevelTest({"--hilog", TEST_CMD_NOTHING}, LEVEL_FATAL);

    DebugLogger::GetInstance()->EnableHiLog(false);
#endif
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
