/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "option_test.h"

#include <gtest/gtest.h>

#include <hilog/log.h>

#include "option.h"

using namespace testing::ext;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class OptionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OptionTest::SetUpTestCase() {}

void OptionTest::TearDownTestCase() {}

void OptionTest::SetUp()
{
    Option::RegisterMainOption(TEST_OPTION_CMD_1, TEST_OPTION_HELP, OptionAlwaysFalse);
    Option::RegisterMainOption(TEST_OPTION_CMD_2, TEST_OPTION_HELP, OptionAlwaysFalse);
    Option::RegisterMainOption(TEST_OPTION_CMD_3, TEST_OPTION_HELP, OptionAlwaysFalse);
}

void OptionTest::TearDown()
{
    Option::ClearMainOptions();
}

/**
 * @tc.name: TestRegisterMainOption
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestRegisterMainOption, TestSize.Level1)
{
    EXPECT_EQ(
        Option::RegisterMainOption(TEST_OPTION_CMD_NO_PREFIX, TEST_OPTION_HELP, OptionAlwaysFalse),
        false);
    EXPECT_EQ(
        Option::RegisterMainOption(TEST_OPTION_CMD_ERR_PREFIX, TEST_OPTION_HELP, OptionAlwaysFalse),
        false);
    EXPECT_EQ(
        Option::RegisterMainOption(TEST_OPTION_CMD_EMPTY, TEST_OPTION_HELP, OptionAlwaysFalse),
        false);

    EXPECT_EQ(Option::RegisterMainOption("-tf", TEST_OPTION_HELP, OptionAlwaysFalse), true);
    EXPECT_EQ(Option::RegisterMainOption("-tf", TEST_OPTION_HELP, OptionAlwaysFalse), false);
    EXPECT_EQ(Option::RegisterMainOption("-tt", TEST_OPTION_HELP, OptionAlwaysTrue), true);
    EXPECT_EQ(Option::RegisterMainOption("-tt", TEST_OPTION_HELP, OptionAlwaysTrue), false);
}

/**
 * @tc.name: TestFindMainOption
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestFindMainOption, TestSize.Level1)
{
    ASSERT_NE(Option::FindMainOption(TEST_OPTION_CMD_1), nullptr);
    EXPECT_NE(Option::FindMainOption(TEST_OPTION_CMD_1)->help, TEST_OPTION_BRIEF);
    EXPECT_EQ(Option::FindMainOption(TEST_OPTION_CMD_1)->help, TEST_OPTION_HELP);

    ASSERT_NE(Option::FindMainOption(TEST_OPTION_CMD_2), nullptr);
    EXPECT_NE(Option::FindMainOption(TEST_OPTION_CMD_2)->help, TEST_OPTION_BRIEF);
    EXPECT_EQ(Option::FindMainOption(TEST_OPTION_CMD_2)->help, TEST_OPTION_HELP);

    ASSERT_NE(Option::FindMainOption(TEST_OPTION_CMD_3), nullptr);
    EXPECT_NE(Option::FindMainOption(TEST_OPTION_CMD_3)->help, TEST_OPTION_BRIEF);
    EXPECT_EQ(Option::FindMainOption(TEST_OPTION_CMD_3)->help, TEST_OPTION_HELP);

    EXPECT_EQ(Option::FindMainOption(TEST_NO_OPTION_CMD), nullptr);
}

/**
 * @tc.name: TestGetMainOptions
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, GetMainOptions, TestSize.Level1)
{
    EXPECT_EQ(Option::GetMainOptions().size(), 3u);
    Option::ClearMainOptions();
    EXPECT_EQ(Option::GetMainOptions().size(), 0u);
}

/**
 * @tc.name: TestGetOptionBool
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, GetOptionBool, TestSize.Level0)
{
    bool boolVal;
    std::vector<std::string> args;

    // one arg
    EXPECT_EQ(Option::GetOptionValue(args = ONE_ARGS_WITH_VALUE, OPTION_NAME, boolVal), true);
    EXPECT_EQ(args.size(), ONE_ARGS_WITH_VALUE.size() - 1u); // only one option should eat
    EXPECT_EQ(boolVal, true);
    EXPECT_EQ(Option::GetOptionValue(args = ONE_ARGS_WITH_VALUE, OPTION_ERROR_NAME, boolVal), true);
    EXPECT_EQ(boolVal, true);
    EXPECT_EQ(Option::GetOptionValue(args = ONE_ARGS_WITH_VALUE, OPTION_NAME, boolVal), true);
    EXPECT_EQ(boolVal, true);
    EXPECT_EQ(Option::GetOptionValue(args = ONE_ARGS_WITH_VALUE, OPTION_ILLEGAL_NAME, boolVal),
              false);
    EXPECT_EQ(boolVal, true);

    // two arg
    EXPECT_EQ(Option::GetOptionValue(args = TWO_ARGS_WITH_VALUE, OPTION_NAME, boolVal), true);
    EXPECT_EQ(args.size(), TWO_ARGS_WITH_VALUE.size() - 1u);
    EXPECT_EQ(boolVal, true);
    EXPECT_EQ(Option::GetOptionValue(args = TWO_ARGS_WITH_VALUE, OPTION_ERROR_NAME, boolVal), true);
    EXPECT_EQ(boolVal, true);
    EXPECT_EQ(Option::GetOptionValue(args = TWO_ARGS_WITH_VALUE, OPTION_NAME, boolVal), true);
    EXPECT_EQ(boolVal, true);
    EXPECT_EQ(Option::GetOptionValue(args = TWO_ARGS_WITH_VALUE, OPTION_ILLEGAL_NAME, boolVal),
              false);
    EXPECT_EQ(boolVal, true);

    // two error arg
    EXPECT_EQ(Option::GetOptionValue(args = TWO_ERROR_WITH_VALUE, OPTION_NAME, boolVal), true);
    EXPECT_EQ(boolVal, true);
    EXPECT_EQ(Option::GetOptionValue(args = TWO_ERROR_WITH_VALUE, OPTION_ERROR_NAME, boolVal),
              true);
    EXPECT_EQ(boolVal, true);
    EXPECT_EQ(Option::GetOptionValue(args = TWO_ERROR_WITH_VALUE, OPTION_NAME, boolVal), true);
    EXPECT_EQ(boolVal, true);
    EXPECT_EQ(Option::GetOptionValue(args = TWO_ERROR_WITH_VALUE, OPTION_ILLEGAL_NAME, boolVal),
              false);
    EXPECT_EQ(boolVal, true);

    // mix arg
    EXPECT_EQ(Option::GetOptionValue(args = MIX_ARGS_1_WITH_VALUE, OPTION_NAME, boolVal), true);
    EXPECT_EQ(boolVal, true);
    EXPECT_EQ(Option::GetOptionValue(args = MIX_ARGS_1_WITH_VALUE, OPTION_ERROR_NAME, boolVal),
              true);
    EXPECT_EQ(boolVal, true);
    EXPECT_EQ(Option::GetOptionValue(args = MIX_ARGS_2_WITH_VALUE, OPTION_NAME, boolVal), true);
    EXPECT_EQ(boolVal, true);
    EXPECT_EQ(Option::GetOptionValue(args = MIX_ARGS_2_WITH_VALUE, OPTION_ERROR_NAME, boolVal),
              true);
    EXPECT_EQ(boolVal, true);
    EXPECT_EQ(Option::GetOptionValue(args = MIX_ARGS_2_WITH_VALUE, OPTION_ILLEGAL_NAME, boolVal),
              false);
    EXPECT_EQ(boolVal, true);
}

/**
 * @tc.name: TestGetOptionInt
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, GetOptionInt, TestSize.Level1)
{
    int intValue;
    std::vector<std::string> args;

    // one arg
    EXPECT_EQ(Option::GetOptionValue(args = ONE_ARGS_WITH_VALUE, OPTION_NAME, intValue), true);
    EXPECT_EQ(intValue, OPTION_INT_VALUE);

    EXPECT_EQ(Option::GetOptionValue(args = ONE_ARGS_WITH_VALUE, OPTION_ERROR_NAME, intValue),
              true);
    EXPECT_EQ(intValue, OPTION_INT_VALUE);

    // two arg
    EXPECT_EQ(Option::GetOptionValue(args = TWO_ARGS_WITH_VALUE, OPTION_NAME, intValue), true);
    EXPECT_EQ(intValue, OPTION_INT_VALUE);

    EXPECT_EQ(Option::GetOptionValue(args = TWO_ARGS_WITH_VALUE, OPTION_ERROR_NAME, intValue),
              true);
    EXPECT_EQ(intValue, OPTION_INT_VALUE);

    EXPECT_EQ(Option::GetOptionValue(args = TWO_ARGS_WITH_VALUE, OPTION_ILLEGAL_NAME, intValue),
              false);
    EXPECT_EQ(intValue, OPTION_INT_VALUE);

    // two error arg
    EXPECT_EQ(Option::GetOptionValue(args = TWO_ERROR_WITH_VALUE, OPTION_NAME, intValue), true);
    EXPECT_EQ(intValue, OPTION_INT_VALUE);

    EXPECT_EQ(Option::GetOptionValue(args = TWO_ERROR_WITH_VALUE, OPTION_ERROR_NAME, intValue),
              true);
    EXPECT_EQ(intValue, OPTION_INT_VALUE);


    EXPECT_EQ(Option::GetOptionValue(args = TWO_ERROR_WITH_VALUE, OPTION_ILLEGAL_NAME, intValue),
              false);
    EXPECT_EQ(intValue, OPTION_INT_VALUE);
}
/**
 * @tc.name: TestGetOptionInt
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, GetOptionInt2, TestSize.Level2)
{
    int intValue;
    std::vector<std::string> args;

    // mix arg
    EXPECT_EQ(Option::GetOptionValue(args = MIX_ARGS_1_WITH_VALUE, OPTION_NAME, intValue), true);
    EXPECT_EQ(intValue, OPTION_INT_VALUE);

    EXPECT_EQ(Option::GetOptionValue(args = MIX_ARGS_1_WITH_VALUE, OPTION_ERROR_NAME, intValue),
              true);
    EXPECT_EQ(intValue, OPTION_INT_VALUE);

    EXPECT_EQ(Option::GetOptionValue(args = MIX_ARGS_2_WITH_VALUE, OPTION_NAME, intValue), true);
    EXPECT_EQ(intValue, OPTION_INT_VALUE);

    EXPECT_EQ(Option::GetOptionValue(args = MIX_ARGS_2_WITH_VALUE, OPTION_ERROR_NAME, intValue),
              true);
    EXPECT_EQ(intValue, OPTION_INT_VALUE);

    EXPECT_EQ(Option::GetOptionValue(args = MIX_ARGS_2_WITH_VALUE, OPTION_ILLEGAL_NAME, intValue),
              false);
    EXPECT_EQ(intValue, OPTION_INT_VALUE);

    EXPECT_EQ(Option::GetOptionValue(args = MIX_ARGS_2_WITH_ILLEGAL_VALUE, OPTION_NAME, intValue),
              false);
    EXPECT_EQ(intValue, OPTION_INT_VALUE);
}

/**
 * @tc.name: TestGetOptionString
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, GetOptionString, TestSize.Level1)
{
    std::string stringValue;
    std::vector<std::string> args;

    // one arg
    EXPECT_EQ(Option::GetOptionValue(args = ONE_ARGS_WITH_VALUE, OPTION_NAME, stringValue), true);
    EXPECT_EQ(stringValue, OPTION_STRING_VALUE);
    stringValue.clear();

    EXPECT_EQ(Option::GetOptionValue(args = ONE_ARGS_WITH_VALUE, OPTION_ERROR_NAME, stringValue),
              true);
    EXPECT_EQ(stringValue.empty(), true);
    stringValue.clear();

    // two arg
    EXPECT_EQ(Option::GetOptionValue(args = TWO_ARGS_WITH_VALUE, OPTION_NAME, stringValue), true);
    EXPECT_EQ(stringValue, OPTION_STRING_VALUE);
    stringValue.clear();

    EXPECT_EQ(Option::GetOptionValue(args = TWO_ARGS_WITH_VALUE, OPTION_ERROR_NAME, stringValue),
              true);
    EXPECT_EQ(stringValue.empty(), true);
    stringValue.clear();

    EXPECT_EQ(Option::GetOptionValue(args = TWO_ARGS_WITH_VALUE, OPTION_ILLEGAL_NAME, stringValue),
              false);
    EXPECT_EQ(stringValue.empty(), true);
    stringValue.clear();

    // two error arg
    EXPECT_EQ(Option::GetOptionValue(args = TWO_ERROR_WITH_VALUE, OPTION_NAME, stringValue), true);
    EXPECT_EQ(stringValue.empty(), true);
    stringValue.clear();

    EXPECT_EQ(Option::GetOptionValue(args = TWO_ERROR_WITH_VALUE, OPTION_ERROR_NAME, stringValue),
              true);
    EXPECT_EQ(stringValue, OPTION_STRING_VALUE);
    stringValue.clear();

    EXPECT_EQ(Option::GetOptionValue(args = TWO_ERROR_WITH_VALUE, OPTION_ILLEGAL_NAME, stringValue),
              false);
    EXPECT_EQ(stringValue.empty(), true);
    stringValue.clear();
}

/**
 * @tc.name: TestGetOptionString
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, GetOptionString2, TestSize.Level2)
{
    std::string stringValue;
    std::vector<std::string> args;

    // mix arg
    EXPECT_EQ(Option::GetOptionValue(args = MIX_ARGS_1_WITH_VALUE, OPTION_NAME, stringValue), true);
    EXPECT_EQ(stringValue, OPTION_STRING_VALUE);
    stringValue.clear();

    EXPECT_EQ(Option::GetOptionValue(args = MIX_ARGS_1_WITH_VALUE, OPTION_ERROR_NAME, stringValue),
              true);
    EXPECT_EQ(stringValue, OPTION_STRING_VALUE);
    stringValue.clear();

    EXPECT_EQ(Option::GetOptionValue(args = MIX_ARGS_2_WITH_VALUE, OPTION_NAME, stringValue), true);
    EXPECT_EQ(stringValue, OPTION_STRING_VALUE);
    stringValue.clear();

    EXPECT_EQ(Option::GetOptionValue(args = MIX_ARGS_2_WITH_VALUE, OPTION_ERROR_NAME, stringValue),
              true);
    EXPECT_EQ(stringValue, OPTION_STRING_VALUE);
    stringValue.clear();

    EXPECT_EQ(
        Option::GetOptionValue(args = MIX_ARGS_2_WITH_VALUE, OPTION_ILLEGAL_NAME, stringValue),
        false);
    EXPECT_EQ(stringValue.empty(), true);
    stringValue.clear();
}

/**
 * @tc.name: TestGetOptionStrings
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, GetOptionStrings, TestSize.Level1)
{
    std::vector<std::string> stringValues;
    const std::vector<std::string> constargs = {OPTION_NAME, OPTION_STRING_THREE_VALUES,
                                                OPTION_ERROR_NAME};
    std::vector<std::string> args;
    EXPECT_EQ(Option::GetOptionValue(args = constargs, OPTION_NAME, stringValues), true);
    EXPECT_EQ(stringValues.size(), 3u);

    // if is error name , value should same as we passed
    // in this case it should be 3 from last test case
    args = constargs;
    EXPECT_EQ(Option::GetOptionValue(args = constargs, OPTION_ERROR_NAME, stringValues), false);
    EXPECT_EQ(stringValues.size(), 3u);
}

/**
 * @tc.name: TestGetOptionStringss
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, GetOptionStringss, TestSize.Level2)
{
    std::vector<std::vector<std::string>> stringValuess;
    const std::vector<std::string> constArgs = {
        OPTION_NAME,
        OPTION_STRING_THREE_VALUES,
        OPTION_ERROR_NAME,
        OPTION_NAME,
        OPTION_STRING_THREE_VALUES,
        OPTION_NAME,
        OPTION_STRING_THREE_VALUES,
        OPTION_NAME,
        OPTION_STRING_THREE_VALUES,
        OPTION_NAME_ONLY,
    };
    std::vector<std::string> args;

    EXPECT_EQ(Option::GetOptionValue(args = constArgs, OPTION_NAME, stringValuess), true);
    EXPECT_EQ(stringValuess.size(), 4u);

    // OPTION_NAME will be use like value, so result size is 1
    args = constArgs;
    EXPECT_EQ(Option::GetOptionValue(args = constArgs, OPTION_ERROR_NAME, stringValuess), true);
    EXPECT_EQ(stringValuess.size(), 1u);

    args = constArgs;
    EXPECT_EQ(Option::GetOptionValue(args = constArgs, OPTION_NAME_ONLY, stringValuess), false);
    // last time it cahnge to 1
    EXPECT_EQ(stringValuess.size(), 1u);

    args = constArgs;
    // void name
    EXPECT_EQ(Option::GetOptionValue(args = constArgs, OPTION_NAME_VOID, stringValuess), true);
    EXPECT_EQ(stringValuess.size(), 1u);
}

/**
 * @tc.name: TestGetOptionInts
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, GetOptionInts, TestSize.Level1)
{
    std::vector<int> intValues;
    const std::vector<std::string> constArgs = {OPTION_NAME, OPTION_STRING_THREE_VALUES,
                                                OPTION_ERROR_NAME};
    const std::vector<std::string> constIllegalArgs = {
        OPTION_NAME, OPTION_STRING_THREE_ILLEGAL_VALUES, OPTION_ERROR_NAME};
    std::vector<std::string> args;

    EXPECT_EQ(Option::GetOptionValue(args = constArgs, OPTION_NAME, intValues), true);
    EXPECT_EQ(intValues.size(), 3u);

    // should still same , not incress
    EXPECT_EQ(Option::GetOptionValue(args = constArgs, OPTION_NAME, intValues), true);
    EXPECT_EQ(intValues.size(), 3u);

    // should not change if false
    EXPECT_EQ(Option::GetOptionValue(args = constArgs, OPTION_ERROR_NAME, intValues), false);
    EXPECT_EQ(intValues.size(), 3u);

    // should not change if false
    EXPECT_EQ(Option::GetOptionValue(args = constIllegalArgs, OPTION_NAME, intValues), false);
    EXPECT_EQ(intValues.size(), 3u);
}

/**
 * @tc.name: TestGetValueFromStringBool
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestGetValueFromStringBool, TestSize.Level2)
{
    bool boolValue;
    EXPECT_EQ(Option::GetValueFromString(OPTION_NAME, OPTION_NAME, boolValue), true);
    EXPECT_EQ(boolValue, true);
}

/**
 * @tc.name: TestGetValueFromStringInt01
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestGetValueFromStringInt01, TestSize.Level0)
{
    int intValue;
    EXPECT_EQ(Option::GetValueFromString(OPTION_STRING_VALUE, OPTION_NAME, intValue), true);
    EXPECT_EQ(intValue, 3);
}

/**
 * @tc.name: TestGetValueFromStringInt02
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestGetValueFromStringInt02, TestSize.Level1)
{
    int intValue = 0;
    EXPECT_EQ(Option::GetValueFromString("a111", OPTION_NAME, intValue), false);  // "a111" can not trans to int
}

/**
 * @tc.name: TestGetValueFromStringInt03
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestGetValueFromStringInt03, TestSize.Level2)
{
    int intValue;
    EXPECT_EQ(Option::GetValueFromString("1a11", OPTION_NAME, intValue), false);  // "1a11" can not trans to int
}

/**
 * @tc.name: TestGetValueFromStringInt04
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestGetValueFromStringInt04, TestSize.Level2)
{
    int intValue;
    EXPECT_EQ(Option::GetValueFromString("-1", OPTION_NAME, intValue), true);  // "-1" can trans to int -1
    EXPECT_EQ(intValue, -1);
}

/**
 * @tc.name: TestGetValueFromStringInt05
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestGetValueFromStringInt05, TestSize.Level2)
{
    int intValue;
    EXPECT_EQ(Option::GetValueFromString("2147483648", OPTION_NAME, intValue), false);  // "2147483648": INT_MAX + 1
    EXPECT_EQ(intValue, 0);
}

/**
 * @tc.name: TestGetValueFromStringFloat01
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestGetValueFromStringFloat01, TestSize.Level1)
{
    float floatValue;
    EXPECT_EQ(Option::GetValueFromString(OPTION_STRING_VALUE, OPTION_NAME, floatValue), true);
    EXPECT_EQ(floatValue, 3.0);
}

/**
 * @tc.name: TestGetValueFromStringFloat02
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestGetValueFromStringFloat02, TestSize.Level2)
{
    float floatValue;
    EXPECT_EQ(Option::GetValueFromString("a13", OPTION_NAME, floatValue), false);  // "a.13" can not trans to float
}

/**
 * @tc.name: TestGetValueFromStringFloat03
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestGetValueFromStringFloat03, TestSize.Level2)
{
    float floatValue;
    float result = 0.1;  // 0.1: test value
    EXPECT_EQ(Option::GetValueFromString(".1", OPTION_NAME, floatValue), true);  // ".1" can trans to float 0.1
    EXPECT_EQ(floatValue, result);
}

/**
 * @tc.name: TestGetValueFromStringFloat04
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestGetValueFromStringFloat04, TestSize.Level3)
{
    float floatValue;
    double doubleMax = DBL_MAX;
    EXPECT_EQ(Option::GetValueFromString(std::to_string(doubleMax), OPTION_NAME, floatValue), false);
}

/**
 * @tc.name: TestGetValueFromStringString
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestGetValueFromStringString, TestSize.Level1)
{
    std::string stringValue;
    EXPECT_EQ(Option::GetValueFromString(OPTION_NAME, OPTION_NAME, stringValue), true);
    EXPECT_EQ(stringValue, OPTION_NAME);
}

/**
 * @tc.name: TestGetValueFromStringInts01
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestGetValueFromStringInts01, TestSize.Level0)
{
    std::vector<int> values;
    EXPECT_EQ(Option::GetValueFromString(OPTION_STRING_THREE_VALUES, OPTION_NAME, values), true);
    EXPECT_EQ(values.size(), 3u);
}

/**
 * @tc.name: TestGetValueFromStringInts02
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestGetValueFromStringInts02, TestSize.Level3)
{
    std::vector<int> values;
    EXPECT_EQ(Option::GetValueFromString(OPTION_STRING_THREE_ILLEGAL_VALUES, OPTION_NAME, values), false);
    EXPECT_EQ(values.size(), 1u); // values: {1}
}

/**
 * @tc.name: TestGetValueFromStringStrings
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestGetValueFromStringStrings, TestSize.Level1)
{
    std::vector<std::string> values;
    EXPECT_EQ(Option::GetValueFromString(OPTION_STRING_THREE_VALUES, OPTION_NAME, values), true);
    EXPECT_EQ(values.size(), 3u);
}

/**
 * @tc.name: TestGetOptionTrackedCommand
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestGetOptionTrackedCommand, TestSize.Level0)
{
    std::vector<std::string> args;
    args = {OPTION_NAME, OPTION_STRING_THREE_VALUES, OPTION_ERROR_NAME};
    std::vector<std::string> trackedCommand;
    EXPECT_EQ(Option::GetOptionTrackedCommand(args, trackedCommand), true);
    EXPECT_EQ(trackedCommand.size(), 3u);
    EXPECT_EQ(args.size(), 0u);
}

/**
 * @tc.name: TestGetValueFromStringUINT64_T01
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestGetValueFromStringUINT64_T01, TestSize.Level2)
{
    static constexpr uint64_t EXPECT = 1234;
    uint64_t value = 0;
    EXPECT_EQ(Option::GetValueFromString("1234", OPTION_NAME, value), true);
    EXPECT_EQ(value, EXPECT);
}

/**
 * @tc.name: TestGetValueFromStringUINT64_T02
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestGetValueFromStringUINT64_T02, TestSize.Level3)
{
    uint64_t value;
    EXPECT_EQ(Option::GetValueFromString("1a00", OPTION_NAME, value), false); // "1a00" can not trans to uint64_t
}

/**
 * @tc.name: TestGetValueFromStringUINT64_T03
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OptionTest, TestGetValueFromStringUINT64_T03, TestSize.Level3)
{
    uint64_t value = 0;
    // 18446744073709551616: UINT64_T_MAX +1
    EXPECT_EQ(Option::GetValueFromString("18446744073709551616", OPTION_NAME, value), false);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
