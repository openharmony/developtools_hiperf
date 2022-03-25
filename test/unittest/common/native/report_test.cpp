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

#include "report_test.h"

#include <bitset>
#include <gmock/gmock.h>
#include <sys/ioctl.h>

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
using namespace ::testing;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class ReportTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::unique_ptr<Report> report_ = nullptr;
};

void ReportTest::SetUpTestCase() {}

void ReportTest::TearDownTestCase() {}

void ReportTest::SetUp()
{
    report_ = std::make_unique<Report>();
    report_->configs_.emplace_back("dummy", 0, 0);
    report_->configIdIndexMaps_.emplace(0u, 0u); // id 0 as config 0
}

void ReportTest::TearDown() {}

void GetNumberTest(const ReportItem &item, ReportKeyGetFunction &getFunction, uint64_t number,
                   size_t len)
{
    ASSERT_GE(len, 3u);
    std::string itemNumber = std::to_string(number);
    EXPECT_STREQ(getFunction(item, 0, "%*" PRIu64 "").c_str(), itemNumber.c_str());
    EXPECT_STREQ(getFunction(item, 1, "%*" PRIu64 "").c_str(), itemNumber.c_str());
    EXPECT_STREQ(getFunction(item, 3, "%*" PRIu64 "").c_str(), itemNumber.c_str());
    EXPECT_STREQ(getFunction(item, len + 1, "%*" PRIu64 "").c_str(), (" " + itemNumber).c_str());
    EXPECT_STREQ(getFunction(item, len + 2, "%*" PRIu64 "").c_str(), ("  " + itemNumber).c_str());
}

void GetNumberTest(const ReportItem &item, ReportKeyGetFunction &getFunction, int number,
                   size_t len)
{
    ASSERT_GE(len, 3u);
    std::string itemNumber = std::to_string(number);
    int num = 3;
    int num2 = 2;
    EXPECT_STREQ(getFunction(item, 0, "%*d").c_str(), itemNumber.c_str());
    EXPECT_STREQ(getFunction(item, 1, "%*d").c_str(), itemNumber.c_str());
    EXPECT_STREQ(getFunction(item, num, "%*d").c_str(), itemNumber.c_str());
    EXPECT_STREQ(getFunction(item, len + 1, "%*d").c_str(), (" " + itemNumber).c_str());
    EXPECT_STREQ(getFunction(item, len + num2, "%*d").c_str(), ("  " + itemNumber).c_str());
}

void GetStringTest(const ReportItem &item, ReportKeyGetFunction &getFunction,
                   const std::string_view &itemString, size_t len)
{
    int num = 3;
    int num2 = 2;
    ASSERT_GE(len, 3u);
    EXPECT_STREQ(getFunction(item, 0, "%-*s").c_str(), itemString.data());
    EXPECT_STREQ(getFunction(item, 1, "%-*s").c_str(), itemString.data());
    EXPECT_STREQ(getFunction(item, num, "%-*s").c_str(), itemString.data());
    EXPECT_STREQ(getFunction(item, len + 1, "%-*s").c_str(),
                 (std::string(itemString) + " ").c_str());
    EXPECT_STREQ(getFunction(item, len + num2, "%-*s").c_str(),
                 (std::string(itemString) + "  ").c_str());
}

/**
 * @tc.name: ReportItemCallFrame Same
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, ReportItemCallFrameSame, TestSize.Level1)
{
    ReportItemCallFrame a("a", 0x0, "aa", 0, 0);
    ReportItemCallFrame aDuplicated("a", 0x0, "aa", 0, 0);
    ReportItemCallFrame a2("a2", 0x0, "aa", 0, 0);
    ReportItemCallFrame aDiffAddr("a", 0x1234, "aa", 0, 0);
    ReportItemCallFrame aDiffEvent("a", 0, "aa", 1234, 0);
    ReportItemCallFrame aDiffSelfEvent("a", 0, "aa", 0, 1234);
    ReportItemCallFrame aDiffDso("a", 0, "aa1234", 0, 1234);
    ReportItemCallFrame b("b", 0x0, "bb", 0, 0);

    EXPECT_EQ(a == a, true);
    EXPECT_EQ(a != a, false);
    EXPECT_EQ(a == aDuplicated, true);
    EXPECT_EQ(a == a2, false);
    EXPECT_EQ(a == aDiffAddr, false);
    EXPECT_EQ(a == aDiffEvent, true);
    EXPECT_EQ(a == aDiffSelfEvent, true);
    EXPECT_EQ(a == aDiffDso, false);
    EXPECT_EQ(a == b, false);
}

/**
 * @tc.name: CompareSortingEventCount
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, CompareSortingEventCount, TestSize.Level1)
{
    ReportItemCallFrame a("a", 0x0, "aa", 0, 0);
    ReportItemCallFrame a2("a", 0x0, "aa", 2, 0);
    ReportItemCallFrame a200("a", 0x0, "aa", 200, 0);

    EXPECT_EQ(ReportItemCallFrame::CompareSortingEventCount(a, a), false);
    EXPECT_EQ(ReportItemCallFrame::CompareSortingEventCount(a, a2), false);
    EXPECT_EQ(ReportItemCallFrame::CompareSortingEventCount(a, a200), false);
    EXPECT_EQ(ReportItemCallFrame::CompareSortingEventCount(a2, a200), false);
    EXPECT_EQ(ReportItemCallFrame::CompareSortingEventCount(a200, a200), false);
    EXPECT_EQ(ReportItemCallFrame::CompareSortingEventCount(a200, a2), true);
    EXPECT_EQ(ReportItemCallFrame::CompareSortingEventCount(a200, a), true);
}

/**
 * @tc.name: OrderCallFrames
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, OrderCallFrames, TestSize.Level1)
{
    ReportItemCallFrame a100("a", 0x0, "aa", 100, 0);
    ReportItemCallFrame a200("a", 0x0, "aa", 200, 0);
    ReportItemCallFrame a300("a", 0x0, "aa", 300, 0);
    std::vector<ReportItemCallFrame> callframes;

    // check empty no error
    ReportItemCallFrame::OrderCallFrames(callframes);

    callframes.emplace_back(a100);
    callframes.emplace_back(a200);
    callframes.emplace_back(a200);
    callframes.emplace_back(a300);

    // check order
    ReportItemCallFrame::OrderCallFrames(callframes);
    ASSERT_EQ(callframes.size() == 4u, true);
    EXPECT_EQ(callframes[0] == a300, true);
    EXPECT_EQ(callframes[1] == a200, true);
    EXPECT_EQ(callframes[2] == a200, true);
    EXPECT_EQ(callframes[3] == a100, true);
}

/**
 * @tc.name: ReportItemSame
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, ReportItemSame, TestSize.Level1)
{
    ReportItem a(1, 2, "comm", "dso", "func", 0x123, 1000);
    ReportItem aDuplicated(1, 2, "comm", "dso", "func", 0x123, 1000);
    ReportItem aDiffPid(10, 2, "comm", "dso", "func", 0x123, 1000);
    ReportItem aDiffTid(1, 20, "comm", "dso", "func", 0x123, 1000);
    ReportItem aDiffComm(1, 2, "comm0", "dso", "func", 0x123, 1000);
    ReportItem aDiffDso(1, 2, "comm", "dso0", "func", 0x123, 1000);
    ReportItem aDiffFunc(1, 2, "comm", "dso", "func0", 0x123, 1000);
    ReportItem aDiffVaddr(1, 2, "comm", "dso", "func", 0x1230, 1000);
    ReportItem aDiffEventCount(1, 2, "comm", "dso", "func", 0x123, 10000);

    EXPECT_EQ(a == a, true);
    EXPECT_EQ(a != a, false);
    EXPECT_EQ(a == aDuplicated, true);

    EXPECT_EQ(a == aDiffPid, false);
    EXPECT_EQ(a == aDiffTid, false);
    EXPECT_EQ(a == aDiffComm, false);
    EXPECT_EQ(a == aDiffDso, false);
    EXPECT_EQ(a == aDiffFunc, false);
    EXPECT_EQ(a == aDiffVaddr, false);
    EXPECT_EQ(a == aDiffEventCount, true);
}

/**
 * @tc.name: ReportItemCompareSortingEventCount
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, ReportItemCompareSortingEventCount, TestSize.Level1)
{
    ReportItem a123(1, 2, "comm", "dso", "func", 0x123, 123);
    ReportItem a1234(1, 2, "comm", "dso", "func", 0x1234, 1234);
    ReportItem a12345(1, 2, "comm", "dso", "func", 0x12345, 12345);

    EXPECT_EQ(ReportItem::CompareSortingEventCount(a123, a123), false);
    EXPECT_EQ(ReportItem::CompareSortingEventCount(a123, a1234), false);
    EXPECT_EQ(ReportItem::CompareSortingEventCount(a123, a12345), false);
    EXPECT_EQ(ReportItem::CompareSortingEventCount(a1234, a12345), false);
    EXPECT_EQ(ReportItem::CompareSortingEventCount(a12345, a12345), false);
    EXPECT_EQ(ReportItem::CompareSortingEventCount(a12345, a1234), true);
    EXPECT_EQ(ReportItem::CompareSortingEventCount(a1234, a123), true);
}

/**
 * @tc.name: CompareEventCount
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, CompareEventCount, TestSize.Level1)
{
    ReportItem low(1, 4, "comm", "dso", "func", 0x123, 123);
    ReportItem mid(2, 5, "comm", "dso", "func", 0x1234, 1234);
    ReportItem high(3, 6, "comm", "dso", "func", 0x12345, 12345);
    CompareNumberTest(low, mid, high, ReportItem::CompareEventCount);
}

/**
 * @tc.name: GetEventCount
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, GetEventCount, TestSize.Level1)
{
    ReportItem a(123, 4, "comm", "dso", "func", 0x123, 123);
    GetNumberTest(a, ReportItem::GetEventCount, a.eventCount_,
                  std::to_string(a.eventCount_).length());
}

/**
 * @tc.name: ComparePid
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, ComparePid, TestSize.Level1)
{
    ReportItem low(1, 4, "comm", "dso", "func", 0x123, 123);
    ReportItem mid(2, 5, "comm", "dso", "func", 0x1234, 1234);
    ReportItem high(3, 6, "comm", "dso", "func", 0x12345, 12345);
    CompareNumberTest(low, mid, high, ReportItem::ComparePid);
}

/**
 * @tc.name: GetPid
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, GetPid, TestSize.Level1)
{
    ReportItem a(123, 456, "comm", "dso", "func", 0x123, 123);
    GetNumberTest(a, ReportItem::GetPid, a.pid_, std::to_string(a.pid_).length());
}

/**
 * @tc.name: CompareTid
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, CompareTid, TestSize.Level1)
{
    ReportItem low(1, 4, "comm", "dso", "func", 0x123, 123);
    ReportItem mid(2, 5, "comm", "dso", "func", 0x1234, 1234);
    ReportItem high(3, 6, "comm", "dso", "func", 0x12345, 12345);
    CompareNumberTest(low, mid, high, ReportItem::CompareTid);
}

/**
 * @tc.name: GetTid
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, GetTid, TestSize.Level1)
{
    ReportItem a(123, 456, "comm", "dso", "func", 0x123, 123);
    GetNumberTest(a, ReportItem::GetTid, a.tid_, std::to_string(a.tid_).length());
}

/**
 * @tc.name: CompareComm
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, CompareComm, TestSize.Level1)
{
    ReportItem low(1, 4, "comm", "dso", "func", 0x123, 123);
    ReportItem mid(2, 5, "domm", "dso", "func", 0x1234, 1234);
    ReportItem high(3, 6, "eomm", "dso", "func", 0x12345, 12345);
    CompareStringTest(low, mid, high, ReportItem::CompareComm);
}

/**
 * @tc.name: GetComm
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, GetComm, TestSize.Level1)
{
    ReportItem a(123, 4, "comm", "dso", "func", 0x123, 123);
    GetStringTest(a, ReportItem::GetComm, a.comm_, a.comm_.length());
}

/**
 * @tc.name: CompareFunc
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, CompareFunc, TestSize.Level1)
{
    ReportItem low(1, 4, "comm", "dso", "func", 0x123, 123);
    ReportItem mid(2, 5, "comm", "dso", "gunc", 0x1234, 1234);
    ReportItem high(3, 6, "comm", "dso", "hunc", 0x12345, 12345);
    CompareStringTest(low, mid, high, ReportItem::CompareFunc);
}

/**
 * @tc.name: GetFunc
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, GetFunc, TestSize.Level1)
{
    ReportItem a(123, 4, "comm", "dso", "func", 0x123, 123);
    GetStringTest(a, ReportItem::GetFunc, a.func_, a.func_.length());
}
/**
 * @tc.name: CompareDso
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, CompareDso, TestSize.Level1)
{
    ReportItem low(1, 4, "comm", "dso", "func", 0x123, 123);
    ReportItem mid(2, 5, "comm", "eso", "func", 0x1234, 1234);
    ReportItem high(3, 6, "comm", "fso", "func", 0x12345, 12345);
    CompareStringTest(low, mid, high, ReportItem::CompareDso);
}

/**
 * @tc.name: GetDso
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, GetDso, TestSize.Level1)
{
    ReportItem a(123, 4, "comm", "dso", "func", 0x123, 123);
    GetStringTest(a, ReportItem::GetDso, a.dso_, a.dso_.length());
}

/**
 * @tc.name: CompareFromDso
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, CompareFromDso, TestSize.Level1)
{
    ReportItem low(1, 4, "comm", "dso", "func", 0x123, 123);
    ReportItem mid(2, 5, "comm", "dso", "func", 0x1234, 1234);
    ReportItem high(3, 6, "comm", "dso", "func", 0x12345, 12345);
    low.fromDso_ = "fromDso";
    mid.fromDso_ = "gromDso";
    high.fromDso_ = "hromDso";
    CompareStringTest(low, mid, high, ReportItem::CompareFromDso);
}

/**
 * @tc.name: GetFromDso
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, GetFromDso, TestSize.Level1)
{
    ReportItem a(123, 4, "comm", "dso", "func", 0x123, 123);
    a.fromDso_ = "fromDso";
    GetStringTest(a, ReportItem::GetFromDso, a.fromDso_, a.fromDso_.length());
}

/**
 * @tc.name: CompareFromFunc
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, CompareFromFunc, TestSize.Level1)
{
    ReportItem low(1, 4, "comm", "dso", "func", 0x123, 123);
    ReportItem mid(2, 5, "comm", "dso", "func", 0x1234, 1234);
    ReportItem high(3, 6, "comm", "dso", "func", 0x12345, 12345);
    low.fromFunc_ = "fromFunc";
    mid.fromFunc_ = "gromFunc";
    high.fromFunc_ = "hromFunc";
    CompareStringTest(low, mid, high, ReportItem::CompareFromFunc);
}

/**
 * @tc.name: GetFromFunc
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, GetFromFunc, TestSize.Level1)
{
    ReportItem a(123, 4, "comm", "dso", "func", 0x123, 123);
    a.fromFunc_ = "fromFunc";
    GetStringTest(a, ReportItem::GetFromFunc, a.fromFunc_, a.fromFunc_.length());
}

/**
 * @tc.name: UpdateValueMaxLen
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, UpdateValueMaxLen, TestSize.Level1)
{
    ReportKey key = {
        "pid", ReportItem::ComparePid, ReportItem::GetPid, "%*d", std::vector<std::string>(),
    };

    key.UpdateValueMaxLen(1);
    key.UpdateValueMaxLen(11);
    key.UpdateValueMaxLen(111);
    key.UpdateValueMaxLen(12345678);
    key.UpdateValueMaxLen(1);
    key.UpdateValueMaxLen(111);
    EXPECT_STREQ(key.maxValue_.c_str(), "12345678");
    EXPECT_EQ(key.maxLen_, 8u);

    ReportKey func = {
        "func", ReportItem::CompareFunc, ReportItem::GetFunc, "%-*s", std::vector<std::string>(),
    };

    func.UpdateValueMaxLen("1");
    func.UpdateValueMaxLen("11");
    func.UpdateValueMaxLen("111");
    func.UpdateValueMaxLen("12345678");
    func.UpdateValueMaxLen("1");
    func.UpdateValueMaxLen("111");
    EXPECT_STREQ(func.maxValue_.c_str(), "12345678");
    EXPECT_EQ(func.maxLen_, 8u);
}

/**
 * @tc.name: GetValue
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, GetValue, TestSize.Level1)
{
    ReportKey key = {
        "pid", ReportItem::ComparePid, ReportItem::GetPid, "%*d", std::vector<std::string>(),
    };
    ReportItem a(123, 4, "comm", "dso", "func", 0x123, 123);

    EXPECT_STREQ(key.GetValue(a).c_str(), "123");
    key.maxLen_ = 10u;
    EXPECT_STREQ(key.GetValue(a).c_str(), "       123");
}

/**
 * @tc.name: ShouldDisplay
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, ShouldDisplay, TestSize.Level1)
{
    ReportOption option;
    ReportKey pidKey = {
        "pid", ReportItem::ComparePid, ReportItem::GetPid, "%*d", option.displayPids_,
    };
    ReportKey commKey = {
        "comm", ReportItem::CompareComm, ReportItem::GetComm, "%-*s", option.displayComms_,
    };
    ReportItem a(123, 4, "abc", "dso", "func", 0x123, 123);
    ReportItem b(12, 4, "ab", "dso", "func", 0x123, 123);
    ReportItem c(1, 4, "a", "dso", "func", 0x123, 123);

    option.displayPids_ = {"1"};
    EXPECT_EQ(pidKey.ShouldDisplay(a), false);
    EXPECT_EQ(pidKey.ShouldDisplay(b), false);
    EXPECT_EQ(pidKey.ShouldDisplay(c), true);
    option.displayPids_.clear();

    option.displayComms_ = {"a", "ab"};
    EXPECT_EQ(commKey.ShouldDisplay(a), false);
    EXPECT_EQ(commKey.ShouldDisplay(b), true);
    EXPECT_EQ(commKey.ShouldDisplay(c), true);
    option.displayComms_.clear();

    option.displayComms_ = {"a", "ab", "abc"};
    EXPECT_EQ(commKey.ShouldDisplay(a), true);
    EXPECT_EQ(commKey.ShouldDisplay(b), true);
    EXPECT_EQ(commKey.ShouldDisplay(c), true);
    option.displayComms_.clear();

    option.displayComms_ = {"a", "ab", "abc", "d"};
    EXPECT_EQ(commKey.ShouldDisplay(a), true);
    EXPECT_EQ(commKey.ShouldDisplay(b), true);
    EXPECT_EQ(commKey.ShouldDisplay(c), true);
    option.displayComms_.clear();
}

/**
 * @tc.name: MultiLevelSame
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, MultiLevelSame, TestSize.Level1)
{
    class ReportMock : public Report {
    public:
        MOCK_METHOD2(MultiLevelCompare, int(const ReportItem &a, const ReportItem &b));
    } report;
    ReportItem dummy(0, 0, "comm", "", "", 0, 0);

    EXPECT_CALL(report, MultiLevelCompare(_, _)).WillOnce(Return(0));
    EXPECT_EQ(report.MultiLevelSame(dummy, dummy), true);

    EXPECT_CALL(report, MultiLevelCompare(_, _)).WillOnce(Return(1));
    EXPECT_EQ(report.MultiLevelSame(dummy, dummy), false);

    EXPECT_CALL(report, MultiLevelCompare(_, _)).WillOnce(Return(-1));
    EXPECT_EQ(report.MultiLevelSame(dummy, dummy), false);
}

/**
 * @tc.name: MultiLevelSorting
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, MultiLevelSorting, TestSize.Level1)
{
    class ReportMock : public Report {
    public:
        MOCK_METHOD2(MultiLevelCompare, int(const ReportItem &a, const ReportItem &b));
    } report;
    ReportItem dummy(0, 0, "comm", "", "", 0, 0);

    EXPECT_CALL(report, MultiLevelCompare(_, _))
        .WillOnce(Return(0))
        .WillOnce(Return(0))
        .WillOnce(Return(0));
    EXPECT_EQ(report.MultiLevelCompare(dummy, dummy), 0);     // 1st
    EXPECT_EQ(report.MultiLevelSorting(dummy, dummy), false); // 2nd 3rd and > 0?

    EXPECT_CALL(report, MultiLevelCompare(_, _))
        .WillOnce(Return(1))
        .WillOnce(Return(1))
        .WillOnce(Return(-1));
    EXPECT_EQ(report.MultiLevelCompare(dummy, dummy), 1);
    EXPECT_EQ(report.MultiLevelSorting(dummy, dummy), true); // > 0?

    EXPECT_CALL(report, MultiLevelCompare(_, _))
        .WillOnce(Return(-1))
        .WillOnce(Return(-1))
        .WillOnce(Return(1));
    EXPECT_EQ(report.MultiLevelCompare(dummy, dummy), -1);
    EXPECT_EQ(report.MultiLevelSorting(dummy, dummy), false); // > 0?
}

/**
 * @tc.name: MultiLevelSameAndUpdateCount
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, MultiLevelSameAndUpdateCount, TestSize.Level1)
{
    class ReportMock : public Report {
    public:
        MOCK_METHOD2(MultiLevelCompare, int(const ReportItem &a, const ReportItem &b));
    } report;
    ReportItem dummy100(0, 0, "comm", "", "", 0x0, 100);
    ReportItem dummy200(0, 0, "comm", "", "", 0x0, 200);
    ReportItem dummy300(0, 0, "comm", "", "", 0x0, 300);

    EXPECT_EQ(dummy100.eventCount_, 100u);

    EXPECT_CALL(report, MultiLevelCompare(_, _)).WillOnce(Return(0));
    EXPECT_EQ(report.MultiLevelSameAndUpdateCount(dummy100, dummy200), true);
    // if true , 100 + 200
    EXPECT_EQ(dummy100.eventCount_, 300u);

    EXPECT_CALL(report, MultiLevelCompare(_, _)).WillOnce(Return(1));
    EXPECT_EQ(report.MultiLevelSameAndUpdateCount(dummy200, dummy200), false);
    EXPECT_EQ(dummy200.eventCount_, 200u);
    EXPECT_EQ(dummy300.eventCount_, 300u);

    EXPECT_CALL(report, MultiLevelCompare(_, _)).WillOnce(Return(-1));
    EXPECT_EQ(report.MultiLevelSameAndUpdateCount(dummy200, dummy200), false);
    EXPECT_EQ(dummy200.eventCount_, 200u);
    EXPECT_EQ(dummy300.eventCount_, 300u);
}

/**
 * @tc.name: MergeCallFrameCount
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, MergeCallFrameCount, TestSize.Level1)
{
    class ReportMock : public Report {
    public:
        MOCK_METHOD2(MultiLevelCompare, int(const ReportItem &a, const ReportItem &b));
    } report;
    ReportItem dummy100(0, 0, "comm", "", "", 0x0, 100);
    ReportItem dummy200(0, 0, "comm", "", "", 0x0, 200);
    ReportItem dummy300(0, 0, "comm", "", "", 0x0, 300);
    EXPECT_EQ(dummy100.eventCount_, 100u);
    ASSERT_EQ(dummy100.callStacks_.size(), 0u);

    /*
    we have a stack like
    dummy 100
       funcA 100
            funcB 100
                funcC 100
    dummy 200
       funcA 100
            funcB 100
    dummy 300
       funcA 100
            funcC 100

    after merge it should be change to
    dummy 600
       funcA 300
            funcB 200
                funcC 100
            funcC 100
    */
    {
        ReportItemCallFrame &child =
            dummy100.callStacks_.emplace_back("funcA", 0x1234, "dso", 100, 0);
        ReportItemCallFrame &child2 = child.childs.emplace_back("funcB", 0x1234, "dso", 100, 0);
        child2.childs.emplace_back("funcC", 0x1234, "dso", 100, 0);
    }

    {
        ReportItemCallFrame &child =
            dummy200.callStacks_.emplace_back("funcA", 0x1234, "dso", 100, 0);
        child.childs.emplace_back("funcB", 0x1234, "dso", 100, 0);
    }
    {
        ReportItemCallFrame &child =
            dummy300.callStacks_.emplace_back("funcA", 0x1234, "dso", 100, 0);
        child.childs.emplace_back("funcC", 0x1234, "dso", 100, 0);
    }
    dummy100.eventCount_ += dummy200.eventCount_;
    ASSERT_EQ(dummy100.callStacks_.size(), 1u);
    ASSERT_EQ(dummy200.callStacks_.size(), 1u);
    ASSERT_STREQ(dummy100.callStacks_[0].func_.data(), "funcA");
    ASSERT_STREQ(dummy200.callStacks_[0].func_.data(), "funcA");
    report_->MergeCallFrameCount(dummy100, dummy200);

    if (dummy100.callStacks_.size() >= 2) {
        printf("%s\n", dummy100.callStacks_[0].ToDebugString().c_str());
        printf("%s\n", dummy100.callStacks_[1].ToDebugString().c_str());
    }
    ASSERT_EQ(dummy100.callStacks_.size(), 1u);

    dummy100.eventCount_ += dummy300.eventCount_;
    report_->MergeCallFrameCount(dummy100, dummy300);

    ASSERT_EQ(dummy100.callStacks_.size(), 1u);
    ASSERT_STREQ(dummy100.callStacks_[0].func_.data(), "funcA");
    EXPECT_EQ(dummy100.callStacks_[0].eventCount_, 300u);

    ASSERT_STREQ(dummy100.callStacks_[0].childs[0].func_.data(), "funcB");
    EXPECT_EQ(dummy100.callStacks_[0].childs[0].eventCount_, 200u);

    ASSERT_STREQ(dummy100.callStacks_[0].childs[1].func_.data(), "funcC");
    EXPECT_EQ(dummy100.callStacks_[0].childs[1].eventCount_, 100u);

    ASSERT_EQ(dummy100.callStacks_[0].childs[0].childs.size(), 1u);
    ASSERT_STREQ(dummy100.callStacks_[0].childs[0].childs[0].func_.data(), "funcC");
    EXPECT_EQ(dummy100.callStacks_[0].childs[0].childs[0].eventCount_, 100u);
}

/**
 * @tc.name: MultiLevelCompare
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, MultiLevelCompare, TestSize.Level1)
{
    report_->option_.sortKeys_ = {"comm", "pid", "tid", "dso", "func"};

    ReportItem a(1, 2, "comm", "dso", "funca", 0x1, 4);
    ReportItem b(2, 3, "comm", "dso", "funcb", 0x2, 3);
    ReportItem c(3, 4, "comm", "dso", "funcc", 0x3, 2);
    ReportItem d(4, 5, "comm", "dso", "funcd", 0x4, 1);

    report_->option_.sortKeys_ = {"comm"};
    EXPECT_EQ(report_->MultiLevelCompare(a, b), 0);

    report_->option_.sortKeys_ = {"comm", "pid"};
    EXPECT_EQ(report_->MultiLevelCompare(a, b), -1);
}

/**
 * @tc.name: AddReportItem
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, AddReportItem, TestSize.Level1)
{
    PerfRecordSample sample(false, 0, 0, 1);
    sample.callFrames_.emplace_back(0x1, 0x1234, "frame1", "dummy");
    sample.callFrames_.emplace_back(0x2, 0x1234, "frame2", "dummy");
    sample.callFrames_.emplace_back(0x3, 0x1234, "frame3", "dummy");
    sample.callFrames_.emplace_back(0x3, 0x1234, "frame4", "dummy");

    // caller order should be
    // 4
    //  -> 3
    //       -> 2
    //            -> 1

    report_->AddReportItem(sample, false);
    auto &reportItems = report_->configs_[0].reportItems_;
    ASSERT_EQ(reportItems.size(), 1u);

    report_->AddReportItem(sample, true);
    ASSERT_EQ(reportItems.size(), 2u);

    // no call frame
    ASSERT_EQ(reportItems[0].callStacks_.size(), 0u);
    // have call frame
    ASSERT_EQ(reportItems[1].callStacks_.size(), 1u);

    // first on the end caller
    ASSERT_STREQ(reportItems[1].callStacks_[0].func_.data(), "frame4");
    ASSERT_EQ(reportItems[1].callStacks_[0].childs.size(), 1u);

    // next caller
    ASSERT_STREQ(reportItems[1].callStacks_[0].childs[0].func_.data(), "frame3");
    ASSERT_EQ(reportItems[1].callStacks_[0].childs[0].childs.size(), 1u);

    // next caller
    ASSERT_STREQ(reportItems[1].callStacks_[0].childs[0].childs[0].func_.data(), "frame2");
    ASSERT_EQ(reportItems[1].callStacks_[0].childs[0].childs.size(), 1u);

    // top called
    ASSERT_STREQ(reportItems[1].callStacks_[0].childs[0].childs[0].childs[0].func_.data(),
                 "frame1");
    ASSERT_EQ(reportItems[1].callStacks_[0].childs[0].childs[0].childs[0].childs.size(), 0u);

    report_->AddReportItem(sample, false);
    EXPECT_EQ(reportItems.size(), 3u);
}

/**
 * @tc.name: AddReportItem
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, AddReportItemBranch, TestSize.Level1)
{
    class PerfRecordSampleMock : public PerfRecordSample {
    public:
        PerfRecordSampleMock(bool inKernel, u32 pid, u32 tid, u64 period)
            : PerfRecordSample(inKernel, pid, tid, period)
        {
        }
    };
    PerfRecordSampleMock sample(false, 0, 0, 1);
    sample.data_.bnr = 3;
    sample.data_.lbr = new perf_branch_entry[sample.data_.bnr];
    sample.data_.lbr[0].to = 0x123400;
    sample.data_.lbr[0].from = 0x432100;
    sample.data_.lbr[1].to = 0x123401;
    sample.data_.lbr[1].from = 0x432101;
    sample.data_.lbr[2].to = 0x123402;
    sample.data_.lbr[2].from = 0x432102;

    sample.callFrames_.emplace_back(0x1, 0x1234, "frame1", "dummy");
    sample.callFrames_.emplace_back(0x2, 0x1234, "frame2", "dummy");
    sample.callFrames_.emplace_back(0x3, 0x1234, "frame3", "dummy");
    // vaddr is 0 , will not added
    sample.callFrames_.emplace_back(0x3, 0, "frame4", "dummy");

    report_->AddReportItemBranch(sample);
    // == nbr size
    ASSERT_EQ(report_->configs_[0].reportItems_.size(), 3u);
    // no call stack
    ASSERT_EQ(report_->configs_[0].reportItems_[0].callStacks_.size(), 0u);

    for (auto &reportItem : report_->configs_[0].reportItems_) {
        printf("reportItem %s\n", reportItem.ToDebugString().c_str());
    }
    EXPECT_STREQ(report_->configs_[0].reportItems_[0].func_.data(), "swapper@0x123400");
    EXPECT_STREQ(report_->configs_[0].reportItems_[1].func_.data(), "swapper@0x123401");
    EXPECT_STREQ(report_->configs_[0].reportItems_[2].func_.data(), "swapper@0x123402");
}

/**
 * @tc.name: PrepareConsole
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ReportTest, PrepareConsole, TestSize.Level1)
{
    struct winsize w = {0, 0, 0, 0};
    ioctl(fileno(stdout), TIOCGWINSZ, &w);
    report_->PrepareConsole();
    if (w.ws_col != 0) {
        EXPECT_EQ(report_->consoleWidth_, w.ws_col);
    } else {
        EXPECT_EQ(report_->consoleWidth_, report_->ConsoleDefaultWidth);
    }
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
