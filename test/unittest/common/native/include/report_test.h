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

#ifndef REPORT_TEST
#define REPORT_TEST

#include <gtest/gtest.h>
#include <hilog/log.h>

#include "debug_logger.h"
#include "report.h"
#include "utilities.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
template<class T>
void CompareNumberTest(T &lowValue, T &midValue, T &highValue,
                       ReportKeyCompareFunction &compareFunction)
{
    EXPECT_EQ(compareFunction(lowValue, lowValue) == 0, true);
    EXPECT_EQ(compareFunction(lowValue, midValue) < 0, true);
    EXPECT_EQ(compareFunction(lowValue, highValue) < 0, true);
    EXPECT_EQ(compareFunction(highValue, midValue) > 0, true);
    EXPECT_EQ(compareFunction(highValue, lowValue) > 0, true);
}

template<class T>
void CompareStringTest(T &lowValue, T &midValue, T &highValue,
                       ReportKeyCompareFunction &compareFunction)
{
    EXPECT_EQ(compareFunction(lowValue, lowValue) == 0, true);
    EXPECT_EQ(compareFunction(lowValue, midValue) < 0, true);
    EXPECT_EQ(compareFunction(lowValue, highValue) < 0, true);
    EXPECT_EQ(compareFunction(highValue, midValue) > 0, true);
    EXPECT_EQ(compareFunction(highValue, lowValue) > 0, true);
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS

#endif // REPORT_TEST
