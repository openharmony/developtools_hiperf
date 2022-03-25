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

#ifndef SUBCOMMAND_HELP_TEST
#define SUBCOMMAND_HELP_TEST

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <hilog/log.h>

#include "debug_logger.h"
#include "subcommand.h"
#include "utilities.h"
namespace OHOS {
namespace Developtools {
namespace HiPerf {
static std::string TEST_CMD_HLP = "TEST_CMD_HLP";
static std::string TEST_HLP_BRIEF = " TEST_BRIEF\n";
static std::string TEST_HLP_HELP = " TEST_HELP\n";
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // SUBCOMMAND_HELP_TEST
