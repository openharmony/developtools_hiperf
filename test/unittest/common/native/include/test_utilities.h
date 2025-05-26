/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef HIPERF_TEST_UTILITIES_H_
#define HIPERF_TEST_UTILITIES_H_

#include <gtest/gtest.h>
#include "dfx_map.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
bool CheckTestApp(const std::string& appName);
bool GetMemMapOffset(pid_t devhostPid, uint64_t &mapOffset,
                     std::vector<std::shared_ptr<OHOS::HiviewDFX::DfxMap>> &memMaps, std::string &line);
bool RunCmd(const std::string& cmdstr);
bool CheckTraceCommandOutput(const std::string& cmd, const std::vector<std::string>& keywords);
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_TEST_UTILITIES_H_
