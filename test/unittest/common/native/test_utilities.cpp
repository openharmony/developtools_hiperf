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
#include <cstdio>
#include <iostream>
#include "test_utilities.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
bool CheckTestApp(const std::string& appName)
{
    FILE *fp = nullptr;
    char buf[128] = {0}; // 128: buf size
    std::string cmd = "pidof " + appName;
    if ((fp = popen(cmd.c_str(), "r")) != nullptr) {
        if (fgets(buf, sizeof(buf), fp) == nullptr) {
            pclose(fp);
            return false;
        }
        pclose(fp);
    }
    return true;
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS