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
#include "test_utilities.h"

#include <securec.h>
#include <cinttypes>
#include <cstdio>
#include <iostream>

namespace OHOS {
namespace Developtools {
namespace HiPerf {
const int CMD_OUTPUT_BUF = 1024;

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

bool GetMemMapOffset(pid_t devhostPid, uint64_t &mapOffset,
                     std::vector<std::shared_ptr<OHOS::HiviewDFX::DfxMap>> &memMaps, std::string &line)
{
    pid_t pid = 0;
    pid_t tid = 0;
    uint64_t addr = 0;
    uint64_t len = 0;
    int ret = sscanf_s(line.c_str(), "  %*s %d, tid %d, addr 0x%" PRIx64 ", len 0x%" PRIx64 "",
                       &pid, &tid, &addr, &len);
    constexpr int numSlices {4};
    if (ret != numSlices) {
        printf("unknown line %d: '%s' \n", ret, line.c_str());
        return false;
    }
    if (devhostPid != pid || devhostPid != tid) {
        return false;
    }
    for (auto& map: memMaps) {
        if (map->begin == addr && map->end - map->begin == len) {
            mapOffset = map->offset;
            return true;
        }
    }
    return false;
}

bool RunCmd(const std::string& cmdstr)
{
    if (cmdstr.empty()) {
        return false;
    }
    FILE *fp = popen(cmdstr.c_str(), "r");
    if (fp == nullptr) {
        return false;
    }
    char res[CMD_OUTPUT_BUF] = { '\0' };
    while (fgets(res, sizeof(res), fp) != nullptr) {
        std::cout << res;
    }
    pclose(fp);
    return true;
}

bool CheckTraceCommandOutput(const std::string& cmd, const std::vector<std::string>& keywords)
{
    if (cmd.empty()) {
        return false;
    }
    FILE* fp = popen(cmd.c_str(), "r");
    if (fp == nullptr) {
        return false;
    }

    char buffer[CMD_OUTPUT_BUF];
    int checkIdx = 0;
    while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
        while (checkIdx < keywords.size() && strstr(buffer, keywords[checkIdx].c_str()) != nullptr) {
            GTEST_LOG_(INFO) << "match keyword :" << keywords[checkIdx];
            checkIdx++;
            if (checkIdx == keywords.size()) {
                break;
            }
        }
    }

    pclose(fp);
    if (checkIdx < keywords.size()) {
        GTEST_LOG_(ERROR) << "Failed to match keyword : " << keywords[checkIdx];
    }
    return checkIdx == keywords.size();
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
