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

#include "ClientApi_fuzzer.h"

using namespace OHOS::Developtools::HiPerf;

namespace OHOS {
const static int32_t MAX_TEST_ARGS_NUMBER = 20;
const static size_t MAX_TEST_ARGS_LEN = 4096;
std::vector<std::string> DataToStringVector(const uint8_t *data, size_t size)
{
    const char *argptr = reinterpret_cast<const char *>(data);
    const char *argsdata = argptr;
    std::vector<std::string> argv;
    // argv[*]
    for (size_t i = 0; i < std::min(MAX_TEST_ARGS_LEN, size); i++) {
        if (argsdata[i] == '\0') {
            argv.emplace_back(argptr);
            argptr = &argsdata[i + 1];
        }
        if (argv.size() > MAX_TEST_ARGS_NUMBER) {
            break;
        }
    }
    return argv;
}

std::vector<pid_t> DataToPidVector(const uint8_t *data, size_t size)
{
    std::vector<pid_t> argv;
    // argv[*]
    for (size_t i = 0; i < std::min(MAX_TEST_ARGS_LEN, size); i++) {
        argv.emplace_back(static_cast<int>(data[i]));
        if (argv.size() > MAX_TEST_ARGS_NUMBER) {
            break;
        }
    }
    return argv;
}

bool FuzzClientApiOption(const uint8_t *data, size_t size)
{
    HiperfClient::RecordOption opt;
    std::string stringArg(reinterpret_cast<const char *>(data), size);
    std::vector<std::string> stringArgs = DataToStringVector(data, size);
    std::vector<pid_t> pids = DataToPidVector(data, size);

    opt.SetOutputFilename(stringArg);
    opt.SetTimeStopSec(size);
    opt.SetFrequency(size);
    opt.SetPeriod(size);
    opt.SetSelectEvents(stringArgs);
    opt.SetSelectGroups(stringArgs);
    opt.SetSelectPids(pids);
    opt.SetSelectTids(pids);
    opt.SetCpuPercent(size);
    opt.SetCallGraph(stringArg);
    opt.SetSymbolDir(stringArg);
    opt.SetDataLimit(stringArg);
    opt.SetAppPackage(stringArg);
    opt.SetClockId(stringArg);
    opt.SetVecBranchSampleTypes(stringArgs);
    opt.SetMmapPages(size);
    opt.GetOptionVecString();

    HiperfClient::Client myHiperf;
    myHiperf.Start(opt);
    myHiperf.Stop();
    return 0;
}

bool FuzzClientApiClient(const uint8_t *data, size_t size)
{
    HiperfClient::Client myHiperf;
    std::string stringArg(reinterpret_cast<const char *>(data), size);
    std::vector<std::string> stringArgs = DataToStringVector(data, size);

    myHiperf.Setup(stringArg);
    myHiperf.IsReady();
    myHiperf.Start(stringArgs);
    myHiperf.Pause();
    myHiperf.Resume();
    myHiperf.Stop();
    return 0;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
/* Run your code on data */
#ifdef DEBUG_HIPERF_FUZZ
    ScopeDebugLevel mix(LEVEL_DEBUG, true);
    DebugLogger::GetInstance()->Disable(false);
#else
    OHOS::Developtools::HiPerf::StdoutRecord noStdOut("/dev/null", "w");
#endif

    OHOS::FuzzClientApiClient(data, size);
    OHOS::FuzzClientApiOption(data, size);
    return 0;
}
