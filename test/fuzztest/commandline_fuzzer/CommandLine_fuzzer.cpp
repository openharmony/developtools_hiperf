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

#include "CommandLine_fuzzer.h"

extern int hiperf_fuzzer_main(const int argc, const char *argv[]);
namespace OHOS {
const static int32_t MAX_TEST_ARGS_NUMBER = 20;
const static size_t MAX_TEST_ARGS_LEN = 4096;

bool FuzzCommandLine(const char *subcommand, const uint8_t *data, size_t size)
{
    char buf[DATA_MAX_SIZE] = { 0 };
    if (memcpy_s(buf, sizeof(buf) - 1, data, size) != 0) { // 1 ：  make sure end of '\0'
        return false;
    }
    const char *argptr = reinterpret_cast<const char *>(buf);
    const char *argsdata = argptr;
    std::vector<const char *> argv;

    // argv[0]
    argv.emplace_back("hiperf");

    // argv[1]
    if (subcommand != nullptr and subcommand[0] != '\0') {
        argv.emplace_back(subcommand);
    }

    // argv[2]
    argv.emplace_back(argptr);

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
#ifdef DEBUG_HIPERF_FUZZ
    std::cout << " size " << argv.size() << std::endl;
#endif
    hiperf_fuzzer_main(static_cast<int>(argv.size()), argv.data());

    return 0;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#ifdef DEBUG_HIPERF_FUZZ
    ScopeDebugLevel mix(LEVEL_VERBOSE, true);
    DebugLogger::GetInstance()->Disable(false);
#else
    OHOS::Developtools::HiPerf::StdoutRecord noStdOut("/dev/null", "w");
#endif
    /* Run your code on data */
    OHOS::FuzzCommandLine("", data, size);
    OHOS::FuzzCommandLine("stat", data, size);
    OHOS::FuzzCommandLine("record", data, size);
    OHOS::FuzzCommandLine("report", data, size);
    OHOS::FuzzCommandLine("list", data, size);
    OHOS::FuzzCommandLine("help", data, size);
    return 0;
}
