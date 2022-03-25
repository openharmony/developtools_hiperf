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
#ifndef HIPERF_SYMBOLS_FILE_TEST
#define HIPERF_SYMBOLS_FILE_TEST

#include <string>

#include "debug_logger.h"
#include "symbols_file.h"
#include "utilities.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
static const std::string PATH_KALLSYMS = "/proc/kallsyms";
static const std::string PATH_NOT_EXISTS = "data/";
static const std::string PATH_DATA_TEMP = "/.";
static const std::string PATH_DATA_TEMP_WINDOS = "\\.";
static const std::string PATH_ILLEGAL = "!@#$%^&*()";
static const std::string PATH_RESOURCE_TEST_DATA = "resource/testdata/";
static const std::string PATH_RESOURCE_TEST_DATA_NO_ENDPATH = "resource/testdata";
// elf
#ifdef __arm__
static const std::string TEST_SYMBOLS_FILE_ELF {"symbols_file_test_elf32"};
static const std::string TEST_FILE_ELF = "elf32_test";
static const std::string TEST_FILE_ELF_STRIPPED = "elf32_test_stripped";
static const std::string TEST_FILE_ELF_STRIPPED_NOBUILDID = "elf32_test_stripped_nobuildid";
static const std::string TEST_FILE_ELF_STRIPPED_BROKEN = "elf32_test_stripped_broken";
static const std::string TEST_FILE_ELF_STRIPPED_NOEFHDR = "elf32_test_stripped_noehframehdr";
#else
static const std::string TEST_SYMBOLS_FILE_ELF {"symbols_file_test_elf64"};
static const std::string TEST_FILE_ELF = "elf_test";
static const std::string TEST_FILE_ELF_STRIPPED = "elf_test_stripped";
static const std::string TEST_FILE_ELF_STRIPPED_NOBUILDID = "elf_test_stripped_nobuildid";
static const std::string TEST_FILE_ELF_STRIPPED_BROKEN = "elf_test_stripped_broken";
static const std::string TEST_FILE_ELF_STRIPPED_NOEFHDR = "elf_test_stripped_noehframehdr";
#endif

// vmlinux
static const std::string TEST_FILE_VMLINUX = "vmlinux";
static const std::string TEST_FILE_VMLINUX_STRIPPED = "vmlinux_stripped";
static const std::string TEST_FILE_VMLINUX_STRIPPED_NOBUILDID = "vmlinux_stripped_nobuildid";
static const std::string TEST_FILE_VMLINUX_STRIPPED_BROKEN = "vmlinux_stripped_broken";

static const std::string KPTR_RESTRICT = "/proc/sys/kernel/kptr_restrict";

static const std::string TEST_FILE_SELF_ELF = "../../hiperf_test";
static const std::string TEST_FILE_ELF_FULL_PATH = PATH_RESOURCE_TEST_DATA + TEST_FILE_ELF;
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_SYMBOLS_FILE_TEST
