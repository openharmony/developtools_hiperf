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
#ifndef HIPERF_CALLSTACK_TEST_H
#define HIPERF_CALLSTACK_TEST_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iterator>
#include <link.h>
#include <random>
#include <sys/mman.h>

#include <hilog/log.h>

#include "callstack.h"
#include "debug_logger.h"
#include "utilities.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
static const std::string PATH_RESOURCE_TEST_DWARF_DATA = "resource/testdata/dwarf/";
struct mmapDumpInfo {
    std::string fileName;
    uint64_t begin = 0;
    uint64_t len = 0;
    uint64_t pgoff = 0;
};

struct frame {
    uint64_t ip = 0;
    uint64_t sp = 0;
};
/*
    create from
    ./hiperf_example_cmd --thread 1 --time 60 --stack 10
    ./hiperf_host dump --userdata > dump.txt
*/
#ifdef __arm__
static const std::string TEST_DWARF_ELF = "hiperf_example_cmd";
/*
record mmap2: type 10, misc 2, size 107
  pid 643, tid 643, addr 0x454000, len 0x3000
  pgoff 0x0, maj 179, min 7, ino 4868, ino_generation 6874019636378171493
  prot 1, flags 2, filename /data/local/tmp/hiperf_example_cmd

record mmap2: type 10, misc 2, size 107
  pid 643, tid 643, addr 0x457000, len 0x5000
  pgoff 0x2000, maj 179, min 7, ino 4868, ino_generation 7237954708011182952
  prot 5, flags 2, filename /data/local/tmp/hiperf_example_cmd

record mmap2: type 10, misc 2, size 107
  pid 643, tid 643, addr 0x45c000, len 0x1000
  pgoff 0x6000, maj 179, min 7, ino 4868, ino_generation 7237954708011182952
  prot 1, flags 2, filename /data/local/tmp/hiperf_example_cmd

record mmap2: type 10, misc 2, size 107
  pid 643, tid 643, addr 0x45d000, len 0x1000
  pgoff 0x6000, maj 179, min 7, ino 4868, ino_generation 7237954708011182952
  prot 3, flags 2, filename /data/local/tmp/hiperf_example_cmd
*/
static const std::vector<mmapDumpInfo> TEST_DWARF_MMAP = {
    {"hiperf_example_cmd", 0x454000, 0x3000, 0x0},
    {"hiperf_example_cmd", 0x457000, 0x5000, 0x2000},
    {"hiperf_example_cmd", 0x45c000, 0x1000, 0x6000},
    {"hiperf_example_cmd", 0x45d000, 0x1000, 0x6000},
};
static const std::string TEST_DWARF_USER_REGS_0 = "user_regs.dump";
static const std::string TEST_DWARF_USER_DATA_0 = "user_data.dump";
/*
UnwindStep:unwind:0: ip 0x45765e sp 0xb6ca1c68
UnwindStep:unwind:1: ip 0x45768a sp 0xb6ca1c78
UnwindStep:unwind:2: ip 0x4576ce sp 0xb6ca1c88
UnwindStep:unwind:3: ip 0x457712 sp 0xb6ca1c98
UnwindStep:unwind:4: ip 0x457756 sp 0xb6ca1ca8
UnwindStep:unwind:5: ip 0x45779a sp 0xb6ca1cb8
UnwindStep:unwind:6: ip 0x4577de sp 0xb6ca1cc8
UnwindStep:unwind:7: ip 0x457822 sp 0xb6ca1cd8
UnwindStep:unwind:8: ip 0x457866 sp 0xb6ca1ce8
UnwindStep:unwind:9: ip 0x4578aa sp 0xb6ca1cf8
UnwindStep:unwind:10: ip 0x4578ee sp 0xb6ca1d08
UnwindStep:unwind:11: ip 0x45793c sp 0xb6ca1d18
UnwindStep:unwind:12: ip 0x457ffe sp 0xb6ca1d28
UnwindStep:unwind:13: ip 0xb6f01f73 sp 0xb6ca1d38
*/
static const std::vector<frame> TEST_DWARF_FRAMES = {
    {0x4575BC, 0xB6CA1C18}, // base ip sp
    {0x45765e, 0xb6ca1c68}, {0x45768a, 0xb6ca1c78},   {0x4576ce, 0xb6ca1c88},
    {0x457712, 0xb6ca1c98}, {0x457756, 0xb6ca1ca8},   {0x45779a, 0xb6ca1cb8},
    {0x4577de, 0xb6ca1cc8}, {0x457822, 0xb6ca1cd8},   {0x457866, 0xb6ca1ce8},
    {0x4578aa, 0xb6ca1cf8}, {0x4578ee, 0xb6ca1d08},   {0x45793c, 0xb6ca1d18},
    {0x457ffe, 0xb6ca1d28}, {0xb6f01f73, 0xb6ca1d38},
};
#else
static const std::string TEST_DWARF_ELF = "hiperf_example_cmd_64";
/*
record mmap2: type 10, misc 2, size 110
  pid 24925, tid 24925, addr 0x5591ef4000, len 0x3000
  pgoff 0x0, maj 179, min 11, ino 2495283, ino_generation 0
  prot 1, flags 2, filename /data/local/tmp/hiperf_example_cmd_64

record mmap2: type 10, misc 2, size 110
  pid 24925, tid 24925, addr 0x5591ef7000, len 0x3000
  pgoff 0x2000, maj 179, min 11, ino 2495283, ino_generation 0
  prot 5, flags 2, filename /data/local/tmp/hiperf_example_cmd_64

record mmap2: type 10, misc 2, size 110
  pid 24925, tid 24925, addr 0x5591efa000, len 0x1000
  pgoff 0x4000, maj 179, min 11, ino 2495283, ino_generation 0
  prot 1, flags 2, filename /data/local/tmp/hiperf_example_cmd_64
*/
static const std::vector<mmapDumpInfo> TEST_DWARF_MMAP = {
    {"hiperf_example_cmd_64", 0x5591ef4000, 0x3000, 0x0},
    {"hiperf_example_cmd_64", 0x5591ef7000, 0x3000, 0x2000},
    {"hiperf_example_cmd_64", 0x5591efa000, 0x1000, 0x4000},
};
static const std::string TEST_DWARF_USER_REGS_0 = "user_regs_64.dump";
static const std::string TEST_DWARF_USER_DATA_0 = "user_data_64.dump";
/*
UnwindStep:unwind:0: ip 0x5591ef772c sp 0x7f9aec76f0
UnwindStep:unwind:1: ip 0x5591ef78cb sp 0x7f9aec77b0
UnwindStep:unwind:2: ip 0x5591ef798f sp 0x7f9aec77e0
UnwindStep:unwind:3: ip 0x5591ef7a4f sp 0x7f9aec7820
UnwindStep:unwind:4: ip 0x5591ef7b0f sp 0x7f9aec7860
UnwindStep:unwind:5: ip 0x5591ef7bcf sp 0x7f9aec78a0
UnwindStep:unwind:6: ip 0x5591ef7c8f sp 0x7f9aec78e0
UnwindStep:unwind:7: ip 0x5591ef7d4f sp 0x7f9aec7920
UnwindStep:unwind:8: ip 0x5591ef7e0f sp 0x7f9aec7960
UnwindStep:unwind:9: ip 0x5591ef7ecf sp 0x7f9aec79a0
UnwindStep:unwind:10: ip 0x5591ef7f8f sp 0x7f9aec79e0
UnwindStep:unwind:11: ip 0x5591ef804f sp 0x7f9aec7a20
UnwindStep:unwind:12: ip 0x5591ef80e7 sp 0x7f9aec7a60
UnwindStep:unwind:13: ip 0x5591ef95db sp 0x7f9aec7a80
UnwindStep:unwind:14: ip 0x7f9b0fa59b sp 0x7f9aec7aa0
*/
static const std::vector<frame> TEST_DWARF_FRAMES = {
    {0x5591ef772c, 0x7f9aec76f0}, // base ip sp
    {0x5591ef78cb, 0x7f9aec77b0}, {0x5591ef798f, 0x7f9aec77e0},   {0x5591ef7a4f, 0x7f9aec7820},
    {0x5591ef7b0f, 0x7f9aec7860}, {0x5591ef7bcf, 0x7f9aec78a0},   {0x5591ef7c8f, 0x7f9aec78e0},
    {0x5591ef7d4f, 0x7f9aec7920}, {0x5591ef7e0f, 0x7f9aec7960},   {0x5591ef7ecf, 0x7f9aec79a0},
    {0x5591ef7f8f, 0x7f9aec79e0}, {0x5591ef804f, 0x7f9aec7a20},   {0x5591ef80e7, 0x7f9aec7a60},
    {0x5591ef95db, 0x7f9aec7a80}, {0x7f9b0fa59b, 0x7f9aec7aa0},
};
#endif

// data convert funcion
template<class T>
void LoadFromFile(const std::string &fileName, std::vector<T> &data)
{
    FILE* fp_ = fopen(fileName.c_str(), "r");
    if (fp_ == nullptr) {
        return;
    }
    std::unique_ptr<FILE, decltype(&fclose)> fp(fp_, fclose);
    if (fp) {
        struct stat sb = {};
        ASSERT_NE(fstat(fileno(fp.get()), &sb), -1);
        ASSERT_NE(sb.st_size, 0);
        ASSERT_EQ(sb.st_size % sizeof(T), 0u);
        data.resize(sb.st_size / sizeof(T));
        ASSERT_EQ(fread(data.data(), sizeof(T), data.size(), fp.get()), data.size());
    }
}

static void MakeMaps(VirtualThread &thread)
{
    for (const mmapDumpInfo &mmap : TEST_DWARF_MMAP) {
        thread.CreateMapItem(mmap.fileName, mmap.begin, mmap.len, mmap.pgoff);
    }
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_CALLSTACK_TEST_H
