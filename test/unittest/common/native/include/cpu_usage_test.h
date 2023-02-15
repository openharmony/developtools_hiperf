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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <string>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <string>
#include <fstream>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sstream>
#include "subcommand_record.h"
#include "subcommand_stat.h"
#include "subcommand_report.h"

#define PROCESS_ITEM 14
#define HUNDRED 100
#define F100_FP_CPU_LIMIT_SYSTEM 6
#define F500_FP_CPU_LIMIT_SYSTEM 10
#define F1000_FP_CPU_LIMIT_SYSTEM 15
#define F2000_FP_CPU_LIMIT_SYSTEM 20
#define F4000_FP_CPU_LIMIT_SYSTEM 35
#define F8000_FP_CPU_LIMIT_SYSTEM 50
#define F100_DWARF_CPU_LIMIT_SYSTEM 30
#define F500_DWARF_CPU_LIMIT_SYSTEM 60
#define F1000_DWARF_CPU_LIMIT_SYSTEM 70
#define F2000_DWARF_CPU_LIMIT_SYSTEM 80
#define F4000_DWARF_CPU_LIMIT_SYSTEM 90
#define F8000_DWARF_CPU_LIMIT_SYSTEM 95

#define F100_FP_CPU_LIMIT_PROCESS 4
#define F500_FP_CPU_LIMIT_PROCESS 5
#define F1000_FP_CPU_LIMIT_PROCESS 6
#define F2000_FP_CPU_LIMIT_PROCESS 7
#define F4000_FP_CPU_LIMIT_PROCESS 10
#define F8000_FP_CPU_LIMIT_PROCESS 20
#define F100_DWARF_CPU_LIMIT_PROCESS 15
#define F500_DWARF_CPU_LIMIT_PROCESS 30
#define F1000_DWARF_CPU_LIMIT_PROCESS 60
#define F2000_DWARF_CPU_LIMIT_PROCESS 70
#define F4000_DWARF_CPU_LIMIT_PROCESS 80
#define F8000_DWARF_CPU_LIMIT_PROCESS 90