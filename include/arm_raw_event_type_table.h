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
#ifndef ARM_RAW_EVENT_TYPE_TABLE_H
#define ARM_RAW_EVENT_TYPE_TABLE_H

// clang-format off
{0x0, "raw-sw-incr"},
{0x1, "raw-l1-icache-refill"},
{0x2, "raw-l1-itlb-refill"},
{0x3, "raw-l1-dcache-refill"},
{0x4, "raw-l1-dcache"},
{0x5, "raw-l1-dtlb-refill"},
{0x6, "raw-load-retired"},
{0x7, "raw-store-retired"},
{0x8, "raw-instruction-retired"},
{0x9, "raw-exception-taken"},
{0xa, "raw-exception-return"},
{0xb, "raw-cid-write-retired"},
{0xc, "raw-pc-write-retired"},
{0xd, "raw-br-immed-retired"},
{0xe, "raw-br-return-retired"},
{0xf, "raw-unaligned-ldst-retired"},
{0x10, "raw-br-mis-pred"},
{0x11, "raw-cpu-cycles"},
{0x12, "raw-br-pred"},
{0x13, "raw-mem-access"},
{0x14, "raw-l1-icache"},
{0x15, "raw-l1-dcache-wb"},
{0x16, "raw-l2-dcache"},
{0x17, "raw-l2-dcache-refill"},
{0x18, "raw-l2-dcache-wb"},
{0x19, "raw-bus-access"},
{0x1a, "raw-memory-error"},
{0x1b, "raw-inst-spec"},
{0x1c, "raw-ttbr-write-retired"},
{0x1d, "raw-bus-cycles"},
{0x1f, "raw-l1-dcache-allocate"},
{0x20, "raw-l2-dcache-allocate"},
{0x21, "raw-br-retired"},
{0x22, "raw-br-mis-pred-retired"},
{0x23, "raw-stall-frontend"},
{0x24, "raw-stall-backend"},
{0x25, "raw-l1-dtlb"},
{0x26, "raw-l1-itlb"},
{0x27, "raw-l2-icache"},
{0x28, "raw-l2-icache-refill"},
{0x29, "raw-l3-dcache-allocate"},
{0x2a, "raw-l3-dcache-refill"},
{0x2b, "raw-l3-dcache"},
{0x2c, "raw-l3-dcache-wb"},
{0x2d, "raw-l2-dtlb-refill"},
{0x2e, "raw-l2-itlb-refill"},
{0x2f, "raw-l2-dtlb"},
{0x30, "raw-l2-itlb"},
#endif