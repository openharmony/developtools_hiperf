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
#ifndef NONLINUX_LINUX_TYPES_H
#define NONLINUX_LINUX_TYPES_H
#include <stdint.h>

/*
long long always 64
only in ILP64 , int is 64, but no OS use this
otherwise int is always 32
*/

using __s8 = char;
using __u8 = unsigned char;
using __s16 = short;
using __u16 = unsigned short;
using __s32 = int;
using __u32 = unsigned int;
using __s64 = long long;
using __u64 = unsigned long long;
#endif
