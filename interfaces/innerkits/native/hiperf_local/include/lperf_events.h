/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef LPERF_EVENTS_H
#define LPERF_EVENTS_H

#include <functional>
#include <string>
#include <vector>
#include <linux/perf_event.h>
#include <poll.h>

#include "lperf_event_record.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
namespace HiPerfLocal {
#define LPERF_IOCTL_INIT 1075866625
#define LPERF_IOCTL_SUMMARY 2150132739
#define LPERF_IOCTL_PROFILE 2148035586
#define LPERF_IOCTL_ADD_THREADS 1074031620
#define HIPERF_BUF_ALIGN alignas(64)

static constexpr int DEFAULT_MMAP_PAGES = 1024;
static constexpr int DEFAULT_WATER_MARK = 5000;

struct lperf_init_arg {
    unsigned int rb_size_int_kb;
    unsigned int sample_period;
    unsigned int sample_interval;
    unsigned int watermark;
    unsigned int reserved1;
    unsigned long long rb_addr;
};

struct lperf_context_summary {
    unsigned int lperf_inst_count;
    unsigned int lperf_thread_count;
    unsigned int lperf_thread_count_total;
    unsigned int state;
    unsigned int rb_size;
    unsigned int sample_period;
    unsigned int sample_interval;
    unsigned int reserved1;
    unsigned long long rb_addr;
};

struct lperf_thread_input_arg {
    unsigned int tid_count;
    unsigned int tids[10];
};

class LperfEvents {
public:
    LperfEvents();
    ~LperfEvents();

    int PrepareRecord();
    int StartRecord();
    bool StopRecord();

    struct MmapFd {
        int fd;
        perf_event_mmap_page* mmapPage = nullptr;
        uint8_t *buf = nullptr;
        size_t bufSize = 0;
        size_t dataSize = 0;

        perf_event_header header;
    };

    void SetTid(std::vector<int> tids);
    void SetTimeOut(int timeOut);
    void SetSampleFrequency(unsigned int frequency);

    using ProcessRecordCB = std::function<void(LperfRecordSample& record)>;
    void SetRecordCallBack(ProcessRecordCB recordCallBack);
    void Clear();

private:
    bool PrepareFdEvents();
    bool AddRecordThreads();
    bool GetHeaderFromMmap(MmapFd& mmap);
    void GetRecordFieldFromMmap(MmapFd& mmap, void* dest, size_t pos, size_t size);
    void GetRecordFromMmap(MmapFd& mmap);
    void ReadRecordsFromMmaps();
    bool PerfEventsEnable(bool enable);
    bool RecordLoop();

    ProcessRecordCB recordCallBack_;

    int lperfFd_ = -1;
    std::vector<int> tids_;
    unsigned int sampleFreq_ = 0;
    int timeOut_ = 0;
    MmapFd lperfMmap_;
    std::vector<struct pollfd> pollFds_;
    int mmapPages_ = DEFAULT_MMAP_PAGES;
    size_t pageSize_ = 4096;
};
} // namespace HiPerfLocal
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // LPERF_EVENTS_H