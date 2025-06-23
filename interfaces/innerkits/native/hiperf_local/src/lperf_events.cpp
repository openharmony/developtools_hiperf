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

#include "lperf_events.h"

#include <chrono>
#include <fcntl.h>
#include <iostream>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

using namespace std::chrono;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
namespace HiPerfLocal {
LperfEvents::LperfEvents()
{
    pageSize_ = sysconf(_SC_PAGESIZE);
}

LperfEvents::~LperfEvents()
{
    Clear();
}

int LperfEvents::PrepareRecord()
{
    CHECK_TRUE_AND_RET(PrepareFdEvents(), -1, "PrepareFdEvents failed");
    CHECK_TRUE_AND_RET(AddRecordThreads(), -1, "AddRecordThreads failed");
    return 0;
}

int LperfEvents::StartRecord()
{
    CHECK_TRUE_AND_RET(PerfEventsEnable(true), -1, "LperfEvents EnableTracking() failed");
    CHECK_TRUE_AND_RET(RecordLoop(), -1, "LperfEvents RecordLoop() failed");
    CHECK_TRUE_AND_RET(PerfEventsEnable(false), -1, "LperfEvents RecordLoop() failed");
    ReadRecordsFromMmaps();
    return 0;
}

bool LperfEvents::StopRecord()
{
    CHECK_TRUE_AND_RET(PerfEventsEnable(false), -1, "LperfEvents StopRecord failed");
    return true;
}

void LperfEvents::SetTid(const std::vector<int>& tids)
{
    tids_ = tids;
}

void LperfEvents::SetTimeOut(int timeOut)
{
    if (timeOut > 0) {
        timeOut_ = timeOut;
    }
}

void LperfEvents::SetSampleFrequency(unsigned int frequency)
{
    if (frequency > 0) {
        sampleFreq_ = frequency;
    }
}

bool LperfEvents::PerfEventsEnable(bool enable)
{
    int err = ioctl(lperfFd_, static_cast<unsigned long>(LPERF_IOCTL_PROFILE), enable ? 1 : 0);
    CHECK_ERR(err, "enable lperfFd_ failed");
    return true;
}

void LperfEvents::SetRecordCallBack(ProcessRecordCB recordCallBack)
{
    recordCallBack_ = recordCallBack;
}

bool LperfEvents::PrepareFdEvents()
{
    unsigned int times = 4;
    struct lperf_init_arg initArg = {
        .rb_size_int_kb = (mmapPages_ + 1) * times,
        .sample_period = sampleFreq_,
        .sample_interval = timeOut_,
        .watermark = DEFAULT_WATER_MARK,
        .rb_addr = 0,
    };
    lperfFd_ = open("/dev/lperf", O_RDWR);
    CHECK_ERR(lperfFd_, "open lperfFd_ failed");
    int err = ioctl(lperfFd_, LPERF_IOCTL_INIT, &initArg);
    CHECK_ERR(err, "init lperf failed");
    lperfMmap_.fd = lperfFd_;
    lperfMmap_.mmapPage = reinterpret_cast<perf_event_mmap_page *>(initArg.rb_addr);
    lperfMmap_.buf = reinterpret_cast<uint8_t *>(initArg.rb_addr) + pageSize_;
    lperfMmap_.bufSize = mmapPages_ * pageSize_;
    pollFds_.emplace_back(pollfd {lperfFd_, POLLIN | POLLHUP, 0});
    return true;
}

bool LperfEvents::AddRecordThreads()
{
    struct lperf_thread_input_arg threadInfo;
    size_t maxCount = 10;
    size_t count = (tids_.size() <= maxCount) ? tids_.size() : maxCount;
    threadInfo.tid_count = static_cast<unsigned int>(count);
    for (size_t i = 0; i < count; i++) {
        threadInfo.tids[i] = tids_[i];
    }
    int err = ioctl(lperfFd_, static_cast<unsigned long>(LPERF_IOCTL_ADD_THREADS), &threadInfo);
    CHECK_ERR(err, "add lperf threads failed");
    return true;
}

bool LperfEvents::GetHeaderFromMmap(MmapFd& mmap)
{
    if (mmap.dataSize <= 0) {
        return false;
    }

    GetRecordFieldFromMmap(mmap, &(mmap.header), mmap.mmapPage->data_tail, sizeof(mmap.header));
    if (mmap.header.type != PERF_RECORD_SAMPLE) {
        mmap.mmapPage->data_tail += mmap.header.size;
        return false;
    }
    return true;
}

void LperfEvents::GetRecordFieldFromMmap(MmapFd& mmap, void* dest, size_t pos, size_t size)
{
    if (mmap.bufSize == 0) {
        return;
    }
    pos = pos % mmap.bufSize;
    size_t tailSize = mmap.bufSize - pos;
    size_t copySize = std::min(size, tailSize);
    if (memcpy_s(dest, size, mmap.buf + pos, copySize) != 0) {
        HIPERF_HILOGE(MODULE_DEFAULT, "memcpy_s %p to %p failed. size %zd", mmap.buf + pos, dest, copySize);
    }
    if (copySize < size) {
        size -= copySize;
        if (memcpy_s(static_cast<uint8_t *>(dest) + copySize, size, mmap.buf, size) != 0) {
            HIPERF_HILOGE(MODULE_DEFAULT, "memcpy_s mmap.buf to dest failed. size %zd", size);
        }
    }
}

void LperfEvents::GetRecordFromMmap(MmapFd& mmap)
{
    HIPERF_BUF_ALIGN static uint8_t buf[RECORD_SIZE_LIMIT];
    GetRecordFieldFromMmap(mmap, buf, mmap.mmapPage->data_tail, mmap.header.size);
    __sync_synchronize();
    mmap.mmapPage->data_tail += mmap.header.size;
    mmap.dataSize -= mmap.header.size;
    recordCallBack_(LperfRecordFactory::GetLperfRecord(mmap.header.type, buf));
}

void LperfEvents::ReadRecordsFromMmaps()
{
    size_t dataSize = lperfMmap_.mmapPage->data_head - lperfMmap_.mmapPage->data_tail;
    __sync_synchronize();
    if (dataSize <= 0) {
        return;
    }
    lperfMmap_.dataSize = dataSize;
    while (GetHeaderFromMmap(lperfMmap_)) {
        GetRecordFromMmap(lperfMmap_);
    }
}

bool LperfEvents::RecordLoop()
{
    CHECK_TRUE_AND_RET(pollFds_.size() > 0, false, "pollFds_ is invalid");
    const auto endTime = steady_clock::now() + milliseconds(timeOut_);

    bool loopCondition = true;
    int pollTimeout = 500;
    while (loopCondition) {
        const auto thisTime = steady_clock::now();
        if (thisTime >= endTime) {
            break;
        }

        if (poll(static_cast<struct pollfd *>(pollFds_.data()), pollFds_.size(), pollTimeout) <= 0) {
            HIPERF_HILOGE(MODULE_DEFAULT, "poll no data");
            continue;
        }
        ReadRecordsFromMmaps();
        if ((pollFds_[0].revents & POLLHUP) == POLLHUP) {
            HIPERF_HILOGE(MODULE_DEFAULT, "poll status is POLLHUP, revents: %{public}d", pollFds_[0].revents);
            loopCondition = false;
        }
    }
    return true;
}

void LperfEvents::Clear()
{
    LperfRecordFactory::ClearData();
    const unsigned int size = 4096;
    if (lperfMmap_.mmapPage != nullptr) {
        if (munmap(lperfMmap_.mmapPage, static_cast<size_t>((mmapPages_ + 1) * size)) == 0) {
            lperfMmap_.mmapPage = nullptr;
        } else {
            HIPERF_HILOGE(MODULE_DEFAULT, "munmap lperfMmap failed");
        }
    }
    if (pollFds_.size() > 0) {
        pollFds_.clear();
    }
    if (lperfFd_ != -1) {
        close(lperfFd_);
        lperfFd_ = -1;
    }
}
} // namespace HiPerfLocal
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS