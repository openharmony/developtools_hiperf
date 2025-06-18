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

#define HILOG_TAG "LRecord"

#include "lperf_record.h"
#include "unwinder_config.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
namespace HiPerfLocal {
LperfRecord::LperfRecord()
{
    unwinder_ = nullptr;
    maps_ = nullptr;
}

LperfRecord::~LperfRecord()
{
    FinishProcessSampling();
}

int LperfRecord::StartProcessSampling(std::vector<int> tids, int freq, int duration, bool parseMiniDebugInfo)
{
    CHECK_TRUE_WITH_LOG(!CheckOutOfRange<int>(tids.size(), MIN_SAMPLE_COUNT, MAX_SAMPLE_COUNT), -1,
                        "invalid tids count: %d", tids.size());
    CHECK_TRUE_WITH_LOG(!CheckOutOfRange<int>(freq, MIN_SAMPLE_FREQUENCY, MAX_SAMPLE_FREQUENCY), -1,
                        "invalid frequency value: %d", freq);
    CHECK_TRUE_WITH_LOG(!CheckOutOfRange<int>(duration, MIN_STOP_SECONDS, MAX_STOP_SECONDS), -1,
                        "invalid duration value: %d", duration);
    for (int tid: tids) {
        CHECK_TRUE_WITH_LOG(tid > 0, -1, "invalid tid: %d", tid);
    }

    tids_ = tids;
    frequency_ = static_cast<unsigned int>(freq);
    timeStopSec_ = static_cast<unsigned int>(duration);
    enableDebugInfoSymbolic_ = parseMiniDebugInfo;

    return OnSubCommand();
}

int LperfRecord::CollectSampleStack(int tid, std::string &stack)
{
    CHECK_TRUE_WITH_LOG(tid > 0, -1, "invalid tid: %d", tid);
    unsigned int uintTid = static_cast<unsigned int>(tid);
    if (tidStackMaps_.find(uintTid) != tidStackMaps_.end()) {
        if (unwinder_ == nullptr) {
            unwinder_ = std::make_shared<Unwinder>(false);
        }
        if (maps_ == nullptr) {
            maps_ = DfxMaps::Create();
        }
        tidStackMaps_[uintTid]->SetUnwindInfo(unwinder_, maps_);
        stack = tidStackMaps_[uintTid]->GetTreeStack();
        if (stack.size()) {
            return 0;
        }
    }
    return -1;
}

int LperfRecord::CollectHeaviestStack(int tid, std::string &stack)
{
    CHECK_TRUE_WITH_LOG(tid > 0, -1, "invalid tid: %d", tid);
    unsigned int uintTid = static_cast<unsigned int>(tid);
    if (tidStackMaps_.find(uintTid) != tidStackMaps_.end()) {
        if (unwinder_ == nullptr) {
            unwinder_ = std::make_shared<Unwinder>(false);
        }
        if (maps_ == nullptr) {
            maps_ = DfxMaps::Create();
        }
        tidStackMaps_[uintTid]->SetUnwindInfo(unwinder_, maps_);
        stack = tidStackMaps_[uintTid]->GetHeaviestStack();
        if (stack.size()) {
            return 0;
        }
    }
    return -1;
}

int LperfRecord::FinishProcessSampling()
{
    lperfEvents_.Clear();
    UnwinderConfig::SetEnableMiniDebugInfo(defaultEnableDebugInfo_);
    if (tidStackMaps_.size()) {
        tidStackMaps_.clear();
    }
    if (tids_.size()) {
        tids_.clear();
    }
    if (maps_ != nullptr) {
        maps_ = nullptr;
    }
    if (unwinder_ != nullptr) {
        unwinder_ = nullptr;
    }
    return 0;
}

void LperfRecord::PrepareLperfEvent()
{
    defaultEnableDebugInfo_ = UnwinderConfig::GetEnableMiniDebugInfo();
    UnwinderConfig::SetEnableMiniDebugInfo(enableDebugInfoSymbolic_);
    lperfEvents_.SetTid(tids_);
    lperfEvents_.SetTimeOut(timeStopSec_);
    lperfEvents_.SetSampleFrequency(frequency_);
    auto processRecord = [this](LperfRecordSample& record) -> void {
        this->SymbolicRecord(record);
    };
    lperfEvents_.SetRecordCallBack(processRecord);
}

void LperfRecord::SymbolicRecord(LperfRecordSample& record)
{
    CHECK_TRUE_WITH_LOG(record.data_.tid > 0, NO_RETVAL, "Symbolic invalid Record, tid: %d", record.data_.tid);
    unsigned int tid = static_cast<unsigned int>(record.data_.tid);
    if (tidStackMaps_.find(tid) == tidStackMaps_.end()) {
        tidStackMaps_[tid] = std::make_unique<StackPrinter>();
        tidStackMaps_[tid]->InitUniqueTable(record.data_.pid, UNIQUE_STABLE_SIZE);
    }
    std::vector<uintptr_t> ptrs;
    for (unsigned int i = 0; i < record.data_.nr; i++) {
        if (record.data_.ips[i] != PERF_CONTEXT_USER) {
            ptrs.push_back(static_cast<uintptr_t>(record.data_.ips[i]));
        }
    }
    tidStackMaps_[tid]->PutPcsInTable(ptrs, record.data_.time);
}

int LperfRecord::OnSubCommand()
{
    PrepareLperfEvent();
    CHECK_TRUE_WITH_LOG(lperfEvents_.PrepareRecord() == 0, -1, "OnSubCommand prepareRecord failed");
    CHECK_TRUE_WITH_LOG(lperfEvents_.StartRecord() == 0, -1, "OnSubCommand startRecord failed");
    return 0;
}
} // namespace HiPerfLocal
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS