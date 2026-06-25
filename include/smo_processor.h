/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef HIPERF_SMO_PROCESSOR_H
#define HIPERF_SMO_PROCESSOR_H

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include "perf_event_record.h"
#include "perf_record_format.h"
#include "symbol_manager.h"
#include "symbols_file.h"
#include "virtual_thread.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {

class SmoProcessor {
public:
    using RecordCallBack = std::function<bool(PerfEventRecord&)>;
    using SymbolsFileRegisterFunc = std::function<int32_t(std::unique_ptr<SymbolsFile>)>;

    SmoProcessor(const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles,
                 SymbolManager& symbolManager, const SymbolsFileRegisterFunc& registerFunc);
    ~SmoProcessor() = default;
    bool UpdateProcessSmoInfo(const VirtualThread& thread);
    void UpdateFromRecord(PerfRecordSmoDetachingEvent& record);
    void SetRecordMode(const RecordCallBack& recordCallBack) { recordCallBack_ = recordCallBack; }
    const std::map<std::string, std::vector<AdltMapDataFragment>>& GetSoMappingMap() const { return soMappingMap_; }
    void UpdateFilesFromSmoRecordData();
    void Clear();

private:
    void UpdateSmoList(const VirtualThread& thread,
                       std::vector<std::shared_ptr<DfxElf>>& elfList,
                       std::vector<std::string>& filePathList);
    void PutSmoDataToRecord(PerfRecordSmoDataFragment& fragment, u32 mapOffset);
    std::vector<uint8_t> UpdateBinaryDataFromRecord(PerfRecordSmoDetachingEvent& record);
    const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles_;
    SymbolManager& symbolManager_;
    const SymbolsFileRegisterFunc& registerFunc_;
    std::map<std::string, std::vector<AdltMapDataFragment>> soMappingMap_;
    std::map<std::string, std::unordered_set<std::string>> originSoMap_;
    std::map<uint16_t, std::vector<uint8_t>> binaryDataMap_;
    std::unordered_set<std::string> savedSmoPathList_;
    RecordCallBack recordCallBack_;
};

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_SMO_PROCESSOR_H
