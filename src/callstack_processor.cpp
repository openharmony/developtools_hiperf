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
#define HILOG_TAG "CallStackProcessor"

#include "callstack_processor.h"

#include <cinttypes>

#include "debug_logger.h"
#include "hiperf_hilog.h"
#include "register.h"
#include "utilities.h"

#if defined(is_ohos) && is_ohos
#include "spe_decoder.h"
#endif

using namespace std::chrono;

namespace OHOS {
namespace Developtools {
namespace HiPerf {

namespace {
// if ip is 0 , 1 both not useful
const uint64_t BAD_IP_ADDRESS = 2;
}

CallStackProcessor::CallStackProcessor(SymbolManager& symbolManager, ThreadManager& threadManager,
                                       const RuntimeContext& ctx)
    : symbolManager_(symbolManager), threadManager_(threadManager), ctx_(ctx)
{
}

void CallStackProcessor::MakeCallFrame(const uint64_t ip, DfxSymbol& symbol, DfxFrame& callFrame)
{
    callFrame.funcOffset = symbol.funcVaddr_;
    callFrame.mapOffset = symbol.offsetToVaddr_;
    callFrame.symbolFileIndex = symbol.symbolFileIndex_;
    callFrame.funcName = symbol.GetName();
    callFrame.map = symbol.map;
    callFrame.originSoName = symbol.originSoName_;
    if (callFrame.map != nullptr &&
        callFrame.map->name.find("libadlt") != std::string::npos && EndsWith(callFrame.map->name, ".so")) {
        callFrame.relPc = ip - callFrame.map->GetAdltLoadBase();
        HLOGV("Get relPc: 0x%" PRIx64 " mapBegin:0x%" PRIx64 " pc:0x%08" PRIx64 "",
            callFrame.relPc, callFrame.map->begin, callFrame.pc);
    }
    if (callFrame.funcName.empty()) {
        HLOGD("callFrame.funcName:%s, GetName:%s\n", callFrame.funcName.c_str(), symbol.GetName().data());
    }

    callFrame.index = static_cast<size_t>(symbol.index_);
    callFrame.mapName = symbol.module_.empty() ? symbol.comm_ : symbol.module_;
    HLOG_ASSERT_MESSAGE(!callFrame.funcName.empty(), "%s", symbol.ToDebugString().c_str());
}

void CallStackProcessor::SymbolicCallFrame(PerfRecordSample& recordSample, const uint64_t ip,
                                           const pid_t serverPid, const perf_callchain_context context)
{
    pid_t pid = static_cast<pid_t>(recordSample.data_.pid);
    pid_t tid = static_cast<pid_t>(recordSample.data_.tid);
    if (serverPid != pid) {
        pid = tid = serverPid;
    }
    auto symbol = symbolManager_.ResolveSymbol(ip, threadManager_.GetThread(pid, tid), context,
                                               threadManager_.IsKernelThread(pid));
    MakeCallFrame(ip, symbol, recordSample.callFrames_.emplace_back(ip, 0));
    HLOGV(" (%zu)unwind symbol: %*s%s", recordSample.callFrames_.size(),
          static_cast<int>(recordSample.callFrames_.size()), "",
          recordSample.callFrames_.back().ToSymbolString().c_str());
}

bool CallStackProcessor::RecoverCallStack(PerfRecordSample& recordSample)
{
    auto StackTable = processStackMap_.find(recordSample.data_.pid);
    CHECK_TRUE(StackTable != processStackMap_.end(), false, 1, "not found %" PRIu32 " pid", recordSample.data_.pid);
    recordSample.ips_.clear();
    if (StackTable->second != nullptr) {
        StackTable->second->GetIpsByStackId(recordSample.stackId_, recordSample.ips_);
    }
    recordSample.RecoverCallStack();
    return true;
}

void CallStackProcessor::SymbolicRecord(PerfRecordSample& recordSample)
{
#ifdef HIPERF_DEBUG_TIME
    const auto startTime = steady_clock::now();
#endif
    // Symbolic the Call Stack
    recordSample.callFrames_.clear();
    perf_callchain_context context = PERF_CONTEXT_MAX;
    pid_t serverPid;
    if (recordSample.data_.nr == 0) {
        serverPid = recordSample.GetServerPidof(0);
        SymbolicCallFrame(recordSample, recordSample.data_.ip, serverPid, PERF_CONTEXT_MAX);
    }
    for (u64 i = 0; i < recordSample.data_.nr; i++) {
        uint64_t ip = recordSample.data_.ips[i];
        if (ip >= PERF_CONTEXT_MAX) {
            std::string contextName = UpdatePerfContext(ip, context);
            HLOGV("context switch to %s", contextName.c_str());
            continue;
        } else if (ip < BAD_IP_ADDRESS) {
            // ip 0 or 1 or less than 0
            continue;
        }
        serverPid = recordSample.GetServerPidof(i);
        SymbolicCallFrame(recordSample, ip, serverPid, context);
    }
#ifdef HIPERF_DEBUG_TIME
    auto usedTime = duration_cast<microseconds>(steady_clock::now() - startTime);
    if (usedTime.count() != 0) {
        HLOGV("cost %0.3f ms to symbolic ", usedTime.count() / MS_DURATION);
    }
    symbolicRecordTimes_ += usedTime;
#endif
}

void CallStackProcessor::NeedDropKernelCallChain(PerfRecordSample& sample)
{
    // only do this in record mode.
    if (recordCallBack_ == nullptr || needKernelCallChain_ ||
        !sample.InKernel() || sample.data_.nr == 0) {
        return;
    }

    u64 skip = 0;
    u64 skipPid = 0;
    u64* ips = sample.data_.ips;
    for (; skip < sample.data_.nr; skip++) {
        if (ips[skip] == PERF_CONTEXT_KERNEL) {
            skipPid++;
        }
        if (ips[skip] == PERF_CONTEXT_USER) {
            break;
        }
    }
    sample.skipKernel_ = skip;
    sample.data_.nr -= skip;
    sample.header_.size -= sizeof(u64) * skip;
    if (sample.data_.server_nr > 0) {
        sample.skipPid_ = skipPid;
        sample.data_.server_nr -= skipPid;
        sample.header_.size -= sizeof(u64) * skipPid;
    }
}

void CallStackProcessor::AdjustCallChain(PerfRecordSample& sample)
{
#if defined(is_ohos) && is_ohos
    if (!ctx_.isHM || recordCallBack_ == nullptr) {
        return;
    }
    constexpr uint64_t minValue = 0x5;
    constexpr uint64_t offset = 0x4;
    for (u64 i = 0; i < sample.data_.nr; i++) {
        if (sample.data_.ips[i] >= PERF_CONTEXT_MAX) {
            i++;
            continue;
        }
        if (i >= 1 && sample.data_.ips[i] >= minValue) {
            sample.data_.ips[i] -= offset;
        }
    }
#endif
}

void CallStackProcessor::ProcessKernelCallChain(PerfRecordSample& sample)
{
#if defined(is_ohos) && is_ohos
    if (ctx_.isRoot) {
        return;
    }
    if (recordCallBack_ != nullptr) {
        if (sample.data_.ip >= 0xffff000000000000) {
            sample.data_.ip = sample.data_.ip & 0xffffff0000000fff;
        }
        for (u64 i = 0; i < sample.data_.nr; i++) {
            if (sample.data_.ips[i] >= PERF_CONTEXT_MAX) {
                continue;
            }
            if (sample.data_.ips[i] >= 0xffff000000000000) {
                sample.data_.ips[i] = sample.data_.ips[i] & 0xffffff0000000fff;
            }
        }
    }
#endif
}

void CallStackProcessor::DedupFromRecord(PerfRecordSample* recordSample)
{
    CHECK_TRUE(recordSample != nullptr, NO_RETVAL, 0, "");
    u64 nr = recordSample->data_.nr;
    if (nr == 0) {
        collectSymbolCallBack_(recordSample);
        return;
    }
    u32 pid = recordSample->data_.pid;
    u64* ips = recordSample->data_.ips;
    StackId stackId;
    stackId.value = 0;
    auto entry = processStackMap_.find(pid);
    std::shared_ptr<UniqueStackTable> table = nullptr;
    if (entry != processStackMap_.end()) {
        table = entry->second;
    } else {
        table = std::make_shared<UniqueStackTable>(pid);
        processStackMap_[pid] = table;
    }
    CHECK_TRUE(table != nullptr, NO_RETVAL, 0, "");
    while (table->PutIpsInTable(&stackId, ips, nr) == 0) {
        // try expand hashtable if collison can not resolved
        if (!table->Resize()) {
            HLOGW("Hashtable size limit, ip compress failed!");
            collectSymbolCallBack_(recordSample);
            return;
        }
    }
    // callstack dedup success
    recordSample->stackId_.value = stackId.value;
    recordSample->header_.size -= (sizeof(u64) * nr - sizeof(stackId));
    recordSample->data_.nr = 0;
    recordSample->data_.ips = nullptr;
    recordSample->removeStack_ = true;
}

void CallStackProcessor::UnwindFromRecord(PerfRecordSample& recordSample)
{
#if defined(is_ohos) && is_ohos
#ifdef HIPERF_DEBUG_TIME
    const auto startTime = steady_clock::now();
#endif
    HLOGV("unwind record (time:%llu)", recordSample.data_.time);
    // if we have userstack ?
    if (recordSample.data_.stack_size > 0) {
        pid_t serverPid = recordSample.GetUstackServerPid();
        pid_t pid = static_cast<pid_t>(recordSample.data_.pid);
        pid_t tid = static_cast<pid_t>(recordSample.data_.tid);
        if (serverPid != pid) {
            pid = tid = serverPid;
        }
        auto& thread = threadManager_.UpdateThread(pid, tid);
        callstack_.UnwindCallStack(thread, recordSample.data_.user_abi == PERF_SAMPLE_REGS_ABI_32,
                                   recordSample.data_.user_regs, recordSample.data_.reg_nr,
                                   recordSample.data_.stack_data, recordSample.data_.dyn_size,
                                   recordSample.callFrames_);
#ifdef HIPERF_DEBUG_TIME
        unwindCallStackTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif
        size_t oldSize = recordSample.callFrames_.size();
        HLOGV("unwind %zu", recordSample.callFrames_.size());
        callstack_.ExpandCallStack(thread.tid_, recordSample.callFrames_, callstackMergeLevel_);
        HLOGV("expand %zu (+%zu)", recordSample.callFrames_.size(),
              recordSample.callFrames_.size() - oldSize);

        recordSample.ReplaceWithCallStack(oldSize);
    }

#ifdef HIPERF_DEBUG_TIME
    unwindFromRecordTimes_ += duration_cast<microseconds>(steady_clock::now() - startTime);
#endif

    NeedDropKernelCallChain(recordSample);
    // we will not do this in non record mode.
    if (dedupStack_ && recordCallBack_ != nullptr) {
        DedupFromRecord(&recordSample);
    }
#endif

    // we will not do this in record mode
    if (recordCallBack_ == nullptr) {
        if (dedupStack_ && recordSample.stackId_.section.id > 0 && recordSample.data_.nr == 0) {
            RecoverCallStack(recordSample);
        }
        // find the symbols , reabuild frame info
        SymbolicRecord(recordSample);
    }
}

void CallStackProcessor::SymbolSpeRecord(PerfRecordAuxtrace& recordAuxTrace)
{
#if defined(is_ohos) && is_ohos
    recordAuxTrace.DumpLog(__FUNCTION__);
    SpeDecoder* decoder = SpeDecoderDataNew(recordAuxTrace.rawData_, recordAuxTrace.data_.size);
    CHECK_TRUE(decoder != nullptr, NO_RETVAL, 0, "");
    while (true) {
        int ret = SpeDecode(decoder);
        if (ret <= 0) {
            break;
        }
        struct SpeRecord record = SpeRecord(decoder->record);
        u64 pc = 0;
        if (record.from_ip) {
            pc = record.from_ip;
        } else if (record.to_ip) {
            pc = record.to_ip;
        } else {
            continue;
        }

        DfxSymbol symbol = symbolManager_.ResolveSymbol(pc,
            threadManager_.GetThread(recordAuxTrace.data_.reserved__, recordAuxTrace.data_.tid),
            PERF_CONTEXT_MAX, threadManager_.IsKernelThread(recordAuxTrace.data_.reserved__));
        HLOGV("pc 0x%llx symbol %s", pc, symbol.ToDebugString().c_str());
    }
    SpeDecoderFree(decoder);
#endif
}

void CallStackProcessor::ProcessAuxtraceRecord(PerfRecordAuxtrace& recordAuxTrace)
{
    if (recordCallBack_ != nullptr) {
        return;
    }
#if defined(is_ohos) && is_ohos
    recordAuxTrace.DumpLog(__FUNCTION__);
    SpeDecoder* decoder = SpeDecoderDataNew(recordAuxTrace.rawData_, recordAuxTrace.data_.size);
    CHECK_TRUE(decoder != nullptr, NO_RETVAL, 0, "");
    std::vector<SpeRecord> speRecords;
    while (true) {
        int ret = SpeDecode(decoder);
        if (ret <= 0) {
            break;
        }
        struct SpeRecord record = SpeRecord(decoder->record);
        speRecords.emplace_back(record);
    }
    std::vector<ReportItemAuxRawData> auxRawData;
    for (auto rec: speRecords) {
        u64 pc = 0;
        if (rec.from_ip) {
            pc = rec.from_ip;
        } else if (rec.to_ip) {
            pc = rec.to_ip;
        } else {
            continue;
        }
        DfxSymbol symbol = symbolManager_.ResolveSymbol(pc,
            threadManager_.GetThread(recordAuxTrace.data_.reserved__, recordAuxTrace.data_.tid),
            PERF_CONTEXT_MAX, threadManager_.IsKernelThread(recordAuxTrace.data_.reserved__));
        HLOGV("pc 0x%llx symbol %s", pc, symbol.ToDebugString().c_str());
        struct ReportItemAuxRawData reportItem = {rec.type, 0.0f, 1, symbol.comm_.data(), pc,
                                                  symbol.module_.data(), symbol.GetName().data(),
                                                  symbol.fileVaddr_};
        auxRawData.emplace_back(reportItem);
        HLOGV("type %u, from_ip: 0x%llx, to_ip: 0x%llx, timestamp: %llu, virt_addr: 0x%llx, phys_addr: 0x%llx",
              rec.type, rec.from_ip, rec.to_ip, rec.timestamp, rec.virt_addr, rec.phys_addr);
    }
    AddReportItems(auxRawData);
    SpeDecoderFree(decoder);
#endif
}

void CallStackProcessor::CollectDedupSymbol(kSymbolsHits& kernelSymbolsHits,
                                            uSymbolsHits& userSymbolsHits)
{
    Node* node = nullptr;
    Node* head = nullptr;
    u32 pid;
    for (const auto& tableEntry : processStackMap_) {
        const auto& table = tableEntry.second;
        if (table == nullptr) {
            continue;
        }
        pid = table->GetPid();
        head = table->GetHeadNode();
        const auto& idxes = table->GetUsedIndexes();
        for (const auto idx : idxes) {
            node = head + idx;
            if (node == nullptr) {
                continue;
            }
            if (node->value == 0) {
                HLOGD("node value error 0x%x", idx);
                continue;
            }
            if (!node->section.inKernel) {
                userSymbolsHits[pid].insert(node->section.ip);
                continue;
            }
            uint64_t ip = node->section.ip | KERNEL_PREFIX;
            if (ip == PERF_CONTEXT_KERNEL || ip == PERF_CONTEXT_USER) {
                continue;
            }
            kernelSymbolsHits.insert(ip);
        }
    }
}

void CallStackProcessor::ImportUniqueStackNodes(const std::vector<UniStackTableInfo>& uniStackTableInfos)
{
    for (const UniStackTableInfo& item : uniStackTableInfos) {
        auto stackTable = std::make_shared<UniqueStackTable>(item.pid, item.tableSize);
        for (const UniStackNode& node : item.nodes) {
            stackTable->ImportNode(node.index, node.node);
        }
        processStackMap_[item.pid] = std::move(stackTable);
    }
}

void CallStackProcessor::Clear()
{
    processStackMap_.clear();
#if defined(is_ohos) && is_ohos
    callstack_.ClearCache();
#endif
}

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
