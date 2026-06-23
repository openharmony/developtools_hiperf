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
#define HILOG_TAG "KernelSymbolLoader"

#include "kernel_symbol_loader.h"

#include <cinttypes>
#include <map>

#include <unistd.h>

#include "debug_logger.h"
#include "hiperf_hilog.h"
#include "utilities.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {

KernelSymbolLoader::KernelSymbolLoader(const std::vector<std::unique_ptr<SymbolsFile>>& symbolsFiles,
                                       MemoryMapManager& mapManager, ThreadManager& threadManager,
                                       const RuntimeContext& ctx, const SymbolsFileRegisterFunc& registerFunc)
    : symbolsFiles_(symbolsFiles), mapManager_(mapManager), threadManager_(threadManager),
      ctx_(ctx), registerFunc_(registerFunc)
{
}

void KernelSymbolLoader::UpdateKernelSymbols()
{
    HLOGD("create a kernel mmap record");
    // found kernel source
    auto kernelFile = SymbolsFile::CreateSymbolsFile(KERNEL_MMAP_NAME);
    // set symbol path If it exists
    if (symbolsPaths_.size() > 0) {
        kernelFile->setSymbolsFilePath(symbolsPaths_); // also load from search path
    }
    if (!ctx_.isRoot) {
        HLOGD("user mode do not load kernel syms");
        printf("Hiperf is not running as root mode. Do not need load kernel syms\n");
    }
    if (kernelFile->LoadSymbols()) {
        auto record = std::make_unique<PerfRecordMmap>(
            true, 0, 0, kernelFile->textExecVaddr_, kernelFile->textExecVaddrRange_,
            kernelFile->textExecVaddrFileOffset_, KERNEL_MMAP_NAME);

        if (recordCallBack_) {
            recordCallBack_(*record);
        }
        registerFunc_(std::move(kernelFile));
    } else {
        HLOGW("kernel symbol not found.\n");
    }
}

void KernelSymbolLoader::UpdateKernelModulesSymbols()
{
    HLOGD("load ko symbol and build id");
    for (auto& map : mapManager_.GetKernelMaps()) {
        if (map.name == KERNEL_MMAP_NAME) {
            continue;
        }
        auto kernelModuleFile = SymbolsFile::CreateSymbolsFile(SYMBOL_KERNEL_MODULE_FILE, map.name);
        if (symbolsPaths_.size() > 0) {
            kernelModuleFile->setSymbolsFilePath(symbolsPaths_); // also load from search path
        }
        kernelModuleFile->LoadSymbols();
        registerFunc_(std::move(kernelModuleFile));
    }
}

void KernelSymbolLoader::UpdateServiceSymbols()
{
    HLOGD("try to update kernel thread symbols for kernel service");
    std::string fileName = SYSMGR_FILE_NAME;
    auto symbolsFile = SymbolsFile::CreateSymbolsFile(SYMBOL_KERNEL_THREAD_FILE, fileName);

    HLOGD("add kernel service symbol file: %s", fileName.c_str());
    if (symbolsFile->LoadSymbols()) {
        registerFunc_(std::move(symbolsFile));
    } else {
        HLOGW("symbols file for '%s' not found.", fileName.c_str());
    }
}

void KernelSymbolLoader::UpdateDevhostSymbols()
{
    HLOGD("try to update kernel thread symbols for devhost");
    auto kallsyms = SymbolsFile::CreateSymbolsFile(SYMBOL_KERNEL_THREAD_FILE, DEVHOST_FILE_NAME);
    // file name of devhost.ko
    std::map<std::string_view, std::unique_ptr<SymbolsFile>> koMaps;
    koMaps[DEVHOST_FILE_NAME] =
        SymbolsFile::CreateSymbolsFile(SYMBOL_KERNEL_THREAD_FILE, DEVHOST_LINUX_FILE_NAME);

    if (kallsyms->LoadSymbols()) {
        for (auto& symbol : kallsyms->GetSymbols()) {
            if (koMaps.find(symbol.module_) == koMaps.end()) {
                std::string filename = std::string(symbol.module_);
                // [devhost] to /liblinux/devhost.ko
                filename.erase(filename.begin());
                filename.erase(filename.end() - 1);
                filename = DEVHOST_LINUX_PREFIX + filename + KERNEL_MODULES_EXT_NAME;
                koMaps[symbol.module_] =
                    SymbolsFile::CreateSymbolsFile(SYMBOL_KERNEL_THREAD_FILE, filename);
            }
            if (koMaps[symbol.module_] == nullptr) {
                continue;
            }
            koMaps[symbol.module_]->AddSymbol(std::move(symbol));
        }

        HLOGD("devhost loaded %zu symbolfiles", koMaps.size());
        for (auto& it : koMaps) {
            if (it.second == nullptr) {
                continue;
            }
            HLOGD("Load %zu symbols to %s", it.second->GetSymbols().size(),
                  it.second->filePath_.c_str());
            registerFunc_(std::move(it.second));
        }
    } else {
        HLOGW("symbols file for devhost parse failed.");
    }

    // update normal symbole files
    pid_t devhostPid = ctx_.devhostPid;
    VirtualThread& kthread = threadManager_.GetThread(devhostPid, devhostPid);
    for (const auto& map : kthread.GetMaps()) {
        if (updateSymbolsCallBack_) {
            updateSymbolsCallBack_(map, devhostPid);
        }
    }
}

/*
   ARM functions
       The table below lists the symbols exported by the vDSO.

       symbol                 version
       ────────────────────────────────────────────────────────────
       __vdso_gettimeofday    LINUX_2.6 (exported since Linux 4.1)
       __vdso_clock_gettime   LINUX_2.6 (exported since Linux 4.1)

       Additionally, the ARM port has a code page full of utility
       functions.  Since it's just a raw page of code, there is no ELF
       information for doing symbol lookups or versioning.  It does
       provide support for different versions though.

       For information on this code page, it's best to refer to the
       kernel documentation as it's extremely detailed and covers
       everything you need to know:
       Documentation/arm/kernel_user_helpers.txt.

   aarch64 functions
       The table below lists the symbols exported by the vDSO.

       symbol                   version
       ──────────────────────────────────────
       __kernel_rt_sigreturn    LINUX_2.6.39
       __kernel_gettimeofday    LINUX_2.6.39
       __kernel_clock_gettime   LINUX_2.6.39
       __kernel_clock_getres    LINUX_2.6.39
*/
void KernelSymbolLoader::LoadVdso()
{
#if defined(is_ohos) && is_ohos
    VirtualThread myThread(getpid(), symbolsFiles_);
    myThread.ParseMap();
    for (const auto& map : myThread.GetMaps()) {
        if (!map->IsVdsoMap()) {
            continue;
        }
        std::string memory(map->end - map->begin, '\0');
        std::copy(reinterpret_cast<char*>((map->begin)), reinterpret_cast<char*>((map->end)),
                  &memory[0]);
        std::string tempPath("/data/log/hiperflog/");
        if (!IsDirectoryExists(tempPath)) {
            HIPERF_HILOGI(MODULE_DEFAULT, "%{public}s not exist.", tempPath.c_str());
            if (!CreateDirectory(tempPath, HIPERF_FILE_PERM_770)) {
                HIPERF_HILOGI(MODULE_DEFAULT, "Create hiperflog path failed.");
            }
        }
        std::string tempFileName = tempPath + map->name;
        if (!WriteStringToFile(tempFileName, memory)) {
            printf("vdso temp file create fail at %s\n", tempFileName.c_str());
            continue;
        }
        HLOGD("vdso temp file create at %s:%zu", tempFileName.c_str(), memory.size());
        auto symbolsFile = SymbolsFile::CreateSymbolsFile(map->name);
        symbolsFile->setSymbolsFilePath(tempPath); // also load from search path
        registerFunc_(std::move(symbolsFile));
        return;
    }
    HLOGD("no vdso found");
#endif
}

} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
