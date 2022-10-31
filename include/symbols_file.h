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

#ifndef HIPERF_SYMBOLS_H
#define HIPERF_SYMBOLS_H

#include <cinttypes>
#include <iomanip>
#include <sstream>
#include <string>

#include "perf_file_format.h"
#include "utilities.h"

#define HIPERF_ELF_READ_USE_MMAP

namespace OHOS {
namespace Developtools {
namespace HiPerf {
constexpr const char KERNEL_MMAP_NAME[] = "[kernel.kallsyms]";
constexpr const char KERNEL_MODULES_EXT_NAME[] = ".ko";
constexpr const char KERNEL_ELF_NAME[] = "vmlinux";
constexpr const char MMAP_VDSO_NAME[] = "[vdso]";
constexpr const char MMAP_ANONYMOUS_NAME[] = "[anon]";
constexpr const char MMAP_ANONYMOUS_OHOS_NAME[] = "//anon";

const std::string NOTE_GNU_BUILD_ID = ".note.gnu.build-id";
const std::string EH_FRAME_HR = ".eh_frame_hdr";
const std::string EH_FRAME = ".eh_frame";
const std::string ARM_EXIDX = ".ARM.exidx";
const std::string SYMTAB = ".symtab";
const std::string DYNSYM = ".dynsym";
const std::string GNU_DEBUGDATA = ".gnu_debugdata";
const std::string PLT = ".plt";
const std::string LINKER_PREFIX = "__dl_";
const std::string LINKER_PREFIX_NAME = "[linker]";

const int MAX_SYMBOLS_TYPE_NAME_LEN = 10;

class FileSymbol {
    [[maybe_unused]] uint64_t vaddr_ = 0;
    [[maybe_unused]] uint64_t len_ = 0;
    std::string name_ = "";
    std::string demangle_ = ""; // demangle string
    FileSymbol(uint64_t vaddr, uint64_t len, const char *name, const char *demangle)
        : vaddr_(vaddr), len_(len), name_(name), demangle_(demangle)
    {
    }
};

struct Symbol {
    uint64_t funcVaddr_ = 0;
    uint64_t offsetToVaddr_ = 0;
    uint64_t fileVaddr_ = 0;
    uint64_t taskVaddr_ = 0;
    uint64_t len_ = 0;
    int32_t symbolFileIndex_ = -1; // symbols file index, used to report protobuf file
    int32_t index_ = -1;
    std::string_view name_ = "";
    std::string_view demangle_ = ""; // demangle string
    std::string_view module_ = "";   // maybe empty
    std::string_view comm_ = "";     // we need a comm name like comm@0x1234
    mutable std::string_view unknow_ = "";
    mutable bool matched_ = false; // if some callstack match this
    int32_t hit_ = 0;

    // elf use this
    Symbol(uint64_t vaddr, uint64_t len, const std::string &name, const std::string &demangle,
           const std::string module)
        : funcVaddr_(vaddr),
          fileVaddr_(vaddr),
          len_(len),
          name_(MemoryHold::Get().HoldStringView(name)),
          demangle_(MemoryHold::Get().HoldStringView(demangle)),
          module_(MemoryHold::Get().HoldStringView(module)) {}
    Symbol(uint64_t vaddr, uint64_t len, const std::string &name, const std::string &module)
        : Symbol(vaddr, len, name, name, module) {}

    // kernel use this
    Symbol(uint64_t vaddr, const std::string &name, const std::string &module)
        : Symbol(vaddr, 0, name, name, module) {}

    // Symbolic use this
    Symbol(uint64_t taskVaddr = 0, const std::string &comm = "")
        : taskVaddr_(taskVaddr), comm_(comm)
    {
    }

    // copy
    Symbol(const Symbol &other) = default;

    static bool SameVaddr(const Symbol &a, const Symbol &b)
    {
        return (a.funcVaddr_ == b.funcVaddr_);
    }
    bool Same(const Symbol &b) const
    {
        return (funcVaddr_ == b.funcVaddr_ and demangle_ == b.demangle_);
    }
    bool operator==(const Symbol &b) const
    {
        return Same(b);
    }

    bool operator!=(const Symbol &b) const
    {
        return !Same(b);
    }

    bool isValid() const
    {
        return !module_.empty();
    }

    void SetMatchFlag() const
    {
        matched_ = true;
    }

    inline bool HasMatched() const
    {
        return matched_;
    }

    std::string_view Name() const
    {
        if (!demangle_.empty()) {
            return demangle_;
        }
        if (!name_.empty()) {
            return name_;
        }
        if (unknow_.empty()) {
            std::stringstream sstream;
            if (!module_.empty()) {
                sstream << module_ << "+0x" << std::hex << fileVaddr_;
            } else {
                sstream << comm_ << "@0x" << std::hex << taskVaddr_;
            }
            std::string hold = sstream.str();
            unknow_ = MemoryHold::Get().HoldStringView(hold);
        }
        return unknow_;
    }

    std::string ToString() const
    {
        std::stringstream sstream;
        if (fileVaddr_ != 0) {
            sstream << "0x" << std::hex << fileVaddr_;
        } else {
            sstream << "0x" << std::hex << taskVaddr_;
        }
        sstream << " " << Name();
        return sstream.str();
    };

    std::string ToDebugString() const
    {
        std::stringstream sstream;
        sstream << "0x" << std::setfill('0') << std::setw(sizeof(funcVaddr_) * BYTE_PRINT_WIDTH)
                << std::hex << funcVaddr_;
        sstream << "|";
        sstream << std::setfill('0') << std::setw(sizeof(len_)) << len_;
        sstream << "|";
        sstream << demangle_ << "|";
        sstream << name_ << "|";
        sstream << (matched_ ? "matched" : "");
        sstream << " unknowname:" << unknow_.size();
        sstream << " task:" << (comm_.size() > 0 ? comm_ : "");
        sstream << "@" << taskVaddr_;
        sstream << " file:" << (module_.size() > 0 ? module_ : "");
        sstream << "@" << fileVaddr_;

        return sstream.str();
    };

    bool Contain(uint64_t addr) const
    {
        if (len_ == 0) {
            return funcVaddr_ <= addr;
        } else {
            return (funcVaddr_ <= addr) and ((funcVaddr_ + len_) > addr);
        }
    }

    // The range [first, last) must be partitioned with respect to the expression !(value < element)
    // or !comp(value, element)
    static bool ValueLessThen(uint64_t vaddr, const Symbol &a)
    {
        return vaddr < a.funcVaddr_;
    }
    static bool ValueLessEqual(uint64_t vaddr, const Symbol &a)
    {
        return vaddr <= a.funcVaddr_;
    }
    static bool CompareLessThen(const Symbol &a, const Symbol &b)
    {
        return a.funcVaddr_ < b.funcVaddr_; // we should use vaddr to sort
    };
    static bool CompareByPointer(const Symbol *a, const Symbol *b)
    {
        return a->funcVaddr_ < b->funcVaddr_; // we should use vaddr to sort
    };
};

enum SymbolsFileType {
    SYMBOL_KERNEL_FILE,
    SYMBOL_KERNEL_MODULE_FILE,
    SYMBOL_ELF_FILE,
    SYMBOL_JAVA_FILE,
    SYMBOL_JS_FILE,
    SYMBOL_UNKNOW_FILE,
};

class SymbolsFile {
public:
    SymbolsFileType symbolFileType_;
    std::string filePath_ = "";
    int32_t id_ = -1; // used to report protobuf file

    // [14] .text             PROGBITS         00000000002c5000  000c5000
    // min exec addr , general it point to .text
    // we make a default value for min compare
    static const uint64_t maxVaddr = std::numeric_limits<uint64_t>::max();

    uint64_t textExecVaddr_ = maxVaddr;
    uint64_t textExecVaddrFileOffset_ = 0;
    uint64_t textExecVaddrRange_ = maxVaddr;

    SymbolsFile(SymbolsFileType symbolType, const std::string path)
        : symbolFileType_(symbolType), filePath_(path) {};
    virtual ~SymbolsFile();

    // create the symbols file object
    static std::unique_ptr<SymbolsFile> CreateSymbolsFile(
        SymbolsFileType = SYMBOL_UNKNOW_FILE, const std::string symbolFilePath = EMPTY_STRING);
    static std::unique_ptr<SymbolsFile> CreateSymbolsFile(const std::string &symbolFilePath);

    // set symbols path
    bool setSymbolsFilePath(const std::string &symbolsSearchPath)
    {
        std::vector<std::string> symbolsSearchPaths = {symbolsSearchPath};
        return setSymbolsFilePath(symbolsSearchPaths);
    };
    bool setSymbolsFilePath(const std::vector<std::string> &);

    // load symbol from file
    virtual bool LoadSymbols([[maybe_unused]] const std::string &symbolFilePath = EMPTY_STRING)
    {
        HLOGV("virtual dummy function called");
        symbolsLoaded_ = true;
        return false;
    };
    // load debug info for unwind
    virtual bool LoadDebugInfo([[maybe_unused]] const std::string &symbolFilePath = EMPTY_STRING)
    {
        HLOGV("virtual dummy function called");
        debugInfoLoaded_ = true;
        return false;
    };
    // get the build if from symbols
    const std::string GetBuildId() const;

    // get the symbols vector
    const std::vector<Symbol> &GetSymbols();
    const std::vector<Symbol *> &GetMatchedSymbols();

    // get vaddr(in symbol) from ip(real addr , after mmap reloc)
    virtual uint64_t GetVaddrInSymbols(uint64_t ip, uint64_t mapStart, uint64_t mapOffset) const;

    // get symbols from vaddr
    const Symbol GetSymbolWithVaddr(uint64_t vaddr);

    // read the .text section and .eh_frame section (RO) memory from elf mmap
    // unwind use this to check the DWARF and so on
    virtual size_t ReadRoMemory(uint64_t, uint8_t * const, size_t) const
    {
        HLOGV("virtual dummy function called");
        return 0; // default not support
    }

    // get the section info , like .ARM.exidx
    virtual bool GetSectionInfo([[maybe_unused]] const std::string &name,
                                [[maybe_unused]] uint64_t &sectionVaddr,
                                [[maybe_unused]] uint64_t &sectionSize,
                                [[maybe_unused]] uint64_t &sectionFileOffset) const
    {
        HLOGV("virtual dummy function called");
        return false;
    }
#ifndef __arm__
    // get hdr info for unwind , need provide the fde table location and entry count
    virtual bool GetHDRSectionInfo([[maybe_unused]] uint64_t &ehFrameHdrElfOffset,
                                   [[maybe_unused]] uint64_t &fdeTableElfOffset,
                                   [[maybe_unused]] uint64_t &fdeTableSize) const
    {
        HLOGV("virtual dummy function called");
        return false;
    }
#endif
    // load from symbols from the perf.data format
    static std::unique_ptr<SymbolsFile> LoadSymbolsFromSaved(const SymbolFileStruct &);
    // save the symbols to perf.data format
    void ExportSymbolToFileFormat(SymbolFileStruct &symbolFileStruct);

    bool SymbolsLoaded()
    {
        return symbolsLoaded_;
    }

    // this means we are in recording
    // will try read some elf in runtime path
    static bool onRecording_;

protected:
    bool symbolsLoaded_ = false;
    bool debugInfoLoaded_ = false;
    bool debugInfoLoadResult_ = false;
    const std::string FindSymbolFile(const std::vector<std::string> &,
                                     std::string symboleFilePath = EMPTY_STRING) const;

    std::string SearchReadableFile(const std::vector<std::string> &searchPaths,
                                   const std::string &filePath) const;
    bool UpdateBuildIdIfMatch(std::string buildId);
    std::string buildId_;
    std::vector<std::string> symbolsFileSearchPaths_;
    std::vector<Symbol> symbols_ {};
    std::vector<Symbol *> matchedSymbols_ {};
    std::vector<FileSymbol> fileSymbols_ {};

    void AdjustSymbols();
    void SortMatchedSymbols();
    bool CheckPathReadable(const std::string &path) const;

    FRIEND_TEST(SymbolsFileTest, FindSymbolFile);
    FRIEND_TEST(SymbolsFileTest, UpdateBuildIdIfMatch);
    FRIEND_TEST(SymbolsFileTest, exportSymbolToFileFormat);
    FRIEND_TEST(SymbolsFileTest, exportSymbolToFileFormatMatched);
    friend class VirtualRuntimeTest;
    FRIEND_TEST(ReportJsonFileTest, ProcessSymbolsFiles);
    FRIEND_TEST(ReportProtobufFileTest, ProcessSymbolsFiles);
    friend class ReportProtobufFileTest;
};
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_SYMBOLS_H
