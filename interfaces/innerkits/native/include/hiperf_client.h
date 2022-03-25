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
#ifndef HIPERF_CLIENT_H_
#define HIPERF_CLIENT_H_

#include <chrono>
#include <string>
#include <vector>

namespace OHOS {
namespace Developtools {
namespace HiPerf {
namespace HiperfClient {
static const std::string HiperfCommandName = "hiperf";
static const std::string SystemBinPath = "/system/bin/";
static const std::string TempBinPath = "/data/local/tmp/";
static const std::string CurrentPath = "./";
static const std::string PerfDataName = "perf.data";

static const std::string ReplyOK = "OK\n";
static const std::string ReplyFAIL = "FAIL\n";
static const std::string ReplyStart = "START\n";
static const std::string ReplyStop = "STOP\n";
static const std::string ReplyPause = "PAUSE\n";
static const std::string ReplyResume = "RESUME\n";
static const std::string ReplyCheck = "CHECK\n";

static const std::string CommandRecord = "record";
static const std::string ArgOutputPath = "-o";
static const std::string ArgDebug = "--verbose";
static const std::string ArgDebugMuch = "--much";
static const std::string ArgHilog = "--hilog";
static const std::string ArgPipeInput = "--pipe_input";
static const std::string ArgPipeOutput = "--pipe_output";
static const std::string ArgTargetSystemWide = "-a";
static const std::string ArgCompressData = "-z";
static const std::string ArgSelectCpus = "-c";
static const std::string ArgTimeStopSec = "-d";
static const std::string ArgFrequency = "-f";
static const std::string ArgPeriod = "--period";
static const std::string ArgSelectEvents = "-e";
static const std::string ArgSelectGroups = "-g";
static const std::string ArgNoInherit = "--no-inherit";
static const std::string ArgSelectPids = "-p";
static const std::string ArgSelectTids = "-t";
static const std::string ArgExcludePerf = "--exclude-hiperf";
static const std::string ArgCpuPercent = "--cpu-limit";
static const std::string ArgOffCPU = "--offcpu";
static const std::string ArgCallGraph = "--call-stack";
static const std::string ArgDelayUnwind = "--delay-unwind";
static const std::string ArgDisableUnwind = "--disable-unwind";
static const std::string ArgDisableCallstackMerge = "--disable-callstack-expand";
static const std::string ArgSymbolDir = "--symbol-dir";
static const std::string ArgOutputFilename = "-o";
static const std::string ArgDataLimit = "--data-limit";
static const std::string ArgAppPackage = "--app";
static const std::string ArgClockId = "--clockid";
static const std::string ArgVecBranchSampleTypes = "-j";
static const std::string ArgMmapPages = "-m";

class RecordOption {
public:
    /**
     * Set output file name, default is perf.data
     */
    void SetOutputFilename(const std::string &outputFilename)
    {
        outputFileName_ = outputFilename;
    }
    /**
     * Get output file name
     */
    const std::string GetOutputFileName() const
    {
        return outputFileName_;
    }

    /**
     * Collect system-wide information for measures all processes/threads
     * default is disable.
     */
    void SetTargetSystemWide(bool enable);
    /**
     * Compress record data. default is disable.
     */
    void SetCompressData(bool enable);
    /**
     * Specify cpu ID, cpu ID shoule be 0,1,2...
     */
    void SetSelectCpus(const std::vector<int> &cpus);
    /**
     * Stop in <timeStopSec> seconds. default is 10000 seconds
     */
    void SetTimeStopSec(int timeStopSec);
    /**
     * Set event sampling frequency. default is 4000 samples every second.
     */
    void SetFrequency(int frequency);
    /**
     * Set event sampling period for tracepoint events.
     * recording one sample when <period> events happen.
     * default is 1
     */
    void SetPeriod(int period);
    /**
     * Customize the name of the event that needs to be sampled.
     */
    void SetSelectEvents(const std::vector<std::string> &selectEvents);
    /**
     * Customize the name of the event that needs to be grouped.
     * the function is added on the basis of the function of the SetSelectEvents().
     */
    void SetSelectGroups(const std::vector<std::string> &selectGroups);
    /**
     * Set to don't tracing child processes. default is disable
     */
    void SetNoInherit(bool enable);
    /**
     * Set the limit process id of the collection target.
     * Conflicts with the SetTargetSystemWide(true).
     */
    void SetSelectPids(const std::vector<pid_t> &selectPids);
    /**
     * Set the limit thread id of the collection target.
     * Conflicts with the SetTargetSystemWide(true).
     */
    void SetSelectTids(const std::vector<pid_t> &selectTids);
    /**
     * Set don’t record events issued by hiperf itself.
     */
    void SetExcludePerf(bool excludePerf);
    /**
     * Set the max percent of cpu time used for recording.
     * percent is in range [1-100], default is 25
     */
    void SetCpuPercent(int cpuPercent);
    /**
     * Set tracing when threads are scheduled off cpu, default is disable
     */
    void SetOffCPU(bool offCPU);
    /**
     * Set call-graph (stack chain/backtrace) recording, Default is 'fp'.
     * as the method to collect the information used to show the call graphs.
     * the value can be:
     *  fp: frame pointer
     *  dwarf: DWARF's CFI - Call Frame Information
     *      'dwarf,###' set sample stack size, size should be in 8~65528 and 8 byte aligned.
     */
    void SetCallGraph(const std::string &sampleTypes);
    /**
     * Set to unwind after recording.
     * If '-g dwarf' used, stack will be unwind while recording by default
     */
    void SetDelayUnwind(bool delayUnwind);
    /**
     * Set to disable unwinding.
     * If '-g dwarf' used, stack will be unwind while recording  by default
     */
    void SetDisableUnwind(bool disableUnwind);
    /**
     * Set callstack don't merged.
     * If '-g dwarf' is used, to break the 64k stack limit, callstack is merged by default
     */
    void SetDisableCallstackMerge(bool disableCallstackMerge);
    /**
     * Set directory to look for symbol files, used for unwinding.
     */
    void SetSymbolDir(const std::string &symbolDir_);
    /**
     * Set to stop recording after <SIZE> bytes of records. Default is unlimited
     * format like: SIZE[K|M|G]
     */
    void SetDataLimit(const std::string &limit);
    /**
     * Set a OHOS app name, collect profile info for this app, the app must be debuggable.
     */
    void SetAppPackage(const std::string &appPackage);
    /**
     * Set the clock id to use for the various time fields in the perf_event_type records.
     */
    void SetClockId(const std::string &clockId);
    /**
     * Set to take branch stack sampling, filter can be
     *  any: any type of branch
     *  any_call: any function call or system call
     *  any_ret: any function return or system call return
     *  ind_call: any indirect branch
     *  call: direct calls, including far (to/from kernel) calls
     *  u: only when the branch target is at the user level
     *  k: only when the branch target is in the kernel\n"
     */
    void SetVecBranchSampleTypes(const std::vector<std::string> &vecBranchSampleTypes);
    /**
     * Set the size of the buffer used to receiving sample data from kernel,
     * must be a power of two. If not set,  a value <=1024 will be used.
     */
    void SetMmapPages(int mmapPages);

    /**
     * Get the string vector of all options.
     */
    const std::vector<std::string> &GetOptionVecString() const
    {
        return args_;
    }

private:
    std::vector<std::string> args_ = {};
    std::string outputFileName_ = "";

    void SetOption(const std::string &name, bool enable);
    void SetOption(const std::string &name, int value);
    void SetOption(const std::string &name, const std::vector<int> &vInt);
    void SetOption(const std::string &name, const std::string &str);
    void SetOption(const std::string &name, const std::vector<std::string> &vStr);
};

class Client {
public:
    /**
     * Set output dir and constuct
     */
    Client(const std::string &outputDir = TempBinPath);
    ~Client();
    /**
     * Start record with default options
     */
    bool Start();
    /**
     * Start record with options of string vector
     */
    bool Start(const std::vector<std::string> &args);
    /**
     * Start record with options of RecordOption
     */
    bool Start(const RecordOption &option);
    /**
     * Pause recording
     */
    bool Pause();
    /**
     * Resume recording
     */
    bool Resume();
    /**
     * Stop recording
     */
    bool Stop();
    /**
     * Check the client is ready
     */
    bool IsReady();
    /**
     * Set the output dir
     */
    bool Setup(std::string outputDir);

    /**
     * Get the output dir
     */
    const std::string &GetOutputDir() const
    {
        return outputDir_;
    }
    /**
     * Get the command path
     */
    const std::string &GetCommandPath() const
    {
        return executeCommandPath_;
    }
    /**
     * Get the the fullpath of output file
     */
    const std::string GetOutputPerfDataPath() const
    {
        return outputDir_ + outputFileName_;
    }

    void SetDebugMode();
    void SetDebugMuchMode();
    void EnableHilog();

private:
    static const uint64_t PIPE_READ = 0;
    static const uint64_t PIPE_WRITE = 1;
    static constexpr size_t SIZE_ARGV_TAIL = 1; // nullptr
    static constexpr int64_t THOUSAND = 1000;

    bool WaitCommandReply(std::chrono::milliseconds = std::chrono::milliseconds(THOUSAND));
    bool SendCommandAndWait(const std::string &cmd);
    void KillChild();
    void GetExecCmd(std::vector<std::string> &cmd, int pipeIn, int pipeOut,
                    const std::vector<std::string> &args);

    std::string outputDir_ = "";
    std::string outputFileName_ = "";
    std::string executeCommandPath_ = "";
    bool ready_ = false;
    pid_t myPid_ = -1;
    bool debug_ = false;
    bool debugMuch_ = false;
    bool hilog_ = false;

    int clientToServerFd_ = -1;
    int serverToClientFd_ = -1;
    pid_t hperfPid_ = -1;
};
} // namespace HiperfClient
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
#endif // HIPERF_CLIENT_H_
