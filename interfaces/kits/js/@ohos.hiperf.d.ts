/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

/**
 * Provides interfaces to trace a task for performance measure by hiperf.
 * result can be use by hiperf python script
 *
 * @devices phone, tablet
 * @since 7
 */

declare namespace hiperf {
  /**
   * Start record when RecordOption pass to Client
   */
  function startWithOption(): boolean;

  /**
   * Reset the option
   */
  function resetOption(): boolean;

  /**
   * Start record with default options
   */
  function start(): boolean;

  /**
   * Pause recording
   */
  function pause(): boolean;

  /**
   * Resume recording
   */
  function resume(): boolean;

  /**
   * Stop recording
   */
  function stop(): boolean;

  /**
   * Check the client is ready
   */
  function isReady(): boolean;

  /**
   * Set the output dir
   * @param directory
   */
  function setup(outputDir: string): boolean;

  /**
   * Get the output dir
   */
  function getOutputDir(): string;

  /**
   * Get the command path
   */
  function getCommandPath(): string;
  /**
   * Get the the fullpath of output file
   */
  function getOutputPerfDataPath(): string;

  function setDebugMode(): boolean;

  /**
   * Set output file name, default is perf.data
   * @param Filename
   */
  function setOutputFilename(outputFilename: string): boolean;

  /**
   * Get output file name
   */
  function getOutputFileName(): string;

  /**
   * Collect system-wide information for measures all processes/threads
   * @param default is disable.
   */
  function setTargetSystemWide(enble: boolean): boolean;

  /**
   * Compress record data.
   * @param default is disable.
   */
  function setCompressData(enble: boolean): boolean;

  /**
   * Specify cpu ID
   * @param cpu ID should 0,1,2...
   */
  function setSelectCpus(cpus: number[]): boolean;

  /**
   * Stop in <timeStopSec> seconds.
   * @param default is 10000 seconds
   */
  function setTimeStopSec(timeStopSec: number): boolean;

  /**
   * Set event sampling frequency.
   * @param default is 4000 samples every second.
   */
  function setFrequency(frequency: number): boolean;

  /**
   * Set event sampling period for tracepoint events.
   * recording one sample when <period> events happen.
   * @param default is 1
   */
  function setPeriod(period: number): boolean;

  /**
   * Customize the name of the event that needs to be sampled.
   */
  function setSelectEvents(selectEvents: string[]): boolean;

  /**
   * Customize the name of the event that needs to be grouped.
   * the function is added on the basis of the function of the SetSelectEvents().
   */
  function setSelectGroups(selectGroups: string[]): boolean;

  /**
   * Set to don't tracing child processes.
   * param default is disable
   */
  function setNoInherit(enable: boolean): boolean;

  /**
   * Set the limit process id of the collection target.
   * Conflicts with the SetTargetSystemWide(true).
   */
  function setSelectPids(selectPids: number[]): boolean;

  /**
   * Set the limit thread id of the collection target.
   * Conflicts with the SetTargetSystemWide(true).
   */
  function setSelectTids(selectTids: number[]): boolean;

  /**
   * Set don’t record events issued by hiperf itself.
   */
  function setExcludePerf(excludePerf: boolean): boolean;

  /**
   * Set the max percent of cpu time used for recording.
   * percent is in range [1-100]
   * @param default is 25
   */
  function setCpuPercent(cpuPercent: number): boolean;

  /**
   * Set tracing when threads are scheduled off cpu
   * @param default is disable
   */
  function setOffCPU(offCPU: boolean): boolean;

  /**
   * Set call-graph (stack chain/backtrace) recording, Default is 'fp'.
   * as the method to collect the information used to show the call graphs.
   * the value can be:
   * fp: frame pointer
   * dwarf: DWARF's CFI - Call Frame Information
   * 'dwarf,###' set sample stack size, size should be in 8~65528 and 8 byte aligned.
   */
  function setCallGraph(sampleTypes: string): boolean;

  /**
   * Set to unwind after recording.
   * If '-g dwarf' used, stack will be unwind while recording by default
   */
  function setDelayUnwind(delayUnwind: boolean): boolean;

  /**
   * Set to disable unwinding.
   * If '-g dwarf' used, stack will be unwind while recording  by default
   */
  function setDisableUnwind(disableUnwind: boolean): boolean;

  /**
   * Set callstack don't merged.
   * If '-g dwarf' is used, to break the 64k stack limit, callstack is merged by default
   */
  function setDisableCallstackMerge(disableCallstackMerge: boolean): boolean;

  /**
   * Set directory to look for symbol files, used for unwinding.
   */
  function setSymbolDir(symbolDir_: string): boolean;

  /**
   * Set to stop recording after <SIZE> bytes of records. Default is unlimited
   * format like: SIZE[K|M|G]
   */
  function setDataLimit(limit: string): boolean;

  /**
   * Set a OHOS app name, collect profile info for this app, the app must be debuggable.
   */
  function setAppPackage(appPackage: string): boolean;

  /**
   * Set the clock id to use for the various time fields in the perf_event_type records.
   */
  function setClockId(clockId: string): boolean;

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
  function setVecBranchSampleTypes(vecBranchSampleTypes: string[]): boolean;

  /**
   * Set the size of the buffer used to receiving sample data from kernel,
   * must be a power of two. If not set,  a value <=1024 will be used.
   */
  function setMmapPages(mmapPages: number): boolean;

  /**
   * Get the string vector of all options.
   */
  function getOptionVecString(): string[];
}
export default hiperf;
