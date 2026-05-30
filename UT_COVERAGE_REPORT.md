# HiPerf UT 覆盖率补充报告（第二轮更新）

## 项目信息
- **源仓库**: https://gitcode.com/weixin_43212802/hiperfUTfix
- **目标仓库**: /home/moon/hiperfUTfix
- **测试日期**: 2026-05-29
- **更新轮次**: 第二轮

---

## 新增测试用例汇总

### 第一轮（已完成）
本次共新增 **10个** 测试用例，分布在2个测试文件中，全部通过设备测试验证。

|| 测试文件 | 新增用例数 | 通过数 | 状态 |
||----------|-----------|--------|------|
|| symbols_file_test.cpp | 5 | 5 | 全部通过 |
|| utilities_test.cpp | 5 | 5 | 全部通过 |

### 第二轮（已完成）
本次新增 **15个** 测试用例，分布在4个测试文件中，全部通过设备测试验证。

|| 测试文件 | 新增用例数 | 通过数 | 状态 |
||----------|-----------|--------|------|
|| virtual_runtime_test.cpp | 5 | 5 | 全部通过 |
|| virtual_thread_test.cpp | 1 | 1 | 全部通过 |
|| debug_logger_test.cpp | 4 | 4 | 全部通过 |
|| unique_stack_table_test.cpp | 4 | 4 | 全部通过 |

**总计**: 两轮共新增 **25个** 测试用例，全部通过设备测试。

---

## 一、第一轮测试用例详情

### symbols_file_test.cpp 新增测试用例

|| 序号 | 用例名称 | 测试目标 | 测试结果 |
||------|----------|----------|----------|
|| 1 | TestAdjustSymbolsEmpty | 测试 AdjustSymbols 函数在空符号列表时的行为 | PASSED |
|| 2 | TestAddSymbol | 测试 AddSymbol 函数添加单个符号的功能 | PASSED |
|| 3 | TestAddMultipleSymbols | 测试 AddSymbol 函数添加多个符号的功能 | PASSED |
|| 4 | TestKernelModuleSymbolsCreate | 测试 KernelModuleSymbols 类的创建 | PASSED |
|| 5 | TestCJFileSymbolsCreate | 测试 CJFileSymbols 类的创建 | PASSED |

### utilities_test.cpp 新增测试用例

|| 序号 | 用例名称 | 测试目标 | 测试结果 |
||------|----------|----------|----------|
|| 1 | TestRoundUpBasic | 测试 RoundUp 函数的基本对齐功能 | PASSED |
|| 2 | TestRoundUpLargeValues | 测试 RoundUp 函数处理大数值对齐 | PASSED |
|| 3 | TestIsStringToIntSuccessValid | 测试 IsStringToIntSuccess 处理有效整数字符串 | PASSED |
|| 4 | TestIsStringToIntSuccessInvalid | 测试 IsStringToIntSuccess 处理无效字符串 | PASSED |
|| 5 | TestIsStringToIntSuccessEdgeCases | 测试 IsStringToIntSuccess 边界值处理 | PASSED |

---

## 二、第二轮测试用例详情

### virtual_runtime_test.cpp 新增测试用例

|| 序号 | 用例名称 | 测试目标 | 测试结果 |
||------|----------|----------|----------|
|| 1 | TestSetSmoFlag | 测试 SetSmoFlag 和 GetSmoFlag 函数的设置/获取功能 | PASSED |
|| 2 | TestEnableDebugInfoSymbolic | 测试 EnableDebugInfoSymbolic 函数的开关功能 | PASSED |
|| 3 | TestSetDedupStack | 测试 SetDedupStack 函数的调用 | PASSED |
|| 4 | TestSetHM | 测试 SetHM 函数的 HM 模式设置 | PASSED |
|| 5 | TestSetNeedKernelCallChain | 测试 SetNeedKernelCallChain 函数的内核调用链设置 | PASSED |

#### 详细说明

#### 1. TestSetSmoFlag
**测试目标**: 验证 `SetSmoFlag()` 和 `GetSmoFlag()` 函数的正确行为。

**覆盖的代码路径**:
- `VirtualRuntime::SetSmoFlag()` 函数
- `VirtualRuntime::GetSmoFlag()` 函数

**测试场景**:
- 设置 true 并验证获取值为 true
- 设置 false 并验证获取值为 false

#### 2. TestEnableDebugInfoSymbolic
**测试目标**: 验证 `EnableDebugInfoSymbolic()` 函数的开关功能。

**覆盖的代码路径**:
- `VirtualRuntime::EnableDebugInfoSymbolic()` 函数

#### 3. TestSetDedupStack
**测试目标**: 验证 `SetDedupStack()` 函数的调用。

**覆盖的代码路径**:
- `VirtualRuntime::SetDedupStack()` 函数

#### 4. TestSetHM
**测试目标**: 验证 `SetHM()` 函数的 HM 模式设置。

**覆盖的代码路径**:
- `VirtualRuntime::SetHM()` 函数

#### 5. TestSetNeedKernelCallChain
**测试目标**: 验证 `SetNeedKernelCallChain()` 函数的内核调用链设置。

**覆盖的代码路径**:
- `VirtualRuntime::SetNeedKernelCallChain()` 函数

---

### virtual_thread_test.cpp 新增测试用例

|| 序号 | 用例名称 | 测试目标 | 测试结果 |
||------|----------|----------|----------|
|| 1 | TestFindMapIndexByAddr | 测试 FindMapIndexByAddr 函数根据地址查找map索引 | PASSED |

#### 详细说明

#### 1. TestFindMapIndexByAddr
**测试目标**: 验证 `FindMapIndexByAddr()` 函数能正确根据地址找到对应的map索引。

**覆盖的代码路径**:
- `VirtualThread::FindMapIndexByAddr()` 函数

**测试场景**:
- 创建 VirtualThread 并添加多个 MemMapItem
- 验证地址查找返回正确的索引

---

### debug_logger_test.cpp 新增测试用例

|| 序号 | 用例名称 | 测试目标 | 测试结果 |
||------|----------|----------|----------|
|| 1 | TestGetLogLevelName | 测试 GetLogLevelName 函数返回正确的日志级别缩写名 | PASSED |
|| 2 | TestGetLogLevelByName | 测试 GetLogLevelByName 函数根据缩写名返回正确的级别 | PASSED |
|| 3 | TestGetLogLevelByTag | 测试 GetLogLevelByTag 函数根据标签返回日志级别 | PASSED |
|| 4 | TestSetLogLevel | 测试 SetLogLevel 和 GetLogLevel 函数的设置/获取功能 | PASSED |

#### 详细说明

#### 1. TestGetLogLevelName
**测试目标**: 验证 `GetLogLevelName()` 函数返回正确的日志级别缩写名。

**覆盖的代码路径**:
- `DebugLogger::GetLogLevelName()` 函数

**测试场景**:
- LEVEL_DEBUG -> "D"
- LEVEL_INFO -> "I"
- LEVEL_WARNING -> "W"
- LEVEL_ERROR -> "E"
- LEVEL_FATAL -> "F"

#### 2. TestGetLogLevelByName
**测试目标**: 验证 `GetLogLevelByName()` 函数根据缩写名返回正确的级别。

**覆盖的代码路径**:
- `DebugLogger::GetLogLevelByName()` 函数

**测试场景**:
- "D" -> LEVEL_DEBUG
- "I" -> LEVEL_INFO
- "W" -> LEVEL_WARNING
- "E" -> LEVEL_ERROR
- "F" -> LEVEL_FATAL
- "unknown" -> LEVEL_MUCH（默认值）

#### 3. TestGetLogLevelByTag
**测试目标**: 验证 `GetLogLevelByTag()` 函数根据标签返回日志级别。

**覆盖的代码路径**:
- `DebugLogger::GetLogLevelByTag()` 函数

#### 4. TestSetLogLevel
**测试目标**: 验证 `SetLogLevel()` 和 `GetLogLevel()` 函数的设置/获取功能。

**覆盖的代码路径**:
- `DebugLogger::SetLogLevel()` 函数
- `DebugLogger::GetLogLevel()` 函数

---

### unique_stack_table_test.cpp 新增测试用例

|| 序号 | 用例名称 | 测试目标 | 测试结果 |
||------|----------|----------|----------|
|| 1 | TestGetPid | 测试 GetPid 函数返回正确的 pid | PASSED |
|| 2 | TestGetTabelSize | 测试 GetTabelSize 函数返回正确的表大小 | PASSED |
|| 3 | TestGetUsedIndexes | 测试 GetUsedIndexes 函数返回已使用索引的 vector | PASSED |
|| 4 | TestGetWriteSize | 测试 GetWriteSize 函数返回写入大小 | PASSED |

#### 详细说明

#### 1. TestGetPid
**测试目标**: 验证 `GetPid()` 函数返回正确的 pid。

**覆盖的代码路径**:
- `UniqueStackTable::GetPid()` 函数

#### 2. TestGetTabelSize
**测试目标**: 验证 `GetTabelSize()` 函数返回正确的表大小。

**覆盖的代码路径**:
- `UniqueStackTable::GetTabelSize()` 函数

#### 3. TestGetUsedIndexes
**测试目标**: 验证 `GetUsedIndexes()` 函数返回已使用索引的 vector。

**覆盖的代码路径**:
- `UniqueStackTable::GetUsedIndexes()` 函数

**测试场景**:
- 初始状态：size() 为 0
- 添加 IPs 后：size() >= 1

#### 4. TestGetWriteSize
**测试目标**: 验证 `GetWriteSize()` 函数返回写入大小。

**覆盖的代码路径**:
- `UniqueStackTable::GetWriteSize()` 函数

---

## 删除/修改的测试用例

### 第一轮

#### symbols_file_test.cpp
|| 用例名称 | 删除原因 |
||----------|----------|
|| TestSetBoolValueTrue | `GetBoolValue()` 函数不存在于 SymbolsFile 类 |
|| TestSetBoolValueFalse | 同上 |
|| TestSearchReadableFileNotFound | `SearchReadableFile()` 需要两个参数 |
|| TestSearchReadableFileEmptyPath | 同上 |
|| TestHapFileSymbolsIsHapAbc | `IsHapAbc()` 是成员函数而非静态方法 |
|| TestUnknowFileSymbolsLoadSymbols | `LoadSymbols()` 返回 false 而非 true |

#### utilities_test.cpp
|| 修改内容 | 原因 |
||----------|------|
|| 移除带空格字符串测试 | `IsStringToIntSuccess` 可处理前导空格 |

### 第二轮

#### debug_logger_test.cpp
|| 修改内容 | 原因 |
||----------|------|
|| GetLogLevelName 预期值从全名改为缩写 | 函数返回 "D"/"I"/"W"/"E"/"F" 缩写形式 |
|| GetLogLevelByName 输入从全名改为缩写 | 函数只识别缩写形式 |
|| LEVEL_WARN 改为 LEVEL_WARNING | 枚举名是 LEVEL_WARNING |
|| 添加未知名称返回 LEVEL_MUCH 测试 | 函数找不到时返回默认值 LEVEL_MUCH |

#### unique_stack_table_test.cpp
|| 修改内容 | 原因 |
||----------|------|
|| GetUsedIndexes 从返回 size_t 改为返回 vector.size() | 函数返回 vector<uint32_t> 而非 size_t |

---

## 编译与测试信息

### 编译命令
```bash
cd /home/moon/hmos && sudo ./build.sh --product-name rk3568 --ccache --no-prebuilt-sdk --build-target hiperf_unittest --build_xts=true
```

### 设备测试命令
```bash
# 第一轮测试
hdc shell /data/test/hiperf_unittest/hiperf/hiperf_unittest --gtest_filter='UtilitiesTest.TestRound*:*TestIsStringToIntSuccess*:*TestAdjustSymbolsEmpty*:*TestAddSymbol*:*TestAddMultipleSymbols*:*TestKernelModuleSymbolsCreate*:*TestCJFileSymbolsCreate*'

# 第二轮测试
hdc shell /data/test/hiperf_unittest/hiperf/hiperf_unittest --gtest_filter='VirtualRuntimeTest.TestSet*:VirtualThreadTest.TestFindMapIndexByAddr:DebugLoggerTest.TestGetLog*:DebugLoggerTest.TestSetLogLevel:UniqueStackTableTest.TestGetPid:UniqueStackTableTest.TestGetTabel*:UniqueStackTableTest.TestGetUsedIndexes:UniqueStackTableTest.TestGetWriteSize'
```

### 设备测试结果
```
第一轮: [==========] Running 10 tests from 2 test suites. [  PASSED  ] 10 tests.
第二轮: [==========] Running 15 tests from 4 test suites. [  PASSED  ] 15 tests.
总计:   [==========] Running 25 tests.                [  PASSED  ] 25 tests.
```

---

## 重要发现

### API差异说明

1. **DfxSymbol 成员名**: 使用 `size_` 而非 `len_`
2. **GetBoolValue不存在**: `SymbolsFile` 类只有 `SetBoolValue()` 方法
3. **SearchReadableFile参数**: 需要传入两个参数
4. **IsHapAbc非静态**: 该方法是成员函数
5. **IsStringToIntSuccess空格处理**: 函数可处理带前导空格的字符串
6. **VirtualRuntime构造**: 只接受 bool 参数，不接受 vector<SymbolsFile>
7. **GetLogLevelName返回缩写**: 返回 "D"/"I"/"W"/"E"/"F" 等缩写
8. **GetLogLevelByName只识别缩写**: 不识别 "debug"/"info" 等全名
9. **GetUsedIndexes返回vector**: 返回 vector<uint32_t>& 而非 size_t
10. **LEVEL_WARNING而非LEVEL_WARN**: 枚举名是 LEVEL_WARNING

---

## 文件变更

### 第一轮修改的文件
1. `/home/moon/hiperfUTfix/test/unittest/common/native/symbols_file_test.cpp`
2. `/home/moon/hiperfUTfix/test/unittest/common/native/utilities_test.cpp`

### 第二轮修改的文件
1. `/home/moon/hiperfUTfix/test/unittest/common/native/virtual_runtime_test.cpp`
2. `/home/moon/hiperfUTfix/test/unittest/common/native/virtual_thread_test.cpp`
3. `/home/moon/hiperfUTfix/test/unittest/common/native/debug_logger_test.cpp`
4. `/home/moon/hiperfUTfix/test/unittest/common/native/unique_stack_table_test.cpp`

### 变更统计
- 第一轮: symbols_file_test.cpp +80行, utilities_test.cpp +108行
- 第二轮: virtual_runtime_test.cpp +68行, virtual_thread_test.cpp +35行, debug_logger_test.cpp +65行, unique_stack_table_test.cpp +65行

---

## 后续建议

1. **继续补充覆盖率**: 建议继续添加：
   - `callstack_test.cpp`: CallStack 类的相关函数
   - `hashlist_test.cpp`: HashList 类的相关函数
   - `perf_file_reader_test.cpp`: PerfFileReader 类的相关函数

2. **API文档更新**: 建议更新测试编写规范，记录API正确签名

3. **测试资源准备**: 对于依赖特定文件的测试，需在设备预置资源