# HiPerf Annotate 工具

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

## 概述

HiPerf Annotate 是一个源代码注释工具，能够将性能分析信息直接添加到源代码和反汇编代码中。它帮助开发者通过显示每个函数、源代码行和汇编指令的执行时间统计，快速定位性能瓶颈。

## 功能特性

- **多格式支持**：同时支持 `perf.data`（二进制）和 `perf.data.dump`（文本）格式
- **支持平台**：支持 Windows 平台
- **智能符号化**：使用 LLVM 工具链（llvm-symbolizer/llvm-addr2line）进行精确的地址到源码映射
- **灵活过滤**：支持按特定动态共享对象（Dynamic Shared Object，DSO）进行过滤分析
- **源代码注释**：在源文件中添加内联性能注释
- **反汇编注释**：生成带性能注释的反汇编代码，支持指令级性能分析
- **DSO 大小阈值**：可配置 DSO 大小阈值，跳过过大的库以提高性能

## 安装

### 前置条件

1. **Python 3.8+**

   检查是否安装 python3。

   ```bash
   python3 --version
   ```

2. **LLVM 工具链**（可选安装）

   - 系统安装 llvm-symbolizer/llvm-addr2line/llvm-objdump 工具，将 LLVM 工具路径配置到系统环境变量 PATH
   - 检查是否安装 LLVM 工具

   ```bash
   llvm-symbolizer --version
   llvm-addr2line --version
   llvm-objdump --version
   ```

### 快速开始

```bash
# 基本用法
python3 hiperf_annotate.py -i perf.data -s /path/to/source --sym_dir ./binary_cache

# 指定 LLVM 工具路径
python3 hiperf_annotate.py -i perf.data -s /path/to/source --ndk_path /path/to/ndk --sym_dir ./binary_cache

# 直接使用 dump 文件
python3 hiperf_annotate.py -i perf.data.dump -s /path/to/source --sym_dir ./binary_cache

# 生成反汇编注释
python3 hiperf_annotate.py -i perf.data -s /path/to/source --sym_dir ./binary_cache --add_disassembly
```

## 使用方法

### 命令行选项

| 选项 | 说明 | 必需 | 默认值 |
|------|------|------|--------|
| `-i, --input` | 输入文件（perf.data 或 perf.data.dump） | 是 | - |
| `-s, --source_dirs` | 包含源文件的目录 | 否 | - |
| `--sym_dir` | 包含符号文件的目录（可指定多个） | 否 | `./binary_cache` |
| `--ndk_path` | LLVM 工具路径 | 否 | - |
| `--raw_period` | 显示原始周期值而非百分比 | 否 | `False` |
| `--summary_width` | 摘要文件的最大宽度 | 否 | `80` |
| `--dso` | 仅分析指定 DSO 的数据 | 否 | - |
| `-o, --output` | 注释文件的输出目录 | 否 | `annotated_files` |
| `--add_disassembly` | 生成反汇编注释 | 否 | `False` |
| `--disassembly_output_dir` | 反汇编输出目录 | 否 | `annotated_disassembly` |
| `--dso_size_threshold` | DSO 大小阈值（字节），超过阈值的 DSO 不处理 | 否 | `1073741824` (1GB) |

### 使用示例

#### 示例 1：基本注释

```bash
# 使用性能数据注释源文件
python3 hiperf_annotate.py \
    -i perf.data \
    -s src/ \
    --sym_dir binary_cache/
```

#### 示例 2：DSO 过滤

```bash
# 仅分析特定库
python3 hiperf_annotate.py \
    -i perf.data \
    -s src/ \
    --sym_dir binary_cache/ \
    --dso libhilog.so
```

#### 示例 3：原始周期值

```bash
# 显示原始周期值而非百分比
python3 hiperf_annotate.py \
    -i perf.data \
    -s src/ \
    --sym_dir binary_cache/ \
    --raw_period
```

#### 示例 4：自定义输出目录

```bash
# 指定自定义的输出目录
python3 hiperf_annotate.py \
    -i perf.data \
    -s src/ \
    --sym_dir binary_cache/ \
    -o results/
```

#### 示例 5：生成反汇编注释

```bash
# 生成带性能注释的反汇编代码
python3 hiperf_annotate.py \
    -i perf.data \
    -s src/ \
    --sym_dir binary_cache/ \
    --add_disassembly
```

#### 示例 6：设置 DSO 大小阈值

```bash
# 跳过大于512MB的DSO
python3 hiperf_annotate.py \
    -i perf.data \
    -s src/ \
    --sym_dir binary_cache/ \
    --dso_size_threshold 536870912
```

## 输出说明

### 目录结构

```
annotated_files/                  # 源代码注释输出目录
├── summary                       # 摘要报告
├── binary_cache.txt              # 二进制文件索引缓存
├── run.log                       # 运行日志
└── [源代码目录结构]
    └── path/
        └── to/
            └── source/
                ├── main.cpp      # 带注释的源文件
                ├── utils.cpp
                └── ...

annotated_disassembly/            # 反汇编输出目录（如果启用 --add_disassembly）
└── [DSO名称目录]
    └── [函数名].asm               # 带注释的反汇编文件
```

### 摘要报告

摘要文件包含多层次的性能统计：

```txt
total period: 1000

=== DSO Summary ===
Total           Self            DSO
30.00%          5.00%           /system/lib64/libhilog.so
20.00%          15.00%          /system/lib64/libapp.so

=== File Summary ===
Total           Self            Source File
50.00%          10.00%          /path/to/source/main.cpp
30.00%          5.00%           /path/to/source/utils.cpp

=== Function/Line Summary in /path/to/source/main.cpp ===
Total           Self            Function/Line
40.00%          20.00%          main(StartLine 10)
10.00%          10.00%          main line 15
5.00%           5.00%           main line 16
```

### 理解 Total 与 Self

**核心概念：**

- **Total（累加周期）**：该函数/行执行的总时间，包括其调用的所有子函数的执行时间
- **Self（自身周期）**：该函数/行本身的执行时间，不包括子函数的执行时间

**关键关系：**
```txt
Total = Self + 所有子函数的 Self
```

**为什么 Total 百分比加起来不等于 100%？**

这是正常且符合预期的，因为存在重复计数问题，参考以下示例代码进行说明：

```cpp
int main() {                        // 函数A
    int result = calculate();       // 调用函数B
    printf("result: %d\n", result); // 函数A自己的代码
    return 0;
}

int calculate() {                   // 函数B
    int sum = 0;
    for (int i = 0; i < 100; i++) { // 函数B自己的代码
        sum += i;                
    }
    return sum;
}
```

**假设性能采样结果：**
- `main()` 函数：Total=100%, Self=20%
- `calculate()` 函数：Total=80%, Self=80%

**解释：**
1. `main().Total=100%`：表示程序运行总时间中，100% 的时间花在 `main()` 及其所有子调用上
2. `main().Self=20%`：表示只有 20% 的时间花在 `main()` 自己的代码上（`printf()` 等）
3. `calculate().Total=80%`：表示 80% 的时间花在 `calculate()` 及其子调用上
4. `calculate().Self=80%`：表示 80% 的时间花在 `calculate()` 自己的代码上

**验证公式：**
```
main().Total = main().Self + calculate().Self
100% = 20% + 80%  ✓ 正确
```

**为什么 Total 加起来超过 100%？**
```
main().Total + calculate().Total = 100% + 80% = 180%
```

这是正常的，因为：
- `main().Total` 包含了 `calculate()` 的所有时间
- `calculate().Total` 也包含了它自己的所有时间
- `calculate()` 的时间被**重复计算**了两次

**正确的理解方式：**
- **Total 列**：查看该函数在调用链中的位置，越靠上层的函数 Total 越大
- **Self 列**：查看该函数本身的执行时间，所有函数的 Self 加起来等于 100%

**实际应用场景：**
1. **定位热点函数**：看 Total 列，找到 Total 值大的函数（说明该函数及其子调用消耗大量时间）
2. **定位热点代码**：看 Self 列，找到 Self 值大的函数（说明该函数本身消耗大量时间）
3. **优化策略**：
   - 如果某函数 Total 大但 Self 小 → 说明其子函数是热点，应该优化子函数
   - 如果某函数 Self 大 → 说明该函数本身是热点，应该优化该函数的算法

### 源文件注释

**源文件注释示例：**

```cpp
/* [file] Total 100.00%, Self 100.00%  */#include <stdio.h>

/* [func] Total 85.00%, Self 85.00%    */int calculate() {
                                             int result = 0;
/* Total 50.00%, Self 50.00%           */    for (int i = 0; i < 100; i++) {
/* Total 35.00%, Self 35.00%           */        result += i;
                                             }
                                             return result;
                                          }

/* [func] Total 100.00%, Self 10.00%   */int main() {
/* Total 90.00%, Self 5.00%            */    int result = calculate();
/* Total 10.00%, Self 10.00%           */    printf("result: %d\n", result);
                                             return 0;
                                         }
```

**源文件注释说明：**

- `[file]`：文件级别的统计信息（仅在文件第一行显示）
- `[func]`：函数级别的统计信息（在函数起始行显示）
- `Total X%, Self Y%`：总周期和自身周期的百分比

### 反汇编文件注释

当启用 `--add_disassembly` 选项时，会生成带性能注释的反汇编代码：

**反汇编文件注释示例：**

```assembly
/* Function: calculate */
/* 10.00% */                                      ldr     w0, [sp, #24]
```

**反汇编注释说明：**

- 第一行是函数名注释：`/* Function: 函数名 */`
- 每条指令前面的注释显示该指令的执行时间占比
- 百分比表示该指令执行时间占总执行时间的比例
- 无百分比数值的指令表示该指令没有采样到

## 架构设计

```shell
hiperf_annotate.py
├── DumpFileParser         # 解析 perf.data.dump 格式
├── HiperfAddr2Line        # 地址到源代码行转换
├── HiperfReadElf          # ELF文件信息提取
├── HiperfBinaryFinder     # 二进制文件查找
├── HiperfObjdump          # 反汇编工具封装
├── SourceFileAnnotator    # 源代码注释控制器
├── DisassemblyAnnotator   # 反汇编注释控制器
└── Period, DsoPeriod, FilePeriod, Symbol, Sample  # 数据结构
```

## 故障排除

### 问题：找不到 llvm-symbolizer

**错误信息：**
```
ERROR: Cannot find llvm-symbolizer or llvm-addr2line. Please install LLVM toolchain or specify --ndk_path path.
```

**解决方案：**
1. 系统安装 llvm-symbolizer/llvm-addr2line 工具，检查 llvm-symbolizer/llvm-addr2line 是否在环境变量中，确保命令行工具可访问
2. 使用 `--ndk_path` 参数指定 LLVM 工具路径

### 问题：源文件找不到

**警告信息：**
```
WARNING: Can't find source file: /path/to/source/main.cpp
```

**解决方案：**
1. 确保使用 `-s` 参数指定了正确的源代码目录
2. 检查源文件路径是否正确
3. 确保源文件存在于指定目录中

### 问题：Build ID 不匹配

**警告信息：**
```
WARNING: local file build id xxx is not request build id yyy
```

**解决方案：**
1. 确保指定 sym_dir 目录下的符号文件是正确的版本
3. 检查 perf.data 和符号文件是否来自同一构建版本

### 问题：没有 .debug_line section

**警告信息：**
```
WARNING: Binary file doesn't contain .debug_line section.
```

**解决方案：**
1. 使用带调试信息的符号文件（未 stripped）

### 问题：DSO被跳过

**警告信息：**
```
WARNING: Skipping large DSO: libc.so (size: 2147483648 bytes > threshold: 1073741824 bytes)
```

**解决方案：**
1. 这不是错误，是性能优化措施
2. 如果需要分析该DSO，增加 `--dso_size_threshold` 值

### 问题：反汇编生成失败

**警告信息：**
```
WARNING: Cannot find llvm-objdump. Please install LLVM toolchain or specify --ndk_path path.
```

**解决方案：**
1. 系统安装 llvm-objdump 工具，检查 llvm-objdump 是否在环境变量中，确保命令行工具可访问
2. 使用 `--ndk_path` 参数指定 LLVM 工具路径

## 许可证

Apache License 2.0

详见 [LICENSE](../LICENSE) 文件。

## 联系方式

如有问题、疑问或贡献，请联系 HiPerf 开发团队。

---

**祝性能分析愉快！🚀**
