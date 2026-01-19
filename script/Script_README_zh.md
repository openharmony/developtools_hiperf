# hiperf火焰图工具

 ## 基础介绍
   hiperf 火焰图工具主要功能收集和整合性能分析数据，将分析结果转换为可视化性能分析报告</br>
 **环境搭建**</br>
  a. 安装python-3.8.3</br>
 **生成hiperf_report.html火焰图文件**</br>
 python make_report.py -i perf.data -r hiperf_report.html
 ## 功能使用介绍
 ## 1、hiperf火焰图工具支持将指定函数拆分至目标so
**规格说明(配置文件说明)**</br>
 **配置项说明：**</br>
    filter_rules: 过滤规则，包含：</br>
    filter_str: 表示需要迁移函数包含的字段</br>
    new_lib_name: 新库名称</br>
    source_lib_name: 要拆分的源库名称</br>
  
   **默认情况下配置文件为空(根据需求配置)：**   </br>
  ```
    {
        "filter_str": [],
        "new_lib_name":"",
        "source_lib_name":""
    }
  ```
 **功能使用示例介绍**</br>
**预制环境：**</br>
1、本地组成完整脚本工程</br> 
```
/developtools/hiperf
└── script			# 主脚本目录
    ├── bin			# 二进制文件目录
    │   └── windows		# Windows平台二进制
    │       └── x86_64		# x86_64架构二进制
    │           ├── hiperf_host.exe	# 主程序可执行文件
    │           ├── libhiperf_report.dll	# 性能报告库
    │           └── libsec_shared.dll	# 安全共享库
    │
    ├── report.html		# 主报告模板
    ├── report-diff.html	# 差异报告模板
    ├── config.json		# 配置文件
    ├── package.sh		# 打包脚本
    ├── make_report.py		# 报告生成脚本
    ├── make_diff.py		# 差异报告生成脚本
    ├── make_report_sample.py	# 报告样本生成脚本
    ├── command_script.py	# 命令脚本
    ├── record_control.py	# 记录控制脚本
    ├── recv_binary_cache.py	# 二进制缓存接收脚本
    ├── hiperf_utils.py		# 工具函数
    ├── main.py			# 主入口脚本
    └── loadlib_test.py		# 库加载测试脚本
  ```
**使用步骤：**</br>
1、配置config.json，配置示例内容：</br>
```
  "filter_rules":[
    {
        "filter_str": ["Parcel::Flush"],
        "new_lib_name":"demo1.so",
        "source_lib_name":"demo"
    },
    {
        "filter_str": ["StartWork"],
       "new_lib_name": "demo2",
      "source_lib_name":  "demo3"
    }
  ]
``` 
  注：其中demo1、demo2可以自定义名字，demo和demo3如果不存在会有错误日志打印。需要测试正常流程需要输入存在的so名字。其中filter_str字段需要自定义，当前配置只作为示例。</br>
2、将perf.data放工程目录下</br>
3、执行命令：python make_report.py -i perf.data</br>
注：在测试工程路径下执行</br>
**预期结果：**</br>
1、demo.so中含有Parcel::Flush字符的函数，迁移到demo1.so</br>
2、demo3.so中含有StartWork字符的函数，迁移到demo2.so</br>

## 2、hiperf火焰图增加近似名称线程及同名线程合并
规格说明(配置文件说明)
配置项说明：</br>
merge_pref_list: 待合并线程的前缀字符串</br>
默认情况下配置文件为空(根据需求配置)：
```
  {
       "merge_pref_list": []
  }
 ```
功能使用示例介绍</br>
使用步骤：</br>
1、配置config.json，配置示例内容：
```
  "filter_rules":[
    {
     "merge_pref_list": ["demo1"]
    }
  ]
  ```
注：其中demo1为待合并线程组名字中共有的字符串，当前配置只作为示例。</br>
2、将perf.data放工程目录下</br>
3、执行命令：python make_report.py -i perf.data</br>
注：在测试工程路径下执行</br>
预期结果：</br>
1、按进程维度，所有线程名带demo1字符串的线程进行合并为一个新线程(demo1*)，原线程数据不发生改变。