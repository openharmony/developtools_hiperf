# hiperf火焰图工具

- ## 基础介绍
   hiperf 火焰图工具主要功能收集和整合性能分析数据，将分析结果转换为可视化性能分析报告
- **环境搭建**</br>
  a. 安装python-3.8.3
- **生成hiperf_report.html火焰图文件**</br>
 python make_report.py -i perf.data -r hiperf_report.html
- ## 功能使用介绍
- ## 1、hiperf火焰图工具支持将指定函数拆分至目标so
- **规格说明(配置文件说明)**</br>
 **配置项说明：**
filter_rules: 过滤规则，包含：</br>
    filter_str: 表示需要迁移函数包含的字段</br>
    new_lib_name: 新库名称</br>
    source_lib_name: 要拆分的源库名称</br>
  
   **默认情况下配置文件为空(根据需求配置)：**   </br>
 {</br>
        "filter_str": [],</br>
        "new_lib_name":"",</br>
        "source_lib_name":""</br>
    }</br>
- **功能使用示例介绍**</br>
**预制环境：**</br>
1、本地组成完整脚本工程，参考[hiperf readme](../README_zh.md)</br>
2、拉取最新的代码，将make_report.py和配置文件config.json替换到本地脚本工程</br>
**使用步骤：**</br>
1、配置config.json，配置示例内容：</br>
  "filter_rules":[</br>
    {</br>
        "filter_str": ["Parcel::Flush"],</br>
        "new_lib_name":"demo1.so",</br>
        "source_lib_name":"demo"</br>
    },</br>
    {</br>
        "filter_str": ["StartWork"],</br>
       "new_lib_name": "demo2",</br>
      "source_lib_name":  "demo3"</br>
    }</br>
  ]</br>
  注：其中demo1、demo2可以自定义名字，demo和demo3如果不存在会有错误日志打印。需要测试正常流程需要输入存在的so名字。其中filter_str字段需要自定义，当前配置只作为示例。</br>
2、将perfect.data与代码放在同一个路径下</br>
3、通过命令：python 脚本路径/make_report.py执行make_report.py</br>
**预期结果：**</br>
1、demo.so中含有Parcel::Flush字符的函数，迁移到demo1.so</br>
2、demo3.so中含有StartWork字符的函数，迁移到demo2.so</br>