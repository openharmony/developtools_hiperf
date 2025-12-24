# hiperf火焰图工具Readme

- ## 基础介绍
- **环境搭建**</br>
  a. 连接设备</br>
  b. 安装python-3.8.3
- **火焰图一键生成**</br>
  在脚本目录下执行命令Python main.py -app com.ohos.xxx -l lib.unstripped exe.unstripped
  注：-l 参数可以不带，unstripped符号表版本一定要和镜像版本一致，否则符号化失败


- ## 功能介绍以及测试说明
- ## 1、hiperf火焰图工具支持将指定函数拆分至目标so
- **需求描述**</br>

- **规格说明(配置文件说明)**</br>
 **配置项说明：**
filter_rules: 过滤规则，包含：</br>
    filter_str: 表示需要迁移函数包含的字段</br>
    new_lib_name: 新库名称</br>
    source_lib_name: 要拆分的源库名称</br>
  
   **默认情况下配置文件为空(根据需求配置)：**   
 ![image.png](https://raw.gitcode.com/user-images/assets/8795508/01e5e06d-08c4-4db2-bedf-053b4a0ba792/image.png 'image.png')
 
- **测试验证**</br>
**测试预制环境：**</br>
拉取最新的代码，将make_report.py和配置文件config.json替换到本地测试工程</br>
**a、默认配置文件(空内容)测试场景**</br>
**测试步骤：**</br>
1、配置config.json，各项内容设置为空(默认)</br>
2、将测试测试的perfect.data与测试代码放在同一个路径下</br>
3、执行make_report.py</br>
**预期结果：**</br>
打印“过滤规则不符合要求，存在空内容”如截图
![image.png](https://raw.gitcode.com/user-images/assets/8795508/3e48bf57-1701-4751-a0ef-954ad7d9ee40/image.png 'image.png')
**b、无配置文件场景(执行脚本会有如下日志打印)：**</br>
**测试步骤：**</br>
1、删除config.json配置文件</br>
2、将测试测试的perfect.data与测试代码放在同一个路径下</br>
3、执行make_report.py</br>
**预期结果：**</br>
打印“config.json文件不存在”

![image.png](https://raw.gitcode.com/user-images/assets/8795508/3e48bf57-1701-4751-a0ef-954ad7d9ee40/image.png 'image.png')
**c、配置一条规则**</br>
**测试步骤：**</br>
1、配置config.json，配置内容：</br>
  "filter_rules":[</br>
    {</br>
        "filter_str": ["Parcel::Flush"],</br>
        "new_lib_name": "/system/lib64/libarkweb_v8.so",</br>
        "source_lib_name": "/system/lib64/chipset-pub-sdk/libutils.z.so"</br>
    }</br>
  ]</br>
2、将测试测试的perfect.data与测试代码放在同一个路径下</br>
3、执行make_report.py</br>
**预期结果：**</br>
1、/system/lib64/chipset-pub-sdk/libutils.z.so中含有Parcel::Flush字符的函数，迁移到/system/lib64/libarkweb_v8.so

**d、配置两条规则**</br>
**测试步骤：**</br>
1、配置config.json，配置内容：</br>
  "filter_rules":[</br>
    {</br>
        "filter_str": ["Parcel::Flush"],</br>
        "new_lib_name": "/system/lib64/libarkweb_v8.so",</br>
        "source_lib_name": "/system/lib64/chipset-pub-sdk/libutils.z.so"</br>
    },</br>
    {</br>
        "filter_str": ["StartWork"],</br>
        "new_lib_name": "/system/lib64/libarkweb_v8.so",</br>
        "source_lib_name": "/system/lib64/chipset-pub-sdk/libipc_single.z.so"</br>
    }</br>
  ]</br>
2、将测试测试的perfect.data与测试代码放在同一个路径下</br>
3、执行make_report.py</br>
**预期结果：**</br>
1、/system/lib64/chipset-pub-sdk/libutils.z.so中含有Parcel::Flush字符的函数，迁移到/system/lib64/libarkweb_v8.so</br>
2、/system/lib64/chipset-pub-sdk/libipc_single.z.so中含有StartWork字符的函数，迁移到/system/lib64/libarkweb_v8.so