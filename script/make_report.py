#!/usr/bin/env python
# -*- coding: utf-8 -*-
#   Copyright (c) 2021 Huawei Device Co., Ltd.
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import json
import os
import sys
import time
import argparse
from hiperf_utils import get_lib
from hiperf_utils import dir_check
from hiperf_utils import file_check

"""
配置项说明：
filter_rules: 过滤规则，包含：
    filter_str: 表示需要迁移函数包含的字段
    new_lib_name: 新库名称
    source_lib_name: 要拆分的源库名称
示例：
"filter_rules": [
    {
        "filter_str": ["v8::", "Builtins_"],
        "new_lib_name": "/system/lib64/libarkweb_v8.so",
        "source_lib_name": "libarkweb_engine.so"
    }
]
"""
def filter_and_move_symbols(data, config_file):
    # 读取规则
    filter_rules = config_file['filter_rules']
    new_lib_indices = {}
    for rule in filter_rules:
        new_lib_name = rule['new_lib_name']
        if new_lib_name not in data['symbolsFileList']:
            data['symbolsFileList'].append(new_lib_name)
            new_lib_indices[new_lib_name] = len(data['symbolsFileList']) - 1
    
    # 处理每个过滤规则
    for rule in filter_rules:
        filter_str_list = rule['filter_str']
        new_lib_name = rule['new_lib_name']
        source_lib_name = rule['source_lib_name']

        # 获取新库的索引
        new_index = new_lib_indices[new_lib_name]

        # 查找源库的索引
        source_lib_indices = set()
        for idx, lib_path in enumerate(data['symbolsFileList']):
            if source_lib_name in lib_path:
                source_lib_indices.add(idx)
        
        if not source_lib_indices:
            print(f"警告：未找到源库'{source_lib_name}'，跳过符号拆分")
            continue
        
        filter_strs = ", ".join(f"'{fs}'" for fs in filter_str_list)
        print(f"处理规则：从 '{source_lib_name}' 移动包含 {filter_strs} 的符号到 '{new_lib_name}'")
        print(f"找到源库 '{source_lib_name}' 的索引：{source_lib_indices}")

        # 收集包含任一过滤字符串的symbol ID
        filtered_symbol_ids = set()

        # 遍历SymbolMap，修改file字段并收集相关信息
        for key, sym_info in data['SymbolMap'].items():
            # 只处理源库中的符号
            if sym_info['file'] in source_lib_indices:
                # 检查符号是否包含任一过滤字符串
                symbol = sym_info['symbol']
                if any(filter_str in symbol for filter_str in filter_str_list):
                    # 记录symbol ID
                    symbol_id = int(key)
                    filtered_symbol_ids.add(symbol_id)

                    # 修改file字段为新的索引
                    sym_info['file'] = new_index
        print(f"从源库中找到 {len(filtered_symbol_ids)} 个匹配 {filter_strs} 的符号")

        # 处理recordSampleInfo -只遍历源库
        if 'recordSampleInfo' in data:
            for event_info in data['recordSampleInfo']:
                for process_info in event_info.get('processes', []):
                    for thread_info in process_info.get('threads', []):
                        # 为当前线程创建新的lib对象
                        new_lib_obj = {
                            "fileId": new_index,
                            "eventCount": 0,
                            "functions": []
                        }

                        # 处理线程中的每个lib
                        libs = thread_info.get('libs', [])

                        # 只处理源库
                        for lib in libs:
                            file_id = lib.get('fileId')
                            if file_id not in source_lib_indices:
                                continue
                            # 分离匹配和不匹配的函数
                            filtered_functions = []
                            remaining_functions = []
                            filtered_event_count = 0

                            for func in lib.get('functions', []):
                                if func.get('symbol') in filtered_symbol_ids:
                                    filtered_functions.append(func)
                                    # 累加counts[1]的值
                                    if len(func.get('counts', [])) > 1:
                                        filtered_event_count += func['counts'][1]
                                else:
                                    remaining_functions.append(func)
                            
                            # 如果有匹配的函数，更新原lib和新lib
                            if filtered_functions:
                                # 更新原lib
                                lib['functions'] = remaining_functions
                                lib['eventCount'] = max(0, lib.get('eventCount', 0) - filtered_event_count)

                                # 更新新lib
                                new_lib_obj['functions'].extend(filtered_functions)
                                new_lib_obj['eventCount'] += filtered_event_count
                        # 如果有匹配的函数，将新lib添加到线程的libs中
                        if new_lib_obj['functions']:
                            libs.append(new_lib_obj)
    return data

def get_used_binaries(perf_data, report_file, local_lib_dir, html_template):
    if local_lib_dir:
        get_lib().ReportUnwindJson(perf_data.encode("utf-8"),
                                   'json.txt'.encode("utf-8"),
                                   local_lib_dir.encode("utf-8"))
    else:
        get_lib().ReportJson(perf_data.encode("utf-8"),
                             'json.txt'.encode("utf-8"))
    time.sleep(2)

    if os.path.exists("config.json"):
        with open('json.txt', 'r') as f:
            data = json.load(f)
        with open('config.json', encoding="utf8") as f:
            config_file = json.load(f)
            data = filter_and_move_symbols(data, config_file)
        with open('json.txt', 'w') as f:
            json.dump(data, f)
    else:
        print(f"config.json文件不存在")

    with open('json.txt', 'r', errors='ignore') as json_file:
        all_json = json_file.read()
        template = os.path.join(html_template, 'report.html')
    with open(template, 'r', encoding='utf-8') as html_file:
        html_str = html_file.read()
    with open(report_file, 'w', encoding='utf-8') as report_html_file:
        report_html_file.write(html_str + all_json + '</script>'
                                      ' </body>'
                                      ' </html>')
    dirname, _ = os.path.split(os.path.abspath(sys.argv[0]))
    abs_path = os.path.join(dirname, report_file)
    print("save to %s success" % abs_path)
    os.remove('json.txt')


def main():
    parser = argparse.ArgumentParser(description=""" To make a report, you 
    need to enter the data source and the path of the report.""")
    parser.add_argument('-i', '--perf_data', default='perf.data',
                        type=file_check, help=""" The path of profiling 
                        data.""")
    parser.add_argument('-r', '--report_html', default='hiperf_report.html',
                        help="""the path of the report.""")
    parser.add_argument('-l', '--local_lib_dir', type=dir_check, default='./binary_cache',
                        help="""Path to find symbol dir use to
                         do offline unwind stack""")
    parser.add_argument('-t', '--html_template', default='./',
                        type=dir_check, help=""" The path of report html template
                        """)
    args = parser.parse_args()

    get_used_binaries(args.perf_data, args.report_html, args.local_lib_dir, args.html_template)


if __name__ == '__main__':
    main()
