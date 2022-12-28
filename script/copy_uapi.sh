#!/bin/bash
# Copyright (c) 2022 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

while getopts "o:i:t:h" arg
do
    case "${arg}" in
        "o")
            OUT_DIR=${OPTARG}
            ;;
        "i")
            SOURCE_DIR=${OPTARG}
            ;;
        "t")
            TARGET_ARCH=${OPTARG}
            ;;
        "h")
            echo "help"
            ;;
        ?)
            echo "unkonw argument"
            exit 1
            ;;
    esac
done

if [ ! -d "${OUT_DIR}" ];then
    mkdir -p ${OUT_DIR}
fi

echo "============= SOURCE_DIR: ${SOURCE_DIR} ============"
echo "============= OUT_DIR: ${OUT_DIR} ============"
echo "============= TARGET_ARCH: ${TARGET_ARCH} ============"

echo "cp -r ${TARGET_ARCH}/include/nonlinux/* ${OUT_DIR}/"
cp -r ${TARGET_ARCH}/include/nonlinux/* ${OUT_DIR}/

echo "cp ${SOURCE_DIR}/linux/perf_event.h ${OUT_DIR}/linux"
cp ${SOURCE_DIR}/linux/perf_event.h ${OUT_DIR}/linux/
