#!/bin/bash
# Copyright (c) 2021 Huawei Device Co., Ltd.
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
set -e
DIR=$(dirname $(realpath ${BASH_SOURCE[0]}))
TOP=$(realpath $DIR/../../../../../..)

HOST_OUT=$TOP/out/ohos-arm-release/
TEST_OUT=$HOST_OUT/tests/unittest/developtools/hiperf/coverage
mkdir -p $TEST_OUT

# collect and convert all gcno and gcda to test.info
lcov -c -d $HOST_OUT -o $TEST_OUT/hiperf_ut_coverage.info --gcov-tool $DIR/gcov.sh
if [ $? -ne 0 ]; then
    echo "Install lcov: sudo apt install lcov"
fi

# filter out system headers
lcov -r $TEST_OUT/hiperf_ut_coverage.info \
    '/usr/include/*' \
    '*/third_party/*' \
    '*/utils/native/base/*' \
    '*/test/unittest/*' \
    '*.pb.h' \
    '*v1/*' \
    -o $TEST_OUT/hiperf_ut_coverage.info

# generate html report
genhtml --demangle-cpp -o $TEST_OUT/html $TEST_OUT/hiperf_ut_coverage.info
