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
#include "ring_buffer_test.h"

#include <chrono>
#include <cinttypes>
#include <cstdlib>

#include <linux/perf_event.h>

#include "debug_logger.h"
#include "utilities.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
class RingBufferTest : public testing::Test {
public:
    static constexpr size_t MEGA = 1024 * 1024;
    static constexpr size_t CAP = 16 * MEGA;
    static constexpr size_t U8MASK = 0xFF;
    static constexpr size_t MAX_TESTSIZE = 1024;

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static void ReadBufferAndCheck(RingBuffer &buf);
    static void WriteBuffer(RingBuffer &buf);
};

void RingBufferTest::SetUpTestCase() {}

void RingBufferTest::TearDownTestCase() {}

void RingBufferTest::SetUp() {}

void RingBufferTest::TearDown() {}

void RingBufferTest::ReadBufferAndCheck(RingBuffer &buf)
{
    __u16 checkSize = sizeof(perf_event_header);
    perf_event_header readData = {0, 0, 0};
    uint8_t *p = nullptr;
    while ((p = buf.GetReadData()) != nullptr) {
        ASSERT_EQ(memcpy_s(&readData, sizeof(perf_event_header), p, sizeof(perf_event_header)), 0);
        ASSERT_EQ(checkSize, readData.size) \
            << " read data size " << readData.size << " expect data size " << checkSize;
        p += sizeof(perf_event_header);
        uint8_t data = static_cast<uint8_t>(checkSize & U8MASK);
        for (size_t i = 0; i < (checkSize - sizeof(perf_event_header)); i++) {
            ASSERT_EQ(*p, data) << "checkSize = " << hex << checkSize;
            p++;
        }
        checkSize++;
        checkSize %= MAX_TESTSIZE;
        if (checkSize < sizeof(perf_event_header)) {
            checkSize = sizeof(perf_event_header);
        }
        buf.EndRead();
    }
}

void RingBufferTest::WriteBuffer(RingBuffer &buf)
{
    perf_event_header writeData = {PERF_RECORD_MMAP, 0, sizeof(perf_event_header)};
    uint8_t *p = nullptr;
    while ((p = buf.AllocForWrite(writeData.size)) != nullptr) {
        ASSERT_EQ(memcpy_s(p, writeData.size, &writeData, sizeof(perf_event_header)), 0);
        p += sizeof(perf_event_header);
        uint8_t data = static_cast<uint8_t>(writeData.size & U8MASK);
        for (size_t i = 0; i < (writeData.size - sizeof(perf_event_header)); i++) {
            *p = data;
            p++;
        }
        buf.EndWrite();
        writeData.size++;
        writeData.size %= MAX_TESTSIZE;
        if (writeData.size < sizeof(perf_event_header)) {
            writeData.size = sizeof(perf_event_header);
        }
    }
}

/**
 * @tc.name: Test
 * @tc.desc: push several records of all type into the buffer
 * @tc.type: FUNC
 */
HWTEST_F(RingBufferTest, Basic, TestSize.Level1)
{
    RingBuffer rb {CAP};
    ASSERT_TRUE(rb.GetFreeSize() == CAP) << "the buffer should be empty now";
    WriteBuffer(rb);
    ASSERT_LE(rb.GetFreeSize(), CAP);

    ReadBufferAndCheck(rb);
    ASSERT_TRUE(rb.GetFreeSize() == CAP) << "the buffer should be empty now";
}

HWTEST_F(RingBufferTest, Wrap, TestSize.Level1)
{
    RingBuffer rb {CAP};
    const __u16 maxWriteSize = 65535;
    perf_event_header writeData = {PERF_RECORD_MMAP, 0, maxWriteSize};
    size_t half = 0;
    uint8_t *p = nullptr;
    while ((p = rb.AllocForWrite(writeData.size)) != nullptr) {
        ASSERT_EQ(memcpy_s(p, writeData.size, &writeData, sizeof(perf_event_header)), 0);
        rb.EndWrite();
        half += writeData.size;
        if (half >= (rb.GetFreeSize() / 2)) {
            break;
        }
    }
    ASSERT_LE(rb.GetFreeSize(), CAP);

    while (rb.GetReadData() != nullptr) {
        rb.EndRead();
    }
    ASSERT_EQ(rb.GetFreeSize(), CAP);

    WriteBuffer(rb); // write_head has turned round
    uint8_t *tail = rb.AllocForWrite(sizeof(perf_event_header));
    ASSERT_NE(tail, nullptr);
    p = rb.GetReadData();
    ASSERT_NE(p, nullptr);
    ASSERT_GE(p, tail); // reading has been ahead of writing

    ReadBufferAndCheck(rb);
    ASSERT_TRUE(rb.GetFreeSize() == CAP) << "the buffer should be empty now";
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
