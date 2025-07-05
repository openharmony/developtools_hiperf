/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "lperf.h"

#include "lite_perf.h"

namespace OHOS {
namespace Developtools {
namespace HiPerf {
namespace HiPerfLocal {
class Lperf::Impl {
public:
    Impl();
    ~Impl();

    int StartProcessStackSampling(const std::vector<int>& tids, int freq, int milliseconds, bool parseMiniDebugInfo);
    int CollectSampleStackByTid(int tid, std::string& stack);
    int FinishProcessStackSampling();

private:
    std::shared_ptr<OHOS::HiviewDFX::LitePerf> litePerf_;
};

Lperf& Lperf::GetInstance()
{
    static Lperf lperfInstance;
    return lperfInstance;
}

Lperf::Lperf() : Impl_(std::make_shared<Impl>())
{}

Lperf::~Lperf()
{
    Impl_ = nullptr;
}

int Lperf::StartProcessStackSampling(const std::vector<int>& tids, int freq,
                                     int milliseconds, bool parseMiniDebugInfo)
{
    return Impl_->StartProcessStackSampling(tids, freq, milliseconds, parseMiniDebugInfo);
}

int Lperf::CollectSampleStackByTid(int tid, std::string& stack)
{
    return Impl_->CollectSampleStackByTid(tid, stack);
}

int Lperf::FinishProcessStackSampling()
{
    return Impl_->FinishProcessStackSampling();
}

Lperf::Impl::Impl() : litePerf_(std::make_shared<OHOS::HiviewDFX::LitePerf>())
{}

Lperf::Impl::~Impl()
{
    litePerf_ = nullptr;
}

int Lperf::Impl::StartProcessStackSampling(const std::vector<int>& tids, int freq,
                                           int milliseconds, bool parseMiniDebugInfo)
{
    return litePerf_->StartProcessStackSampling(tids, freq, milliseconds, parseMiniDebugInfo);
}

int Lperf::Impl::CollectSampleStackByTid(int tid, std::string& stack)
{
    return litePerf_->CollectSampleStackByTid(tid, stack);
}

int Lperf::Impl::FinishProcessStackSampling()
{
    return litePerf_->FinishProcessStackSampling();
}
} // namespace HiPerfLocal
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS