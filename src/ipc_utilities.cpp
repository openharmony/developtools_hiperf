/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "ipc_utilities.h"

#include <atomic>

#include "debug_logger.h"
#include "hiperf_hilog.h"
#include "utilities.h"
#if defined(is_ohos) && is_ohos && defined(BUNDLE_FRAMEWORK_ENABLE)
#include "application_info.h"
#include "bundle_mgr_proxy.h"
using ApplicationInfo = OHOS::AppExecFwk::ApplicationInfo;
using BundleMgrProxy = OHOS::sptr<OHOS::AppExecFwk::IBundleMgr>;
#else
using ApplicationInfo = void*;
using BundleMgrProxy = void*;
#endif
#if defined(is_ohos) && is_ohos
#include "iservice_registry.h"
#include "system_ability_definition.h"
#endif

namespace OHOS::Developtools::HiPerf {

static std::atomic<bool> g_haveIpc = false;
#if defined(is_ohos) && is_ohos && defined(BUNDLE_FRAMEWORK_ENABLE)
int32_t g_getBundleInfoFlags = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
#else
int32_t g_getBundleInfoFlags = 1;
#endif

BundleMgrProxy GetBundleMgrProxy(std::string& err)
{
#if defined(is_ohos) && is_ohos && defined(BUNDLE_FRAMEWORK_ENABLE)
    err.clear();
    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        err = "GetSystemAbilityManager failed!";
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject = sam->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        err = "Get BundleMgr SA failed!";
        return nullptr;
    }

    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy == nullptr) {
        err = "iface_cast failed!";
        return nullptr;
    }

    return proxy;
#else
    err = "Not support bundle framework!";
    return nullptr;
#endif
}

bool GetAppInfo(const std::string& bundleName, ApplicationInfo& appInfo, int32_t flags)
{
#if defined(is_ohos) && is_ohos && defined(BUNDLE_FRAMEWORK_ENABLE)
    std::string err = "";
    sptr<AppExecFwk::IBundleMgr> proxy = GetBundleMgrProxy(err);
    if (proxy == nullptr) {
        HIPERF_HILOGE(MODULE_DEFAULT, "GetAppInfo error, err: [%{public}s]", err.c_str());
        return false;
    }
    AppExecFwk::BundleInfo bundleInfo;
    auto ret = proxy->GetBundleInfoV9(bundleName, flags, bundleInfo, AppExecFwk::Constants::ANY_USERID);
    if (ret != ERR_OK) {
        HIPERF_HILOGE(MODULE_DEFAULT, "GetAppInfo error, err: GetBundleInfo failed!");
        return false;
    }
    appInfo = bundleInfo.applicationInfo;
    return true;
#else
    HIPERF_HILOGE(MODULE_DEFAULT, "GetAppInfo error, err: not support bundle framework!");
    return false;
#endif
}

bool IsDebugableApp(const std::string& bundleName)
{
#if defined(is_ohos) && is_ohos && defined(BUNDLE_FRAMEWORK_ENABLE)
    g_haveIpc.store(true);
    std::string err = "";
    if (bundleName.empty()) {
        HIPERF_HILOGE(MODULE_DEFAULT, "IsDebugableApp error, err: [bundleName is empty!]");
        return false;
    }
    sptr<AppExecFwk::IBundleMgr> proxy = GetBundleMgrProxy(err);
    if (proxy == nullptr) {
        HIPERF_HILOGE(MODULE_DEFAULT, "IsDebugableApp error, err: [%{public}s]", err.c_str());
        return false;
    }

    bool isDebugApp = false;
    auto ret = proxy->IsDebuggableApplication(bundleName, isDebugApp);
    if (ret != ERR_OK) {
        HIPERF_HILOGE(MODULE_DEFAULT, "IsDebugableApp error, err: IsDebuggableApplication failed!");
        return false;
    }

    if (!isDebugApp) {
        HIPERF_HILOGE(MODULE_DEFAULT, "IsDebugableApp error, err: app is not debuggable");
        return false;
    }
    HIPERF_HILOGI(MODULE_DEFAULT, "app: %{public}s is debuggable", bundleName.c_str());
    return true;
#else
    return false;
#endif
}

bool IsApplicationEncryped(const int pid)
{
#if defined(is_ohos) && is_ohos && defined(BUNDLE_FRAMEWORK_ENABLE)
    g_haveIpc.store(true);
    CHECK_TRUE(pid > 0, true, LOG_TYPE_PRINTF, "Invalid -p value '%d', the pid should be larger than 0\n", pid);
    std::string bundleName = GetProcessName(pid);
    CHECK_TRUE(!bundleName.empty(), true, 1, "bundleName is empty,pid is %d", pid);
    auto pos = bundleName.find(":");
    if (pos != std::string::npos) {
        bundleName = bundleName.substr(0, pos);
    }
    AppExecFwk::ApplicationInfo appInfo;
    bool ret = GetAppInfo(bundleName, appInfo, g_getBundleInfoFlags);
    CHECK_TRUE(ret, true, 1, "%s:%s GetApplicationInfo failed!", __func__, bundleName.c_str());
    bool isEncrypted = (appInfo.applicationReservedFlag &
                        static_cast<uint32_t>(AppExecFwk::ApplicationReservedFlag::ENCRYPTED_APPLICATION)) != 0;
    HIPERF_HILOGI(MODULE_DEFAULT, "check application encryped.%{public}d : %{public}s, pid:%{public}d",
                  isEncrypted, bundleName.c_str(), pid);
    return isEncrypted;
#else
    return false;
#endif
}

bool IsProfileableThirdPartyApp(const std::string& bundleName)
{
#if defined(is_ohos) && is_ohos && defined(BUNDLE_FRAMEWORK_ENABLE)
    g_haveIpc.store(true);
    if (bundleName.empty()) {
        HIPERF_HILOGE(MODULE_DEFAULT, "IsProfileableThirdPartyApp error, err: [bundleName is empty!]");
        return false;
    }

    AppExecFwk::ApplicationInfo appInfo;
    if (!GetAppInfo(bundleName, appInfo, g_getBundleInfoFlags)) {
        return false;
    }
    if (!appInfo.profileable) {
        HIPERF_HILOGE(MODULE_DEFAULT, "IsProfileableThirdPartyApp: app is not profileable");
        return false;
    }
    if (appInfo.isSystemApp) {
        HIPERF_HILOGE(MODULE_DEFAULT, "IsProfileableThirdPartyApp: app is system app");
        return false;
    }
    HIPERF_HILOGI(MODULE_DEFAULT, "app: %{public}s is profileable third party app", bundleName.c_str());
    return true;
#else
    return false;
#endif
}

void CheckIpcBeforeFork()
{
    if (g_haveIpc.load()) {
        HIPERF_HILOGW(MODULE_DEFAULT, "fork after ipc!");
    }
}

} // namespace OHOS::Developtools::HiPerf
