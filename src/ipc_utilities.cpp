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
using BundleMgrProxy = OHOS::sptr<OHOS::AppExecFwk::IBundleMgr>;
#else
using BundleMgrProxy = void*;
#endif
#if defined(is_ohos) && is_ohos
#include "iservice_registry.h"
#include "system_ability_definition.h"
#endif

namespace OHOS::Developtools::HiPerf {

static std::atomic<bool> g_haveIpc = false;

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
    HIPERF_HILOGI(MODULE_DEFAULT, "app is debuggable");
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
    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_TRUE(sam != nullptr, true, LOG_TYPE_PRINTF, "GetSystemAbilityManager failed!\n");
    sptr<IRemoteObject> remoteObject = sam->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    CHECK_TRUE(remoteObject != nullptr, true, LOG_TYPE_PRINTF, "Get BundleMgr SA failed!\n");
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    CHECK_TRUE(proxy != nullptr, true, LOG_TYPE_PRINTF, "iface_cast failed!\n");

    AppExecFwk::ApplicationInfo appInfo;
    bool ret = proxy->GetApplicationInfo(bundleName, AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO,
                                         AppExecFwk::Constants::ANY_USERID, appInfo);
    CHECK_TRUE(ret, true, 1, "%s:%s GetApplicationInfo failed!", __func__, bundleName.c_str());
    bool isEncrypted = (appInfo.applicationReservedFlag &
                        static_cast<uint32_t>(AppExecFwk::ApplicationReservedFlag::ENCRYPTED_APPLICATION)) != 0;
    HLOGD("check application encryped.%d : %s, pid:%d", isEncrypted, bundleName.c_str(), pid);
    return isEncrypted;
#else
    return false;
#endif
}

bool IsThirdPartyApp(const std::string& bundleName)
{
#if defined(is_ohos) && is_ohos && defined(BUNDLE_FRAMEWORK_ENABLE)
    g_haveIpc.store(true);
    std::string err = "";
    if (bundleName.empty()) {
        HIPERF_HILOGE(MODULE_DEFAULT, "IsThirdPartyApp error, err: [bundleName is empty!]");
        return false;
    }

    sptr<AppExecFwk::IBundleMgr> proxy = GetBundleMgrProxy(err);
    if (proxy == nullptr) {
        HIPERF_HILOGE(MODULE_DEFAULT, "IsThirdPartyApp error, err: [%{public}s: %{public}s]", bundleName.c_str(),
                      err.c_str());
        return false;
    }

    AppExecFwk::ApplicationInfo appInfo;
    bool ret = proxy->GetApplicationInfo(bundleName, AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO,
                                         AppExecFwk::Constants::ANY_USERID, appInfo);
    if (!ret) {
        HIPERF_HILOGE(MODULE_DEFAULT, "IsThirdPartyApp error, err: GetApplicationInfo failed!");
        return false;
    }
    bool isSystemApp = appInfo.isSystemApp;
    if (isSystemApp) {
        HIPERF_HILOGE(MODULE_DEFAULT, "IsThirdPartyApp error, err: app is system app");
        return false;
    }
    HIPERF_HILOGI(MODULE_DEFAULT, "app is third party app");
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
