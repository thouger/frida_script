//@ts-nocheck
import {inline_hook,_inline_hook} from "./so/inlinehook.js"
import {hook_func} from "./so/hook_func.js"
import { so_method } from "./so/so_method.js"

import {trace} from "./java/trace.js"
import {trace_change} from './java/trace_change.js'
import {all_so} from "./so/all_so.js"
import {so_info} from "./so/so_info.js"
import {scan} from "./so/scan.js"
import { init_array } from "./so/init_array.js"
import { sktrace } from "./so/sktrace/sktrace.js"
import { stalker,native_trace } from "./so/stalker.js"
import { hook_string } from "./java/stringBuilder.js"
import { hook_file } from "./java/file.js"
import { native_print } from "./utils/log.js"

// import {findClass} from './java/findClass.js'
// import {all_java} from './java/all_java.js'
Java.perform(function () {
// import { one_instance } from "./java/one_instance.js"
// import { encryption } from "./java/encryption.js"
// import { findClass } from "./java/findClass.js"
// import {anti_InMemoryDexClassLoader} from './java/anti_InMemoryDexClassLoader';

// native层
// so_method('libAppGuard.so')
// setTimeout(all_so,5000)
// so_info('libAppGuard.so')
// inline_hook('libOnLoad.so',0x9E0)
// init_array()
// scan()
// all_so(false)
// hook_func('libc.so','openat')
// native_trace("libnativeLib.so",0x1208,0x14d);
// native_print("libnativeLib.so",0x1208)
// sktrace('libnativeLib.so')

//java
// trace_change()
// trace("com.cyjh.mobileanjian.vip.p377m.RootUtil",'upgradeRootPermission')
// trace('com.appsflyer.internal.AFLogger')

// ---------------常用java类-------------
// trace('dalvik.system.DexPathList')
// trace('dalvik.system.DexClassLoader')
trace('dalvik.system.BaseDexClassLoader')
// ---------------mlbb日志-------------
// mlbb的日志-1
// trace("com.ss.android.common.util.b")
// mlbb的日志-2
// trace('com.ss.android.common.applog.AppLog')
// 发送日志加密类
// trace('com.ss.android.common.applog.NetUtil')
// 日志发送的请求类
// trace("gsdk.impl.crash.isolate.b")

// trace('com.adjust.sdk.AdjustConfig')
// trace('com.adjust.sdk.network.ActivityPackageSender')
// trace('com.moba.unityplugin.MobaGameUnityActivity')
// trace('com.moba.unityplugin.MobaGameMainActivityWithExtractor')

// mlbb的getDeviceId、getOpenUdid、getInstallId、getClientUDID
// trace("com.ss.android.deviceregister.core.e",'getDeviceId')
// trace('com.ss.android.deviceregister.core.cache.internal.a','a')
// trace('com.appsflyer.internal.AFa1xSDK$AFa1zSDK$AFa1zSDK','AFInAppEventType')  
// trace('com.appsflyer.internal.AFa1ySDK')
// setTimeout(trace,1000,'com.appsflyer.internal.AFa1ySDK')

// setTimeout(trace,3000,'com.alibaba.minilibc.android.MtopMethodJniBridge')
// all_java('com.alibaba.minilibc.android.MtopMethodJniBridge')
// setTimeout(all_java,5000)
// findClass()

// hook_file()
// trace('com.alibaba.wireless.security.open.SecException')
// trace('com.uc.crashsdk.JNIBridge')

// setTimeout(trace,1000,'com.appsflyer.internal.AFa1xSDK$AFa1wSDK','values')
// hook_hashmap()
// trace('java.util.HashMap','put')
// trace('ava.lang.reflect.Method','invoke')
// hook_string()
// encryption()
// anti_InMemoryDexClassLoader()
})