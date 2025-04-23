//@ts-nocheck
import {inline_hook,_inline_hook} from "./so/inlinehook.js"
import {hook_func} from "./so/hook_func.js"
import { so_method } from "./so/so_method.js"

import {trace} from "./java/trace.js"
import {trace_change} from './java/trace_change.js'
import {hook_abstract} from './java/abstract.js'
import {all_so} from "./so/all_so.js"
import {so_info} from "./so/so_info.js"
import {scan} from "./so/scan.js"
import {hook_dlopen,monitorStrings,nativeHookFunction} from "./so/utils.js"
import { init_array } from "./so/init_array.js"
import { sktrace } from "./so/sktrace/sktrace.js"
import { stalker,native_trace } from "./so/stalker.js"
import { hook_string } from "./java/stringBuilder.js"
import { hook_file } from "./java/file.js"
import { native_print,log,printRegisters,stacktrace_so } from "./utils/log.js"
import { hexdumpAdvanced,hexdumpAsciiOnly } from "./so/BufferUtils.js"
import { antiFrida } from "./utils/anti_frida.js"
import { hookNativeSocket } from "./so/socket.js"
import { hook_str } from "./so/hook_str.js"

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
// native_print("libunity.so",0x9b4420,0x228)
// native_print("libunity.so",0x9b4500)
// monitorStrings("libunity.so")
// sktrace('libnativeLib.so')
// hookNativeSocket()

// hook_dlopen('libunity.so',hook_str)
// hook_str("openid")

//java
// setTimeout(() => {
//     trace('SSLOutputStream')
// }, 500);
// trace('com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream','write')
// trace('android.content.res.ResourcesImpl')
// trace("java.util.HashMap")
// trace("org.json.JSONObject")
// trace('java.io.BufferedOutputStream','write')
// trace('dalvik.system.DexFile','loadDex')
// trace('dalvik.system.BaseDexClassLoader')
// trace('java.lang.Class','getDeclaredConstructor')
// trace('java.net.InetSocketAddress')
// trace('java.net.Socket','connect')
// trace("java.io.BufferedReader",'readLine')

// af相关
// setTimeout(() => {
//     trace('com.appsflyer.internal.AFa1uSDK')
//     // trace("com.shopee.plugins.accountfacade.data.model.UserInfo",'setUserId')
// },2000);
// trace('com.appsflyer.internal.AFa1vSDK$9249')
// trace('com.appsflyer.internal.AFa1uSDK')
// trace("com.shopee.plugins.accountfacade.data.model.UserInfo",'setUserId')
// trace("javax.crypto.spec.SecretKeySpec")
// trace('java.lang.Class','getResourceAsStream')

// af iaa
// trace("com.appsflyer.adrevenue.adnetworks.AFWrapper")
// trace("com.appsflyer.adrevenue.AppsFlyerAdRevenue")
// trace("com.appsflyer.adrevenue.data.model.AppsFlyerAdEvent")
// trace("com.unity3d.services.core.api.Sdk")
// 最详细的日志
// trace("com.unity3d.services.core.log.DeviceLog")
// 解密类
// trace("com.ironsource.ri")
// 竞价过程类
// trace("com.ironsource.f5")
// 网络请求类
// trace("com.vungle.ads.internal.network.VungleApiClient")
// 播放视频
// trace("com.unity3d.services.ads.api.VideoPlayer")
// trace('com.ironsource.mediationsdk.e')

trace("com.android.server.pm.PackageManagerService",'getPackageInfo')

// hook_abstract("com.anythink.rewardvideo.unitgroup.api.CustomRewardVideoAdapter")
// trace("com.anythink.network.unityads.UnityAdsATInterstitialAdapter")
// trace("com.anythink.core.common.l.a$1")
// 抽象类，hook没用
// trace("java.net.URL",'openConnection')
// trace("com.android.server.am.BroadcastQueue",'finishReceiverLocked')
// trace("java.io.InputStreamReader",'11111')

// ---------------常用java类-------------
// trace('dalvik.system.DexPathList')
// trace('dalvik.system.DexClassLoader')
// trace('dalvik.system.BaseDexClassLoader')
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
// trace("android.os.BaseBundle",'putString')
// trace('oze')

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
trace('com.delta.msdk.DidManager')

// setTimeout(trace,1000,'com.appsflyer.internal.AFa1xSDK$AFa1wSDK','values')
// hook_hashmap()
// trace('java.util.HashMap','put')
// trace('ava.lang.reflect.Method','invoke')
// hook_string()
// encryption()
// anti_InMemoryDexClassLoader()

// antiFrida()


  // native_hook()
  function native_hook(){
    nativeHookFunction(
      function(args, context, retval, base_addr, hook_addr,currentThreadId) {
        try{
          // onEnter回调函数体
          console.log("进入函数");
          // var module = Process.findModuleByName("libunity.so"); 
          //   //??是通配符
          //   var pattern = "62 35 39 66 65 61 66 36 37 39 63 63 34 34 39 39 63 62 31 31 30 39 32 30 38 61 64 34 61 36 35 61";
          //   //基址
          //   //从so的基址开始搜索，搜索大小为so文件的大小，搜指定条件03 49 ?? 50 20 44的数据
          //   var res = Memory.scan(module.base, module.size, pattern, {
          //       onMatch: function(address, size){
          //           //搜索成功
          //           console.log('搜索到 ' +pattern +" 地址是:"+ address.toString());  
          //       }, 
          //       onError: function(reason){
          //           //搜索失败
          //           // console.log('搜索失败');
          //       },
          //       onComplete: function()
          //       {
          //           //搜索完毕
          //           // console.log("搜索完毕")
          //       }
          //     });
  
          //   console.log(hexdump(ptr(args[1]), {
          //     length: 50,
          //     header: false,
          //     ansi: true
          // }))
  
          // var targetAddr = context.x19.add(0xc28);
          // var memValue = Memory.readU64(targetAddr);
          // hexdumpAdvanced(ptr(memValue))
  
          // var targetAddr = context.x0.add(0x670);
          // var memValue = Memory.readU64(targetAddr);
          // hexdumpAdvanced(ptr(memValue))
  
          // hexdumpAdvanced(context.x0);
          // log(stacktrace_so(context))
          
          // Memory.protect(context.x0, 0x1000, 'rwx');
          // MemoryAccessMonitor.enable({base: context.x0, size: 0x1000},
          //   {onAccess: function (details) {
          //     if (details.operation === 'write') {
          //       // 输出偏移地址
          //       log("写入的偏移地址："+details.address.sub(base_addr));
          //       log("写入来源："+details.source);
          //       log("写入调用堆栈"+stacktrace_so(context))
          //       log("写入内存"+hexdumpAdvanced(details.address))
          //     }
          //   }}
          // );
        
          //   MemoryAccessMonitor.attach(function (details) {
          //     if (details.operation === 'write' && details.address.equals(base_addr.add(context.x0))) {
          //         console.log('写入内存:', details.address, details.size, details.data);
          //     }
          // }
          // );  
  
        // var start_address = base_addr.add(0x348e18);  // 模块基址
        // var end_address = base_addr.add(0x348f98);  // 相对于基址的偏移
          Stalker.follow(this.tid, {
            events: {
                // 禁用所有事件，减少崩溃风险
                call: false,
                ret: false,
                exec: false,
                block: false,
                compile: false
            },
            transform(iterator) {

            do {
                var instruction = iterator.next();

                if (instruction === null) return;  // 安全检查

                const startAddress = instruction.address;
                // 确保地址在有效范围内
                const isModuleCode = startAddress.compare(start_address) >= 0 && 
                                    startAddress.compare(end_address) < 0;
                if(isModuleCode){
                    console.log("startAddress: 0x" + startAddress.sub(base_addr).toString(16));

                    //这里是寄存器变化时调用
                    iterator.putCallout((context) => {
                        log(JSON.stringify(context))
                        // log("x0:"+hexdumpAdvanced(context.x0));
                        // log("x1:"+hexdumpAdvanced(context.x1));
                    })



                    }
                    if (instruction !== null) {
                        iterator.keep();
                    }
                } while (instruction !== null);
            }
        });

        // for(var i=0;i<=7;i++){
        //   var reg = "x"+i;
        //   hexdumpAsciiOnly(ptr(context[reg]));
        // }
          // hexdumpAsciiOnly(context.x4)

          // hexdumpAdvanced(ptr(Memory.readU64(ptr(context.x0))))
          // hexdumpAdvanced(context.x0)
          // log(hexdumpAdvanced(context.x1))
          // log(hexdumpAdvanced(context.x2))
          // log(Memory.readCString(context.X1))
          // log(Memory.readCString(args[0]))
          // log(Memory.readCString(args[1]))
          // log(Memory.readCString(args[2]))
  
          // hexdumpAdvanced(context.x1);
          // hexdumpAdvanced(context.x3);
            // hexdumpAdvanced(context.x25);
  
            // var address = base_addr.add(0x11ad1b8);
            // // log("address:"+Memory.readCString(address));
            // log("address:"+hexdumpAdvanced(address));
  
          // printRegisters(context,["x8"]);
          // printRegisters(context);
  
          // var funcName = "memcpy";
          // const address = Module.findExportByName(null, funcName);
          // Interceptor.attach(address, {
          //   onEnter: function(args) {
          //       const sourceStr = Memory.readUtf8String(args[1]);
          //       log(`[${funcName}] 字符串内容: ${sourceStr}`);
          //   },
          //   onLeave: function(retval) {
          //   }
          // });
          }catch(e) {
            log("Error in onEnter: " + e.message);
        }
      },
      function(this,retval, context, args, base_addr, hook_addr) {
        // onLeave回调函数体
        // 处理返回值
        // console.log(hexdump(ptr(retval), {
        //     length: 50,
        //     header: false,
        //     ansi: true,
        //     ascii: false,
        //     format: 'linear'
        // }))
        
      },
      "libnativeLib.so",  // so_name参数
      0x1660
      // 0x9eaae4
      // 0x348ed0
      // 0x4818b8
          // 0x9b44d0    // 请求参数
              // 0x9b443c     // 都是请求
    );
  }
})