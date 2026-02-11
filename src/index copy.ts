//@ts-nocheck
import {inline_hook} from "./so/inlinehook.js"
import {native_hook, trace_so_call, smartRead, smartReadArgs} from "./so/hook_func.js"
import {so_method} from "./so/so_method.js"
import {trace} from "./java/trace.js"
import {trace_change} from './java/trace_change.js'
import {hook_abstract} from './java/abstract.js'
import {all_so} from "./so/all_so.js"
import {so_info} from "./so/so_info.js"
import {scan} from "./so/scan.js"
import {hook_dlopen,monitorStrings} from "./so/utils.js"
import {init_array} from "./so/init_array.js"
import {sktrace} from "./so/sktrace/sktrace.js"
import {stalker,native_trace,stalker_at_caller} from "./so/stalker.js"
import {hook_string} from "./java/stringBuilder.js"
import {hook_file} from "./java/file.js"
import {log,printRegisters,stacktrace_so} from "./utils/log.js"
import {hexdumpAdvanced,hexdumpAsciiOnly,toHex} from "./so/BufferUtils.js"
import {antiFrida} from "./utils/anti_frida.js"
import {hookNativeSocket} from "./so/socket.js"
import {hook_str} from "./so/hook_str.js"
import {dySslBypass, hookCronetEngine} from "./cert/ssl_bypass.js"
import {bypassVpnDetection} from "./java/vpn.js"
import {bypassSslPinning} from "./cert/sslpinning2.js"

// 主动调用 ttEncrypt 函数 - 通过 rpc.exports 导出
rpc.exports = {
    callTtencrypt: function() {
        Java.perform(function() {
            const targetClass = "com.bytedance.frameworks.encryptor.EncryptorUtil";

            log('开始查找类加载器...');

            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    try {
                        if (loader.findClass(targetClass)) {
                            log("成功找到类加载器");
                            log("loader is : " + loader);
                            Java.classFactory.loader = loader;
                            log("切换类加载器成功！");

                            // 使用找到的类加载器来调用方法
                            let EncryptorUtil = Java.use(targetClass);
                            let StringClass = Java.use("java.lang.String");
                            let str = "0123456789abcdef";

                            let result = EncryptorUtil.ttEncrypt(StringClass.$new(str).getBytes(), str.length);
                            log("ttEncrypt 结果: " + toHex(result));
                        }
                    } catch (error) {
                        // 忽略查找错误
                    }
                },
                onComplete: function () {
                    log("类加载器枚举完成");
                }
            });
        });
    },

    // 主动调用 libmetasec_ov.so 0X238ee0 函数
    callMetasecSign: function(url, headers) {
        let result = { success: false, error: "未执行" };

        // 使用 Java.perform 确保在正确的线程上下文中执行
        Java.perform(function() {
            try {
                // 如果没有提供参数，使用默认测试数据
                if (!url) {
                    url = "https://log-boot.tiktokv.com/service/2/app_log/?version_code=330205&ab_version=33.2.5&device_platform=android&aid=1233&ac=wifi&channel=googleplay&app_name=musical_ly&version_name=33.2.5&os=android&ssmix=a&device_type=Pixel+6&device_brand=google&language=en&os_api=33&os_version=13&openudid=8fd395ea1ccf3479&manifest_version_code=2023302050&resolution=1080*2209&dpi=420&update_version_code=2023302050&_rticket=1761894165808&is_pad=0&app_type=normal&sys_region=US&timezone_name=Asia%2FShanghai&app_language=en&ac2=wifi5g&uoo=0&op_region=US&timezone_offset=28800&build_number=33.2.5&host_abi=arm64-v8a&locale=en&region=US&ts=1761894165&cdid=43397d17-8ecd-4fbf-9801-6f7fc0cf0994";
                    log("使用默认 URL");
                }

                if (!headers) {
                    headers = "log-encode-type\ngzip\nsdk-version\n2\nx-tt-dm-status\nlogin=0;ct=0;rt=7\ncontent-encoding\ngzip\nx-ss-req-ticket\n1761894165815\npassport-sdk-version\n19\npns_event_id\n112\nx-vc-bdturing-sdk-version\n2.3.5.i18n\ncontent-type\napplication/octet-stream;tt-data=b\nx-ss-stub\n0999A9978AAF0DBDD9CEAD5D0C8C0405\ncontent-length\n2068\nx-tt-app-init-region\ncarrierregion=;mccmnc=;sysregion=US;appregion=US\nx-tt-store-region\nus\nx-tt-store-region-src\nlocal\nx-ss-dp\n1233\nx-tt-trace-id\n00-39136efa0102d657caa2cb5e1fc904d1-39136efa0102d657-01\nuser-agent\ncom.zhiliaoapp.musically/2023302050 (Linux; U; Android 13; en_US; Pixel 6; Build/TQ3A.230901.001.C2; Cronet/TTNetVersion:996128d2 2024-01-12 QuicVersion:ce58f68a 2024-01-12)\naccept-encoding\ngzip, deflate, br";
                    log("使用默认 Headers");
                }

                // 获取 libmetasec_ov.so 模块
                let module = Process.findModuleByName("libmetasec_ov.so");
                if (!module) {
                    result = { error: "libmetasec_ov.so not found" };
                    return;
                }

                log("找到 libmetasec_ov.so, 基址: " + module.base);

                // 计算函数地址
                let funcAddr = module.base.add(0X238ee0);
                log("函数地址: " + funcAddr);

                // 分配内存并写入 URL 字符串
                let urlMem = Memory.allocUtf8String(url);
                log("URL 参数地址: " + urlMem);
                log("URL 内容验证: " + urlMem.readUtf8String().substring(0, 100) + "...");

                // 分配内存并写入 Headers 字符串
                let headersMem = Memory.allocUtf8String(headers);
                log("Headers 参数地址: " + headersMem);
                log("Headers 内容验证: " + headersMem.readUtf8String().substring(0, 100) + "...");

                // 创建 NativeFunction
                let nativeFunc = new NativeFunction(funcAddr, 'pointer', ['pointer', 'pointer']);

                log("开始调用函数...");

                // 添加异常监控
                let interceptorAttached = false;
                try {
                    // 调用函数
                    let retval = nativeFunc(urlMem, headersMem);

                    log("函数返回地址: " + retval);

                    if (retval && !retval.isNull()) {
                        try {
                            let resultStr = retval.readUtf8String();
                            log("返回结果:\n" + resultStr);
                            result = { success: true, result: resultStr };
                        } catch (readErr) {
                            log("读取返回值失败: " + readErr.message);
                            // 尝试读取前几个字节看看是什么
                            try {
                                log("返回地址内存内容: " + hexdump(retval, {length: 64}));
                            } catch(e) {}
                            result = { success: false, error: "无法读取返回值: " + readErr.message };
                        }
                    } else {
                        log("返回值为 null 或 0");
                        result = { success: false, error: "返回值为空，可能缺少初始化或上下文" };
                    }
                } catch (callErr) {
                    log("函数调用异常: " + callErr.message);
                    result = { success: false, error: "调用异常: " + callErr.message };
                }

            } catch (e) {
                log("调用失败: " + e.message);
                log("堆栈: " + e.stack);
                result = { error: e.message, stack: e.stack };
            }
        });

        return result;
    }
};

// 同时也定义为全局函数（使用 globalThis）
globalThis.call_ttEncrypt = rpc.exports.callTtencrypt;
globalThis.call_metasec_sign = rpc.exports.callMetasecSign;

// 使用捕获的参数调用
globalThis.call_with_captured = function() {
    if (!capturedUrl || !capturedHeaders) {
        console.log("错误: 还没有捕获到参数，请先触发应用请求");
        return { error: "没有捕获到参数" };
    }

    try {
        console.log("\n========== 使用捕获的参数主动调用 ==========");
        let module = Process.findModuleByName("libmetasec_ov.so");
        if (!module) {
            return { error: "libmetasec_ov.so not found" };
        }

        let funcAddr = module.base.add(0X238ee0);
        console.log("函数地址:", funcAddr);
        console.log("URL 长度:", capturedUrl.length);
        console.log("Headers 长度:", capturedHeaders.length);

        let urlMem = Memory.allocUtf8String(capturedUrl);
        let headersMem = Memory.allocUtf8String(capturedHeaders);

        let nativeFunc = new NativeFunction(funcAddr, 'pointer', ['pointer', 'pointer']);

        console.log("调用函数...");
        let result = nativeFunc(urlMem, headersMem);

        console.log("返回值:", result);
        if (result && !result.isNull()) {
            let resultStr = result.readUtf8String();
            console.log("调用成功！返回结果:\n" + resultStr);
            return { success: true, result: resultStr };
        } else {
            console.log("调用失败：返回值为空");
            return { success: false, error: "返回值为空" };
        }
    } catch(e) {
        console.log("调用异常:", e.message);
        return { error: e.message, stack: e.stack };
    }
};

// 查看捕获的参数
globalThis.show_captured = function() {
    if (!capturedUrl || !capturedHeaders) {
        console.log("还没有捕获到参数");
        return;
    }
    console.log("\n========== 捕获的参数 ==========");
    console.log("URL:");
    console.log(capturedUrl);
    console.log("\nHeaders:");
    console.log(capturedHeaders);
    console.log("======================================\n");
};

// // ============ 方案2: Process.setExceptionHandler 捕获异常 ============
// Process.setExceptionHandler(function(details) {
//     console.log("\n========== 捕获到异常 ==========");
//     console.log("类型:", details.type);
//     console.log("地址:", details.address);
//     console.log("消息:", details.message);

//     // 如果是 APM 初始化错误，忽略并继续执行
//     if (details.message && details.message.indexOf("You must call Apm.getInstance().init()") !== -1) {
//         console.log("[!] 检测到 APM 初始化错误，已忽略");
//         console.log("[+] 恢复执行...");

//         // 返回 true 表示已处理，继续执行
//         return true;
//     }

//     // 其他异常，打印堆栈并继续
//     if (details.context) {
//         console.log("PC:", details.context.pc);
//         console.log("SP:", details.context.sp);
//     }

//     console.log("==============================\n");

//     // 返回 false 让 Frida 使用默认处理
//     return false;
// });

// console.log("[✓] 方案2: 全局异常处理器已设置");

// // ============ 测试所有方案 ============
// Java.perform(function () {

// // 方案3：Hook init() 提前设置标志
// try {
//     let ApmDelegate = Java.use("com.bytedance.apm.internal.ApmDelegate");

//     // Hook init 方法，确保初始化完成
//     ApmDelegate["init"].overload("android.content.Context", "com.bytedance.apm.config.ApmInitConfig").implementation = function(context, config) {
//         console.log("[APM-方案3] init() 开始执行，立即设置 mInited = true");

//         // 立即设置标志，避免竞态
//         this.mInited.value = true;

//         // 调用原始方法
//         let result = this["init"](context, config);

//         console.log("[APM-方案3] init() 执行完成");
//         return result;
//     };

//     console.log("[✓] 方案3: APM init hook 已设置");
// } catch(e) {
//     console.log("[-] 方案3失败:", e.message);
// }

// native层函数示例
// so_method('libAppGuard.so')
// all_so(false)
// so_info('libAppGuard.so')
// inline_hook('libOnLoad.so',0x9E0)
// init_array()
// scan()
// hook_func('libc.so','openat')

// ============ SSL Bypass ============
// dySslBypass()
// hookCronetEngine()

// ============ libEncryptor Hook 示例 ============
// trace_so_call("libEncryptor.so", 0x2BD8);

// ============ libsscronet sub_40216C Hook ============
// 方式1: 使用 smartRead - 完整自动分析（推荐）
// native_hook("libmetasec_ml.so", 0x40216C, {
//   logEnter: false,
//   logLeave: false,
//   customEnter: function(args, context) {
//     try {
//       // args[1] - 直接读取为 C 字符串（header key）
//       let key = args[1].readCString();
//       // 只关注 x-tt-trace-id
//       if (key === "x-tt-trace-id") {
//         console.log("\n========== 0x40216C: x-tt-trace-id ==========");

//         // 使用 smartRead 自动分析所有参数
//         console.log(smartRead(args[1], { label: "args[1] (key)", showHex: false }));
//         console.log(smartRead(args[2], { label: "args[2] (value)", showHex: false }));
//         console.log(smartRead(args[4], { label: "args[4]", showHex: true, tryStructFields: true }));

//         console.log("\nCaller:", DebugSymbol.fromAddress(this.returnAddress));
//         console.log("==========================================\n");
//       }
//     } catch(e) {
//       console.log("Error in 0x40216C hook:", e.message);
//     }
//   }
// });


// 全局变量保存捕获的参数
let capturedUrl = null;
let capturedHeaders = null;
let captureCount = 0;

// native_hook("libmetasec_ml.so", 0xC7E1C+1, {
// logEnter: false,
// logLeave: false,
// customEnter: function(args, context, retval, base_addr, hook_addr, tid){
//     try {
//         // var a3_deref = ptr(context.x0).readPointer();  // *a3 (第一层解引用)
//         // var target_addr = a3_deref.add(12);            // *a3 + 12
//         // var value = ptr(target_addr).readS32();        // *(*a3 + 12) - 这才是整数！
//         // console.log("*(*a3 + 12) =", value);

//             var ptr = context.x10-base_addr;
//             console.log(ptr.toString(16));
//         } catch(e) {
//         console.log("Hook 错误:", e.message);
//         }
//     }
// });

// 方式2: 使用 smartReadArgs - 批量分析
// native_hook("libmetasec_ml.so", 0x40216C, {
//   logEnter: false,
//   logLeave: false,
//   customEnter: function(args, context) {
//     try {
//       let key = args[1].readCString();
//       if (key === "x-tt-trace-id") {
//         console.log(smartReadArgs(args, {
//           1: { showHex: false },
//           2: { showHex: false },
//           4: { showHex: true, tryStructFields: true }
//         }));
//         console.log("Caller:", DebugSymbol.fromAddress(this.returnAddress));
//       }
//     } catch(e) {
//       console.log("Error:", e.message);
//     }
//   }
// });

// 方式3: 手动解析版（适合已知结构的情况）
// native_hook("libmetasec_ml.so", 0x40216C, {
//   logEnter: false,
//   logLeave: false,
//   customEnter: function(args, context) {
//     try {
//       let key = args[1].readCString();
//       if (key === "x-tt-trace-id") {
//         // args[2] 是 std::string 结构体（指针+长度）
//         let valuePtr = args[2].readPointer();
//         let valueLen = args[2].add(8).readU64();
//         let value = valuePtr.readUtf8String(Number(valueLen));
//
//         console.log("x-tt-trace-id:", value);
//         console.log("Caller:", DebugSymbol.fromAddress(this.returnAddress));
//       }
//     } catch(e) {
//       console.log("Error:", e.message);
//     }
//   }
// });

// 方式2: 使用 smartRead - 自动推断所有可能的读取方式
// native_hook("libmetasec_ml.so", 0x378F40, {
//   logEnter: false,
//   logLeave: false,
//   customEnter: function(args, context) {  
//     console.log("\n========== HTTP Header Hook ==========");
//     console.log(smartRead(args[1], { maxDepth: 2 }));

//     console.log("\nargs[2] (header value):");
//     console.log(smartRead(args[2], { maxDepth: 2 }));
//     console.log("\nCaller:", DebugSymbol.fromAddress(context.lr));
//     console.log("======================================\n");
//   }
// });

// 方式3: 使用 smartReadArgs - 批量智能读取
// native_hook("libmetasec_ml.so", 0x378F40, {
//   logEnter: false,
//   logLeave: false,
//   customEnter: function(args, context) {
//     console.log(smartReadArgs(args, {
//       0: {},  // a1: HttpRequestHeaders 对象
//       1: { maxDepth: 2 },  // a2: header name
//       2: { maxDepth: 2 }   // a3: header value
//     }));
//     console.log("Caller:", DebugSymbol.fromAddress(context.lr));
//   }
// });

// 主动调用 ttEncrypt
// monitorStrings("libunity.so")
// sktrace('libnativeLib.so')
// hookNativeSocket()
// hook_dlopen('libunity.so',hook_str)
// hook_str("openid")

// //java层函数示例
// trace('ms.bd.c.p2','b')
// call_ttEncrypt()

// trace('dalvik.system.DexFile','loadDex')
// trace('com.bytedance.bdinstall.Api','LJ')
// trace_change('com.example.TestClass')
// hook_abstract("com.anythink.rewardvideo.unitgroup.api.CustomRewardVideoAdapter")
// hook_file()
// hook_string()
// antiFrida()

// ============================================================
// 追踪 libmetasec_ml.so 数据流 - 从 sub_DC110 到 sub_1B1990
// ============================================================

let hookCounter = 0;
let dataFlowMap = new Map(); // 用于关联不同函数调用之间的数据
let capturedStrings = new Set(); // 捕获的 ID 相关字符串
let stringCompositionLog = []; // ID 字符串组成日志

// 辅助函数：读取结构体数据
function readDataStruct(ptr) {
    try {
        if (!ptr || ptr.isNull()) {
            return { valid: false };
        }

        let length = ptr.add(12).readS32();
        let dataPtr = ptr.add(16).readPointer();

        return {
            valid: true,
            length: length,
            dataPtr: dataPtr,
            data: (dataPtr && !dataPtr.isNull() && length > 0) ?
                  hexdumpAdvanced(dataPtr, Math.min(length, 64)) : "无数据"
        };
    } catch(e) {
        return { valid: false, error: e.message };
    }
}

// Auxiliary function: Try to read as string and capture device fingerprint fields
function tryReadAndCaptureString(ptr, maxLen) {
    try {
        if (!ptr || ptr.isNull()) return null;

        let str = ptr.readUtf8String(maxLen);
        if (str && str.length > 3) {
            // Filter device-related fields (SSID, BSSID, AndroidID, IMEI, etc)
            if (str.includes("ssid") || str.includes("SSID") ||
                str.includes("bssid") || str.includes("BSSID") ||
                str.includes("android_id") || str.includes("AndroidID") ||
                str.includes("imei") || str.includes("IMEI") ||
                str.includes("mac") || str.includes("MAC") ||
                str.includes("wifi") || str.includes("Wifi") ||
                str.includes("device") || str.includes("Device") ||
                str.includes("serial") || str.includes("Serial") ||
                str.includes("build") || str.includes("Build") ||
                str.includes("model") || str.includes("Model") ||
                str.includes("brand") || str.includes("Brand") ||
                str.includes("manufacturer") ||
                str.includes("WifiInfo") || str.includes("WifiManager") ||
                str.includes("TelephonyManager") ||
                str.length > 50) { // Long strings might be fingerprint data
                capturedStrings.add(str);
                console.log("[Fingerprint Field] " + str.substring(0, 100));
                return str;
            }
        }
        return str;
    } catch(e) {
        return null;
    }
}

// 辅助函数：深度分析指针
function deepAnalyzePointer(ptr, label, depth) {
    if (depth > 2 || !ptr || ptr.isNull()) return;

    try {
        console.log("  ".repeat(depth) + "[" + label + "] 地址: " + ptr);

        // 尝试作为字符串读取
        let str = tryReadAndCaptureString(ptr, 128);
        if (str && str.length > 0) {
            console.log("  ".repeat(depth) + "  ↳ 字符串: " + str.substring(0, 80));
        }

        // 尝试解引用
        try {
            let deref = ptr.readPointer();
            if (deref && !deref.isNull()) {
                deepAnalyzePointer(deref, "*" + label, depth + 1);
            }
        } catch(e) {}

    } catch(e) {}
}

// ============================================================
// Java Layer Hook: ms.bd.c.p2 - Entry from Java to Native
// ============================================================
Java.perform(function() {
    try {
        let clazz = Java.use("ms.bd.c.p2");

        // Hook method 'a' - 使用正确的参数类型
        try {
            clazz.a.overload('int', 'int', 'long', 'java.lang.String', 'java.lang.Object').implementation = function(a, b, c, d, e) {
                console.log("\n========================================");
                console.log("[Java] ms.bd.c.p2.a CALLED");
                console.log("========================================");
                console.log("Param[0] int:", a);
                console.log("Param[1] int:", b);
                console.log("Param[2] long:", c);
                console.log("Param[3] String:", d);
                console.log("Param[4] Object:", e);
                console.log("Param[4] Type:", e ? e.$className : "null");

                // If byte array, show content
                if (e && e.$className === '[B') {
                    let byteArray = Java.cast(e, Java.use('[B'));
                    console.log("byte array length:", byteArray.length);
                    if (byteArray.length > 0) {
                        let bytes = [];
                        for (let i = 0; i < Math.min(byteArray.length, 64); i++) {
                            bytes.push(byteArray[i]);
                        }
                        console.log("First 64 bytes:", bytes);
                    }
                }

                let result = this.a(a, b, c, d, e);

                console.log("Return value:", result);
                console.log("========================================\n");
                return result;
            };
            console.log("[+] 成功hook ms.bd.c.p2.a");
        } catch(e) {
            console.log("[-] 无法hook ms.bd.c.p2.a:", e.message);
        }

        // Hook method 'b' - 这个才是真正被调用的!
        try {
            clazz.b.overload('int', 'int', 'long', 'java.lang.String', 'java.lang.Object').implementation = function(a, b, c, d, e) {
                console.log("\n========================================");
                console.log("[Java] ★★★ ms.bd.c.p2.b CALLED ★★★");
                console.log("========================================");
                console.log("Param[0] int:", a);
                console.log("Param[1] int:", b);
                console.log("Param[2] long:", c);
                console.log("Param[3] String:", d);
                console.log("Param[4] Object:", e);
                console.log("Param[4] Type:", e ? e.$className : "null");

                // If byte array, show content
                if (e && e.$className === '[B') {
                    let byteArray = Java.cast(e, Java.use('[B'));
                    console.log("byte array length:", byteArray.length);
                    if (byteArray.length > 0) {
                        let bytes = [];
                        for (let i = 0; i < Math.min(byteArray.length, 64); i++) {
                            bytes.push(byteArray[i]);
                        }
                        console.log("First 64 bytes:", bytes);
                    }
                }

                let result = this.b(a, b, c, d, e);

                console.log("Return value:", result);
                console.log("Return value type:", result ? result.$className : "null");
                console.log("========================================\n");
                return result;
            };
            console.log("[+] ★ Successfully hooked ms.bd.c.p2.b (Real entry point!)");
        } catch(e) {
            console.log("[-] 无法hook ms.bd.c.p2.b:", e.message);
        }

    } catch(e) {
        console.log("[-] 无法加载 ms.bd.c.p2:", e.message);
    }
});

// ============================================================
// Hook JNI NewByteArray and SetByteArrayRegion
// These are where sub_1B1990 converts native device fingerprint to Java byte[]
// ============================================================

// Hook JNI NewByteArray to catch when native creates Java byte arrays
Interceptor.attach(Module.findExportByName("libart.so", "_ZN3art3JNI12NewByteArrayEP7_JNIEnvi"), {
    onEnter: function(args) {
        let jniEnv = args[0];
        let length = args[1].toInt32();

        // Log byte arrays larger than 50 bytes
        if (length > 50) {
            this.length = length;
            this.hookId = ++hookCounter;
            console.log("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            console.log("!!! [" + this.hookId + "] JNI NewByteArray CALLED !!!");
            console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            console.log("Length:", length, "bytes");
            console.log("Caller:", DebugSymbol.fromAddress(this.returnAddress));

            if (length > 1000) {
                console.log("★★★ LARGE DATA - Likely device fingerprint! ★★★");
                try {
                    stacktrace_so();
                } catch(e) {
                    console.log("Stack trace failed:", e.message);
                }
            }
        }
    },
    onLeave: function(retval) {
        if (this.length) {
            console.log("NewByteArray returned jbyteArray:", retval);
            console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        }
    }
});

// Hook JNI SetByteArrayRegion to see the actual data being copied
Interceptor.attach(Module.findExportByName("libart.so", "_ZN3art3JNI19SetByteArrayRegionEP7_JNIEnvP11_jbyteArrayiiPKa"), {
    onEnter: function(args) {
        let jniEnv = args[0];
        let jarray = args[1];
        let start = args[2].toInt32();
        let len = args[3].toInt32();
        let buf = args[4];

        // Only log large data (likely device fingerprint)
        if (len > 1000) {
            let id = ++hookCounter;
            console.log("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            console.log("!!! [" + id + "] JNI SetByteArrayRegion - Device Fingerprint Data !!!");
            console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            console.log("Array:", jarray);
            console.log("Start:", start);
            console.log("Length:", len, "bytes");
            console.log("Buffer:", buf);
            console.log("\n[DEVICE FINGERPRINT DATA - First 512 bytes]:");
            console.log(hexdumpAdvanced(buf, Math.min(len, 512)));

            // Try to find device info fields
            try {
                let dataStr = buf.readCString(Math.min(len, 2000));
                if (dataStr) {
                    console.log("\n[STRING VIEW - First 1000 chars]:");
                    console.log(dataStr.substring(0, 1000));
                }
            } catch(e) {}

            console.log("\nCaller:", DebugSymbol.fromAddress(this.returnAddress));
            try {
                stacktrace_so();
            } catch(e) {}
            console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        }
    }
});

console.log("[+] JNI byte array hooks installed");

// ============================================================
// Direct hook sub_1B1990
// ============================================================
setTimeout(function() {
    try {
        let base = Module.findBaseAddress("libmetasec_ml.so");
        if (base) {
            let sub_1B1990 = base.add(0x1B1990);

            Interceptor.attach(sub_1B1990, {
                onEnter: function(args) {
                    let id = ++hookCounter;
                    console.log("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                    console.log("!!! [" + id + "] sub_1B1990 CALLED !!!");
                    console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                    console.log("a1 (JNIEnv*):", args[0]);
                    console.log("a2 (data ptr):", args[1]);

                    try {
                        let len = args[2].toInt32();
                        console.log("a3 (length):", len);

                        if (args[1] && !args[1].isNull() && len > 0) {
                            console.log("\nData hexdump:");
                            console.log(hexdumpAdvanced(args[1], Math.min(len, 512)));
                        }
                    } catch(e) {
                        console.log("Failed to read:", e.message);
                    }

                    console.log("\nCaller:", DebugSymbol.fromAddress(this.returnAddress));
                    try {
                        stacktrace_so();
                    } catch(e) {}
                    console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                },
                onLeave: function(retval) {
                    console.log("sub_1B1990 returned:", retval);
                }
            });

            console.log("[+] Hooked sub_1B1990 at", sub_1B1990);
        }
    } catch(e) {
        console.log("[-] Failed to hook sub_1B1990:", e.message);
    }
}, 100);

console.log("[+] All hooks installed - tracking device fingerprint");

// 启用 VPN 检测绕过
console.log("[*] 启用 VPN 检测绕过...");
bypassVpnDetection();

// 启用 SSL Pinning 绕过
console.log("[*] 启用 SSL Pinning 绕过...");
bypassSslPinning();

setTimeout(() => {
    trace('com.commonlib.util.net.DHCC_NewSimpleHttpCallback','n');
    
    // 返利快报
    // trace('com.commonlib.util.net.aflkbNewSimpleHttpCallback');

    // 手淘优惠券
    // trace('com.commonlib.util.net.astyhqNewSimpleHttpCallback','n');
}
, 2000);

console.log("[*] 所有绕过模块已加载完成");