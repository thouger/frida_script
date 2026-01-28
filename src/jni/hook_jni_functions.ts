/**
 * Hook JNI函数的通用工具
 * 支持 FindClass, GetMethodID, GetFieldID 等JNI函数
 */

// ============ 配置区域 ============
// 设置要监控的 SO 文件，可以配置多个
// 留空数组 [] 表示监控所有 SO
// 例如: ["libmetasec_ml.so"] 或 ["libmetasec_ml.so", "libsgmainso.so"]
let TARGET_SO_LIST: string[] = [];
// ===================================

/**
 * 判断是否应该监控指定模块
 */
function shouldMonitorModule(module: Module | null): boolean {
    if (!module) return false;
    if (TARGET_SO_LIST.length === 0) return true; // 空数组表示监控所有

    for (let soName of TARGET_SO_LIST) {
        if (module.name.indexOf(soName) >= 0) {
            return true;
        }
    }
    return false;
}

/**
 * Hook JNI FindClass 函数
 * @param targetSoList 目标SO文件列表，为空则监控所有
 */
export function hookFindClass(targetSoList: string[] = []): void {
    TARGET_SO_LIST = targetSoList;
    console.log("[*] Target SO List for FindClass:", TARGET_SO_LIST.length === 0 ? "ALL" : TARGET_SO_LIST.join(", "));

    Java.perform(function() {
        try {
            const env = Java.vm.getEnv();
            const FindClassPtr = env.handle.readPointer().add(Process.pointerSize * 6); // FindClass在JNIEnv表中的偏移
            const FindClass = Memory.readPointer(FindClassPtr);

            console.log("[*] FindClass address:", FindClass);

            Interceptor.attach(FindClass, {
                onEnter: function(args) {
                    const caller = this.returnAddress;
                    const module = Process.findModuleByAddress(caller);

                    // 只记录符合条件的SO调用
                    if (shouldMonitorModule(module)) {
                        const className = Memory.readCString(args[1]);
                        console.log("[FindClass] className:", className);
                        if (module) {
                            console.log("           called from:", module.name, "offset:", caller.sub(module.base));
                        }
                    }
                },
                onLeave: function(retval) {
                    // 可以在这里打印返回值
                }
            });

            console.log("[*] FindClass hooked successfully!");
        } catch (e) {
            console.error("[!] Failed to hook FindClass:", e);
        }
    });
}

/**
 * Hook JNI GetMethodID 函数
 * @param targetSoList 目标SO文件列表，为空则监控所有
 */
export function hookGetMethodID(targetSoList: string[] = []): void {
    TARGET_SO_LIST = targetSoList;
    console.log("[*] Target SO List for GetMethodID:", TARGET_SO_LIST.length === 0 ? "ALL" : TARGET_SO_LIST.join(", "));

    Java.perform(function() {
        try {
            const env = Java.vm.getEnv();
            const GetMethodIDPtr = env.handle.readPointer().add(Process.pointerSize * 33); // GetMethodID在JNIEnv表中的偏移
            const GetMethodID = Memory.readPointer(GetMethodIDPtr);

            console.log("[*] GetMethodID address:", GetMethodID);

            Interceptor.attach(GetMethodID, {
                onEnter: function(args) {
                    const caller = this.returnAddress;
                    const module = Process.findModuleByAddress(caller);

                    if (shouldMonitorModule(module)) {
                        const methodName = Memory.readCString(args[2]);
                        const methodSig = Memory.readCString(args[3]);
                        console.log("[GetMethodID] method:", methodName, "sig:", methodSig);
                        if (module) {
                            console.log("              called from:", module.name, "offset:", caller.sub(module.base));
                        }
                    }
                }
            });

            console.log("[*] GetMethodID hooked successfully!");
        } catch (e) {
            console.error("[!] Failed to hook GetMethodID:", e);
        }
    });
}

/**
 * Hook JNI GetFieldID 函数
 * @param targetSoList 目标SO文件列表，为空则监控所有
 */
export function hookGetFieldID(targetSoList: string[] = []): void {
    TARGET_SO_LIST = targetSoList;
    console.log("[*] Target SO List for GetFieldID:", TARGET_SO_LIST.length === 0 ? "ALL" : TARGET_SO_LIST.join(", "));

    Java.perform(function() {
        try {
            const env = Java.vm.getEnv();
            const GetFieldIDPtr = env.handle.readPointer().add(Process.pointerSize * 94); // GetFieldID在JNIEnv表中的偏移
            const GetFieldID = Memory.readPointer(GetFieldIDPtr);

            console.log("[*] GetFieldID address:", GetFieldID);

            Interceptor.attach(GetFieldID, {
                onEnter: function(args) {
                    const caller = this.returnAddress;
                    const module = Process.findModuleByAddress(caller);

                    if (shouldMonitorModule(module)) {
                        const fieldName = Memory.readCString(args[2]);
                        const fieldSig = Memory.readCString(args[3]);
                        console.log("[GetFieldID] field:", fieldName, "sig:", fieldSig);
                        if (module) {
                            console.log("             called from:", module.name, "offset:", caller.sub(module.base));
                        }
                    }
                }
            });

            console.log("[*] GetFieldID hooked successfully!");
        } catch (e) {
            console.error("[!] Failed to hook GetFieldID:", e);
        }
    });
}

/**
 * 通用Hook JNI函数入口
 * @param funcName JNI函数名（不区分大小写），支持: findclass, getmethodid, getfieldid
 * @param targetSoList 目标SO文件列表，为空则监控所有
 */
export function hookJniFunction(funcName: string, targetSoList: string[] = []): void {
    const lowerFuncName = funcName.toLowerCase();

    switch (lowerFuncName) {
        case "findclass":
            hookFindClass(targetSoList);
            break;
        case "getmethodid":
            hookGetMethodID(targetSoList);
            break;
        case "getfieldid":
            hookGetFieldID(targetSoList);
            break;
        default:
            console.error("[!] Unsupported JNI function:", funcName);
            console.log("[*] Supported functions: findclass, getmethodid, getfieldid");
            break;
    }
}

/**
 * 打印 JNINativeMethod 结构
 * 在调用 RegisterNatives 之前 hook，读取 JNINativeMethod 数组
 * @param soName SO 文件名
 * @param offset 调用 RegisterNatives 前的偏移地址（此时 X2 寄存器指向 JNINativeMethod 数组）
 */
export function printJNINativeMethod(soName: string, offset: number): void {
    const baseAddr = Module.findBaseAddress(soName);
    if (!baseAddr) {
        console.log(`[!] 找不到 ${soName}`);
        return;
    }

    const hookAddr = baseAddr.add(offset);
    console.log(`[✓] Hook 地址: ${hookAddr} (${soName}+0x${offset.toString(16)})`);

    Interceptor.attach(hookAddr, {
        onEnter: function(args) {
            try {
                // ARM64: X2 = JNINativeMethod 数组指针
                const methodsPtr = (this.context as Arm64CpuContext).x2;

                console.log("\n========== JNINativeMethod 结构 ==========");
                console.log("数组地址:", methodsPtr);

                // JNINativeMethod 结构:
                // struct {
                //     const char* name;      // +0x00
                //     const char* signature; // +0x08
                //     void*       fnPtr;     // +0x10
                // }

                const namePtr = ptr(methodsPtr).readPointer();
                const sigPtr = ptr(methodsPtr).add(8).readPointer();
                const fnPtr = ptr(methodsPtr).add(16).readPointer();

                const methodName = namePtr.readCString();
                const methodSig = sigPtr.readCString();

                console.log("方法名:", methodName);
                console.log("签名:", methodSig);
                console.log("函数指针:", fnPtr, DebugSymbol.fromAddress(fnPtr));
                console.log("==========================================\n");
            } catch(e) {
                console.log("读取失败:", (e as Error).message);
            }
        }
    });
}
