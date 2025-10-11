// ============ 配置区域 ============
// 设置要监控的 SO 文件，可以配置多个
// 留空数组 [] 表示监控所有 SO
// 例如: ["libEncryptor.so"] 或 ["libEncryptor.so", "libsgmainso.so"]
var TARGET_SO_LIST = ["libEncryptor.so"];
// ===================================

function shouldMonitorModule(module) {
    if (!module) return false;
    if (TARGET_SO_LIST.length === 0) return true; // 空数组表示监控所有

    for (var i = 0; i < TARGET_SO_LIST.length; i++) {
        if (module.name.indexOf(TARGET_SO_LIST[i]) >= 0) {
            return true;
        }
    }
    return false;
}

function find_RegisterNatives(params) {
    console.log("[*] Target SO List:", TARGET_SO_LIST.length === 0 ? "ALL" : TARGET_SO_LIST.join(", "));
    let module_libart = Process.getModuleByName("libart.so");
    let symbols = module_libart.enumerateSymbols();
    let addrRegisterNatives = null;
    for (let i = 0; i < symbols.length; i++) {
        let symbol = symbols[i];
        
        //_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
        if (symbol.name.indexOf("art") >= 0 &&
                symbol.name.indexOf("JNI") >= 0 && 
                symbol.name.indexOf("RegisterNatives") >= 0 && 
                symbol.name.indexOf("CheckJNI") < 0) {
            addrRegisterNatives = symbol.address;
            console.log("RegisterNatives is at ", symbol.address, symbol.name);
            hook_RegisterNatives(addrRegisterNatives)
        }
    }

}

function hook_RegisterNatives(addrRegisterNatives) {

    if (addrRegisterNatives != null) {
        Interceptor.attach(addrRegisterNatives, {
            onEnter: function (args) {
                let java_class = args[1];
                let class_name = Java.vm.tryGetEnv().getClassName(java_class);
                let methods_ptr = ptr(args[2]);
                let method_count = parseInt(args[3]);

                // 先检查是否有我们关心的模块
                let shouldLog = false;
                for (let i = 0; i < method_count; i++) {
                    let fnPtr_ptr = methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();
                    let find_module = Process.findModuleByAddress(fnPtr_ptr);
                    if (shouldMonitorModule(find_module)) {
                        shouldLog = true;
                        break;
                    }
                }

                if (!shouldLog) return;

                console.log("[RegisterNatives] method_count:", args[3]);

                for (let i = 0; i < method_count; i++) {
                    let name_ptr = methods_ptr.add(i * Process.pointerSize * 3).readPointer();
                    let sig_ptr = methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize).readPointer();
                    let fnPtr_ptr = methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();

                    let name = name_ptr.readCString();
                    let sig = sig_ptr.readCString();
                    let symbol = DebugSymbol.fromAddress(fnPtr_ptr);
                    var find_module = Process.findModuleByAddress(fnPtr_ptr);

                    if (shouldMonitorModule(find_module)) {
                        console.log("[RegisterNatives] java_class:", class_name, "name:", name, "sig:", sig, "fnPtr:", fnPtr_ptr,  " fnOffset:", ptr(fnPtr_ptr).sub(find_module.base), " callee:", DebugSymbol.fromAddress(this.returnAddress)," base:",find_module.base);
                    }
                }
            }
        });
    }
}

setImmediate(find_RegisterNatives);
