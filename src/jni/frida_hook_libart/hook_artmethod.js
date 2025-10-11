
// ============ 配置区域 ============
// 设置要监控的 SO 文件，可以配置多个
// 留空数组 [] 表示监控所有 SO
// 例如: ["libEncryptor.so"] 或 ["libEncryptor.so", "libsgmainso.so"]
var TARGET_SO_LIST = ["libEncryptor.so"];

// 是否启用 Java 类过滤（过滤掉 java.* 和 android.* 开头的类）
var FILTER_SYSTEM_CLASSES = true;
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

const STD_STRING_SIZE = 3 * Process.pointerSize;
class StdString {
    constructor() {
        this.handle = Memory.alloc(STD_STRING_SIZE);
    }

    dispose() {
        const [data, isTiny] = this._getData();
        if (!isTiny) {
            Java.api.$delete(data);
        }
    }

    disposeToString() {
        const result = this.toString();
        this.dispose();
        return result;
    }

    toString() {
        const [data] = this._getData();
        return data.readUtf8String();
    }

    _getData() {
        const str = this.handle;
        const isTiny = (str.readU8() & 1) === 0;
        const data = isTiny ? str.add(1) : str.add(2 * Process.pointerSize).readPointer();
        return [data, isTiny];
    }
}

function prettyMethod(method_id, withSignature) {
    const result = new StdString();
    Java.api['art::ArtMethod::PrettyMethod'](result, method_id, withSignature ? 1 : 0);
    return result.disposeToString();
}

function hook_dlopen(module_name, fun) {
    var android_dlopen_ext = Module.findGlobalExportByName("android_dlopen_ext");

    if (android_dlopen_ext) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr) {
                    this.path = pathptr.readCString();
                    if (this.path.indexOf(module_name) >= 0) {
                        this.canhook = true;
                        console.log("android_dlopen_ext:", this.path);
                    }
                }
            },
            onLeave: function (retval) {
                if (this.canhook) {
                    fun();
                }
            }
        });
    }
    var dlopen = Module.findGlobalExportByName("dlopen");
    if (dlopen) {
        Interceptor.attach(dlopen, {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr) {
                    this.path = pathptr.readCString();
                    if (this.path.indexOf(module_name) >= 0) {
                        this.canhook = true;
                        console.log("dlopen:", this.path);
                    }
                }
            },
            onLeave: function (retval) {
                if (this.canhook) {
                    fun();
                }
            }
        });
    }
    console.log("android_dlopen_ext:", android_dlopen_ext, "dlopen:", dlopen);
}


function hook_native() {
    console.log("[*] Target SO List:", TARGET_SO_LIST.length === 0 ? "ALL" : TARGET_SO_LIST.join(", "));

    var module_libart = Process.findModuleByName("libart.so");
    var symbols = module_libart.enumerateSymbols();
    var ArtMethod_Invoke = null;
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        var address = symbol.address;
        var name = symbol.name;
        var indexArtMethod = name.indexOf("ArtMethod");
        var indexInvoke = name.indexOf("Invoke");
        var indexThread = name.indexOf("Thread");
        if (indexArtMethod >= 0
            && indexInvoke >= 0
            && indexThread >= 0
            && indexArtMethod < indexInvoke
            && indexInvoke < indexThread) {
            console.log(name);
            ArtMethod_Invoke = address;
        }
    }
    if (ArtMethod_Invoke) {
        Interceptor.attach(ArtMethod_Invoke, {
            onEnter: function (args) {
                var method_name = prettyMethod(args[0], 0);
                if (!FILTER_SYSTEM_CLASSES || !(method_name.indexOf("java.") == 0 || method_name.indexOf("android.") == 0)) {
                    var stackTraceMsg = Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n');

                    // 检查调用栈是否包含目标 SO
                    if (TARGET_SO_LIST.length === 0) {
                        // 监控所有
                        console.log("ArtMethod Invoke:" + method_name + '  called from:\n' + stackTraceMsg + '\n');
                    } else {
                        // 检查调用栈中是否包含目标 SO
                        var shouldLog = false;
                        for (var i = 0; i < TARGET_SO_LIST.length; i++) {
                            if (stackTraceMsg.indexOf(TARGET_SO_LIST[i]) >= 0) {
                                shouldLog = true;
                                break;
                            }
                        }
                        if (shouldLog) {
                            console.log("ArtMethod Invoke:" + method_name + '  called from:\n' + stackTraceMsg + '\n');
                        }
                    }
                }
            }
        });
    }
}

function main() {
    hook_dlopen("libart.so", hook_native);
    hook_native();
}

setImmediate(main);