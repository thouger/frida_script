
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

/*
GetFieldID is at  0xe39b87c5 _ZN3art3JNI10GetFieldIDEP7_JNIEnvP7_jclassPKcS6_
GetMethodID is at  0xe39a1a19 _ZN3art3JNI11GetMethodIDEP7_JNIEnvP7_jclassPKcS6_
NewStringUTF is at  0xe39cff25 _ZN3art3JNI12NewStringUTFEP7_JNIEnvPKc
RegisterNatives is at  0xe39e08fd _ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
GetStaticFieldID is at  0xe39c9635 _ZN3art3JNI16GetStaticFieldIDEP7_JNIEnvP7_jclassPKcS6_
GetStaticMethodID is at  0xe39be0ed _ZN3art3JNI17GetStaticMethodIDEP7_JNIEnvP7_jclassPKcS6_
GetStringUTFChars is at  0xe39d06e5 _ZN3art3JNI17GetStringUTFCharsEP7_JNIEnvP8_jstringPh
FindClass is at  0xe399ae5d _ZN3art3JNI9FindClassEP7_JNIEnvPKc
*/

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

function hook_libart() {
    var module_libart = Process.getModuleByName("libart.so");
    var symbols = module_libart.enumerateSymbols();
    var addrGetStringUTFChars = null;
    var addrNewStringUTF = null;
    var addrFindClass = null;
    var addrGetMethodID = null;
    var addrGetStaticMethodID = null;
    var addrGetFieldID = null;
    var addrGetStaticFieldID = null;
    var addrRegisterNatives = null;

    console.log("[*] Target SO List:", TARGET_SO_LIST.length === 0 ? "ALL" : TARGET_SO_LIST.join(", "));

    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        if (symbol.name.indexOf("art") >= 0 &&
            symbol.name.indexOf("JNI") >= 0 &&
            symbol.name.indexOf("CheckJNI") < 0 &&
            symbol.name.indexOf("_ZN3art3JNIILb0") >= 0
        ) {
            if (symbol.name.indexOf("GetStringUTFChars") >= 0) {
                addrGetStringUTFChars = symbol.address;
                console.log("GetStringUTFChars is at ", symbol.address, symbol.name);
            } else if (symbol.name.indexOf("NewStringUTF") >= 0) {
                addrNewStringUTF = symbol.address;
                console.log("NewStringUTF is at ", symbol.address, symbol.name);
            } else if (symbol.name.indexOf("FindClass") >= 0) {
                addrFindClass = symbol.address;
                console.log("FindClass is at ", symbol.address, symbol.name);
            } else if (symbol.name.indexOf("GetMethodID") >= 0) {
                addrGetMethodID = symbol.address;
                console.log("GetMethodID is at ", symbol.address, symbol.name);
            } else if (symbol.name.indexOf("GetStaticMethodID") >= 0) {
                addrGetStaticMethodID = symbol.address;
                console.log("GetStaticMethodID is at ", symbol.address, symbol.name);
            } else if (symbol.name.indexOf("GetFieldID") >= 0) {
                addrGetFieldID = symbol.address;
                console.log("GetFieldID is at ", symbol.address, symbol.name);
            } else if (symbol.name.indexOf("GetStaticFieldID") >= 0) {
                addrGetStaticFieldID = symbol.address;
                console.log("GetStaticFieldID is at ", symbol.address, symbol.name);
            } else if (symbol.name.indexOf("RegisterNatives") >= 0) {
                addrRegisterNatives = symbol.address;
                console.log("RegisterNatives is at ", symbol.address, symbol.name);
            } else if (symbol.name.indexOf("CallStatic") >= 0) {
                console.log("CallStatic is at ", symbol.address, symbol.name);
                Interceptor.attach(symbol.address, {
                    onEnter: function (args) {
                        var module = Process.findModuleByAddress(this.returnAddress);
                        if (shouldMonitorModule(module)) {
                            var java_class = args[1];
                            var mid = args[2];
                            var class_name = Java.vm.tryGetEnv().getClassName(java_class);
                            if (!FILTER_SYSTEM_CLASSES || (class_name.indexOf("java.") == -1 && class_name.indexOf("android.") == -1)) {
                                var method_name = prettyMethod(mid, 1);
                                console.log("<>CallStatic:", DebugSymbol.fromAddress(this.returnAddress), class_name, method_name);
                            }
                        }
                    },
                    onLeave: function (retval) { }
                });
            } else if (symbol.name.indexOf("CallNonvirtual") >= 0) {
                console.log("CallNonvirtual is at ", symbol.address, symbol.name);
                Interceptor.attach(symbol.address, {
                    onEnter: function (args) {
                        var module = Process.findModuleByAddress(this.returnAddress);
                        if (shouldMonitorModule(module)) {
                            var jobject = args[1];
                            var jclass = args[2];
                            var jmethodID = args[3];
                            var obj_class_name = Java.vm.tryGetEnv().getObjectClassName(jobject);
                            var class_name = Java.vm.tryGetEnv().getClassName(jclass);
                            if (!FILTER_SYSTEM_CLASSES || (class_name.indexOf("java.") == -1 && class_name.indexOf("android.") == -1)) {
                                var method_name = prettyMethod(jmethodID, 1);
                                console.log("<>CallNonvirtual:", DebugSymbol.fromAddress(this.returnAddress), class_name, obj_class_name, method_name);
                            }
                        }
                    },
                    onLeave: function (retval) { }
                });
            } else if (symbol.name.indexOf("Call") >= 0 && symbol.name.indexOf("Method") >= 0) {
                console.log("Call<>Method is at ", symbol.address, symbol.name);
                Interceptor.attach(symbol.address, {
                    onEnter: function (args) {
                        var module = Process.findModuleByAddress(this.returnAddress);
                        if (shouldMonitorModule(module)) {
                            var java_class = args[1];
                            var mid = args[2];
                            var class_name = Java.vm.tryGetEnv().getObjectClassName(java_class);
                            if (!FILTER_SYSTEM_CLASSES || (class_name.indexOf("java.") == -1 && class_name.indexOf("android.") == -1)) {
                                var method_name = prettyMethod(mid, 1);
                                console.log("<>Call<>Method:", DebugSymbol.fromAddress(this.returnAddress), class_name, method_name);
                            }
                        }
                    },
                    onLeave: function (retval) { }
                });
            }
        }
    }

    if (addrGetStringUTFChars != null) {
        Interceptor.attach(addrGetStringUTFChars, {
            onEnter: function (args) {
            },
            onLeave: function (retval) {
                if (retval != null) {
                    var module = Process.findModuleByAddress(this.returnAddress);
                    if (shouldMonitorModule(module)) {
                        var bytes = retval.readCString();
                        console.log("[GetStringUTFChars] result:" + bytes, DebugSymbol.fromAddress(this.returnAddress));
                    }
                }
            }
        });
    }
    if (addrNewStringUTF != null) {
        Interceptor.attach(addrNewStringUTF, {
            onEnter: function (args) {
                if (args[1] != null) {
                    var module = Process.findModuleByAddress(this.returnAddress);
                    if (shouldMonitorModule(module)) {
                        var string = args[1].readCString();
                        console.log("[NewStringUTF] bytes:" + string, DebugSymbol.fromAddress(this.returnAddress));
                    }

                }
            },
            onLeave: function (retval) { }
        });
    }

    if (addrFindClass != null) {
        Interceptor.attach(addrFindClass, {
            onEnter: function (args) {
                if (args[1] != null) {
                    var module = Process.findModuleByAddress(this.returnAddress);
                    if (shouldMonitorModule(module)) {
                        var name = args[1].readCString();
                        console.log("[FindClass] name:" + name, DebugSymbol.fromAddress(this.returnAddress));
                    }
                }
            },
            onLeave: function (retval) { }
        });
    }
    if (addrGetMethodID != null) {
        Interceptor.attach(addrGetMethodID, {
            onEnter: function (args) {
                if (args[2] != null) {
                    var clazz = args[1];
                    var class_name = Java.vm.tryGetEnv().getClassName(clazz);
                    var module = Process.findModuleByAddress(this.returnAddress);
                    if (shouldMonitorModule(module)) {
                        var name = args[2].readCString();
                        if (args[3] != null) {
                            var sig = args[3].readCString();
                            console.log("[GetMethodID] class_name:" + class_name + " name:" + name + ", sig:" + sig, DebugSymbol.fromAddress(this.returnAddress));
                        } else {
                            console.log("[GetMethodID] class_name:" + class_name + " name:" + name, DebugSymbol.fromAddress(this.returnAddress));
                        }
                    }
                }
            },
            onLeave: function (retval) { }
        });
    }
    if (addrGetStaticMethodID != null) {
        Interceptor.attach(addrGetStaticMethodID, {
            onEnter: function (args) {
                if (args[2] != null) {
                    var clazz = args[1];
                    var class_name = Java.vm.tryGetEnv().getClassName(clazz);
                    var module = Process.findModuleByAddress(this.returnAddress);
                    if (shouldMonitorModule(module)) {
                        var name = args[2].readCString();
                        if (args[3] != null) {
                            var sig = args[3].readCString();
                            console.log("[GetStaticMethodID] class_name:" + class_name + " name:" + name + ", sig:" + sig, DebugSymbol.fromAddress(this.returnAddress));
                        } else {
                            console.log("[GetStaticMethodID] class_name:" + class_name + " name:" + name, DebugSymbol.fromAddress(this.returnAddress));
                        }
                    }
                }
            },
            onLeave: function (retval) { }
        });
    }
    if (addrGetFieldID != null) {
        Interceptor.attach(addrGetFieldID, {
            onEnter: function (args) {
                if (args[2] != null) {
                    var module = Process.findModuleByAddress(this.returnAddress);
                    if (shouldMonitorModule(module)) {
                        var name = args[2].readCString();
                        if (args[3] != null) {
                            var sig = args[3].readCString();
                            console.log("[GetFieldID] name:" + name + ", sig:" + sig, DebugSymbol.fromAddress(this.returnAddress));
                        } else {
                            console.log("[GetFieldID] name:" + name, DebugSymbol.fromAddress(this.returnAddress));
                        }
                    }
                }
            },
            onLeave: function (retval) { }
        });
    }
    if (addrGetStaticFieldID != null) {
        Interceptor.attach(addrGetStaticFieldID, {
            onEnter: function (args) {
                if (args[2] != null) {
                    var module = Process.findModuleByAddress(this.returnAddress);
                    if (shouldMonitorModule(module)) {
                        var name = args[2].readCString();
                        if (args[3] != null) {
                            var sig = args[3].readCString();
                            console.log("[GetStaticFieldID] name:" + name + ", sig:" + sig, DebugSymbol.fromAddress(this.returnAddress));
                        } else {
                            console.log("[GetStaticFieldID] name:" + name, DebugSymbol.fromAddress(this.returnAddress));
                        }
                    }
                }
            },
            onLeave: function (retval) { }
        });
    }

    if (addrRegisterNatives != null) {
        Interceptor.attach(addrRegisterNatives, {
            onEnter: function (args) {
                var java_class = args[1];
                var class_name = Java.vm.tryGetEnv().getClassName(java_class);
                var methods_ptr = ptr(args[2]);
                var method_count = parseInt(args[3]);

                // 先检查是否有我们关心的模块
                var shouldLog = false;
                for (var i = 0; i < method_count; i++) {
                    var fnPtr_ptr = methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();
                    var find_module = Process.findModuleByAddress(fnPtr_ptr);
                    if (shouldMonitorModule(find_module)) {
                        shouldLog = true;
                        break;
                    }
                }

                if (!shouldLog) return;

                console.log("[RegisterNatives] method_count:", args[3], DebugSymbol.fromAddress(this.returnAddress));

                for (var i = 0; i < method_count; i++) {
                    var name_ptr = methods_ptr.add(i * Process.pointerSize * 3).readPointer();
                    var sig_ptr = methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize).readPointer();
                    var fnPtr_ptr = methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();

                    var name = name_ptr.readCString();
                    var sig = sig_ptr.readCString();
                    var find_module = Process.findModuleByAddress(fnPtr_ptr);

                    if (shouldMonitorModule(find_module)) {
                        console.log("[RegisterNatives] java_class:", class_name, "name:", name, "sig:", sig, "fnPtr:", fnPtr_ptr, "module_name:", find_module.name, "module_base:", find_module.base, "offset:", ptr(fnPtr_ptr).sub(find_module.base));
                    }
                }
            },
            onLeave: function (retval) { }
        });
    }
}

setImmediate(hook_libart);
