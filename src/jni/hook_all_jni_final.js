// ============ 配置区域 ============
var TARGET_SO_LIST = [];
var FILTER_SYSTEM_CLASSES = false;  // 改为 false，不过滤任何类

// 配置要 hook 的 JNI 函数
var HOOK_CONFIG = {
    // 类查找和定义
    FindClass: true,              // hook FindClass，能看到查找的类
    DefineClass: true,            // 从原始类数据定义类
    GetObjectClass: true,         // 从对象获取类（常用）
    GetSuperclass: true,          // 获取父类
    IsAssignableFrom: true,       // 检查类型兼容性
    IsInstanceOf: true,           // 检查对象是否是某类实例

    // 方法相关
    GetMethodID: true,             // hook GetMethodID，能看到获取的方法
    GetStaticMethodID: true,       // hook GetStaticMethodID
    FromReflectedMethod: true,     // 从Java Method对象获取方法ID
    ToReflectedMethod: true,       // 将方法ID转为Java Method对象

    // 字段相关
    GetFieldID: true,              // hook GetFieldID，也可能访问类
    GetStaticFieldID: true,        // hook GetStaticFieldID
    FromReflectedField: true,      // 从Java Field对象获取字段ID
    ToReflectedField: true,        // 将字段ID转为Java Field对象

    // 对象创建（涉及类访问）
    AllocObject: true,             // 分配对象但不调用构造函数
    NewObject: true,               // 创建对象（会访问类）
    NewObjectArray: true,          // 创建对象数组

    // Native注册和字符串
    RegisterNatives: false,
    NewStringUTF: false,
    GetStringUTFChars: false
};

// 是否显示所有调用（包括不在目标 SO 列表中的）
var SHOW_ALL_CALLS = false;
// ===================================

var hookCount = 0;  // 统计 hook 触发次数

function shouldMonitorModule(module) {
    if (!module) return false;
    if (TARGET_SO_LIST.length === 0) return true;  // 空数组 = 监控所有

    for (var i = 0; i < TARGET_SO_LIST.length; i++) {
        if (module.name.indexOf(TARGET_SO_LIST[i]) >= 0) {
            return true;
        }
    }
    return false;
}

function getCallerInfo(returnAddress) {
    var module = Process.findModuleByAddress(returnAddress);
    if (module) {
        var offset = returnAddress.sub(module.base);
        return "[" + module.name + "+" + offset + "]";
    }
    return "[unknown+" + returnAddress + "]";
}

function hookAllJNI() {
    console.log("[*] ========================================");
    console.log("[*] Starting Universal JNI Hook");
    console.log("[*] Target SO:", TARGET_SO_LIST.length === 0 ? "ALL" : TARGET_SO_LIST.join(", "));
    console.log("[*] Filter System Classes:", FILTER_SYSTEM_CLASSES);
    console.log("[*] Show All Calls:", SHOW_ALL_CALLS);
    console.log("[*] ========================================\n");

    // 检查目标 SO 是否已加载
    console.log("[*] Checking if target SO is loaded:");
    var targetLoaded = false;
    Process.enumerateModules().forEach(function(module) {
        for (var i = 0; i < TARGET_SO_LIST.length; i++) {
            if (module.name.indexOf(TARGET_SO_LIST[i]) >= 0) {
                console.log("  [+] Found:", module.name, "at", module.base);
                targetLoaded = true;
            }
        }
    });

    if (!targetLoaded && TARGET_SO_LIST.length > 0) {
        console.log("  [!] WARNING: Target SO not yet loaded. Hooks will activate when SO makes JNI calls.");
    }
    console.log("");

    var env = Java.vm.getEnv();
    var jniEnvPtr = env.handle.readPointer();

    // Hook FindClass (index 6)
    if (HOOK_CONFIG.FindClass) {
        try {
            var FindClass = jniEnvPtr.add(Process.pointerSize * 6).readPointer();
            console.log("[*] Hooking FindClass at:", FindClass);
            Interceptor.attach(FindClass, {
                onEnter: function(args) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    if (SHOW_ALL_CALLS || shouldMonitorModule(module)) {
                        var className = Memory.readCString(args[1]);
                        if (!FILTER_SYSTEM_CLASSES || (className.indexOf("java/") == -1 && className.indexOf("android/") == -1)) {
                            var prefix = shouldMonitorModule(module) ? "[FindClass] *TARGET*" : "[FindClass]";
                            console.log(prefix, className, getCallerInfo(this.returnAddress));
                        }
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook FindClass:", e.message);
        }
    }

    // Hook GetMethodID (index 33)
    if (HOOK_CONFIG.GetMethodID) {
        try {
            var GetMethodID = jniEnvPtr.add(Process.pointerSize * 33).readPointer();
            console.log("[*] Hooking GetMethodID at:", GetMethodID);
            Interceptor.attach(GetMethodID, {
                onEnter: function(args) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    var shouldShow = SHOW_ALL_CALLS || shouldMonitorModule(module);
                    if (shouldShow) {
                        try {
                            var methodName = Memory.readCString(args[2]);
                            var signature = Memory.readCString(args[3]);
                            var prefix = shouldMonitorModule(module) ? "[GetMethodID] *TARGET*" : "[GetMethodID]";
                            console.log(prefix, "method:", methodName, "sig:", signature, getCallerInfo(this.returnAddress));
                        } catch (e) {
                            console.log("[GetMethodID] Error reading args:", e.message);
                        }
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook GetMethodID:", e.message);
        }
    }

    // Hook GetStaticMethodID (index 113)
    if (HOOK_CONFIG.GetStaticMethodID) {
        try {
            var GetStaticMethodID = jniEnvPtr.add(Process.pointerSize * 113).readPointer();
            console.log("[*] Hooking GetStaticMethodID at:", GetStaticMethodID);
            Interceptor.attach(GetStaticMethodID, {
                onEnter: function(args) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    if (SHOW_ALL_CALLS || shouldMonitorModule(module)) {
                        try {
                            var clazz = args[1];
                            var className = Java.vm.tryGetEnv().getClassName(clazz);
                            var methodName = Memory.readCString(args[2]);
                            var signature = Memory.readCString(args[3]);

                            if (!FILTER_SYSTEM_CLASSES || (className.indexOf("java.") == -1 && className.indexOf("android.") == -1)) {
                                var prefix = shouldMonitorModule(module) ? "[GetStaticMethodID] *TARGET*" : "[GetStaticMethodID]";
                                console.log(prefix, className + "." + methodName, signature, getCallerInfo(this.returnAddress));
                            }
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook GetStaticMethodID:", e.message);
        }
    }

    // Hook GetFieldID (index 94)
    if (HOOK_CONFIG.GetFieldID) {
        try {
            var GetFieldID = jniEnvPtr.add(Process.pointerSize * 94).readPointer();
            console.log("[*] Hooking GetFieldID at:", GetFieldID);
            Interceptor.attach(GetFieldID, {
                onEnter: function(args) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    if (SHOW_ALL_CALLS || shouldMonitorModule(module)) {
                        try {
                            var clazz = args[1];
                            var className = Java.vm.tryGetEnv().getClassName(clazz);
                            var fieldName = Memory.readCString(args[2]);
                            var signature = Memory.readCString(args[3]);

                            if (!FILTER_SYSTEM_CLASSES || (className.indexOf("java.") == -1 && className.indexOf("android.") == -1)) {
                                var prefix = shouldMonitorModule(module) ? "[GetFieldID] *TARGET*" : "[GetFieldID]";
                                console.log(prefix, className + "." + fieldName, signature, getCallerInfo(this.returnAddress));
                            }
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook GetFieldID:", e.message);
        }
    }

    // Hook GetStaticFieldID (index 144)
    if (HOOK_CONFIG.GetStaticFieldID) {
        try {
            var GetStaticFieldID = jniEnvPtr.add(Process.pointerSize * 144).readPointer();
            console.log("[*] Hooking GetStaticFieldID at:", GetStaticFieldID);
            Interceptor.attach(GetStaticFieldID, {
                onEnter: function(args) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    if (SHOW_ALL_CALLS || shouldMonitorModule(module)) {
                        try {
                            var clazz = args[1];
                            var className = Java.vm.tryGetEnv().getClassName(clazz);
                            var fieldName = Memory.readCString(args[2]);
                            var signature = Memory.readCString(args[3]);

                            if (!FILTER_SYSTEM_CLASSES || (className.indexOf("java.") == -1 && className.indexOf("android.") == -1)) {
                                var prefix = shouldMonitorModule(module) ? "[GetStaticFieldID] *TARGET*" : "[GetStaticFieldID]";
                                console.log(prefix, className + "." + fieldName, signature, getCallerInfo(this.returnAddress));
                            }
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook GetStaticFieldID:", e.message);
        }
    }

    // Hook RegisterNatives (index 215)
    if (HOOK_CONFIG.RegisterNatives) {
        try {
            var RegisterNatives = jniEnvPtr.add(Process.pointerSize * 215).readPointer();
            console.log("[*] Hooking RegisterNatives at:", RegisterNatives);
            Interceptor.attach(RegisterNatives, {
                onEnter: function(args) {
                    hookCount++;
                    try {
                        var clazz = args[1];
                        var className = Java.vm.tryGetEnv().getClassName(clazz);
                        var methods_ptr = ptr(args[2]);
                        var method_count = parseInt(args[3]);

                        // 检查是否有我们关心的模块
                        var shouldLog = SHOW_ALL_CALLS;
                        for (var i = 0; i < method_count; i++) {
                            var fnPtr = methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();
                            var module = Process.findModuleByAddress(fnPtr);
                            if (shouldMonitorModule(module)) {
                                shouldLog = true;
                                break;
                            }
                        }

                        if (!shouldLog) return;

                        console.log("[RegisterNatives] *TARGET*", className, "count:", method_count, getCallerInfo(this.returnAddress));

                        for (var i = 0; i < method_count; i++) {
                            var name_ptr = methods_ptr.add(i * Process.pointerSize * 3).readPointer();
                            var sig_ptr = methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize).readPointer();
                            var fnPtr = methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();

                            var name = name_ptr.readCString();
                            var sig = sig_ptr.readCString();
                            var module = Process.findModuleByAddress(fnPtr);

                            if (shouldMonitorModule(module) || SHOW_ALL_CALLS) {
                                var offset = fnPtr.sub(module.base);
                                console.log("  ->", name, sig, "[" + module.name + "+" + offset + "]");
                            }
                        }
                    } catch (e) {
                        console.log("[RegisterNatives] Error:", e.message);
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook RegisterNatives:", e.message);
        }
    }

    // Hook NewStringUTF (index 167)
    if (HOOK_CONFIG.NewStringUTF) {
        try {
            var NewStringUTF = jniEnvPtr.add(Process.pointerSize * 167).readPointer();
            console.log("[*] Hooking NewStringUTF at:", NewStringUTF);
            Interceptor.attach(NewStringUTF, {
                onEnter: function(args) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    if (SHOW_ALL_CALLS || shouldMonitorModule(module)) {
                        try {
                            var str = Memory.readCString(args[1]);
                            var prefix = shouldMonitorModule(module) ? "[NewStringUTF] *TARGET*" : "[NewStringUTF]";
                            console.log(prefix, str, getCallerInfo(this.returnAddress));
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook NewStringUTF:", e.message);
        }
    }

    // Hook GetStringUTFChars (index 169)
    if (HOOK_CONFIG.GetStringUTFChars) {
        try {
            var GetStringUTFChars = jniEnvPtr.add(Process.pointerSize * 169).readPointer();
            console.log("[*] Hooking GetStringUTFChars at:", GetStringUTFChars);
            Interceptor.attach(GetStringUTFChars, {
                onLeave: function(retval) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    if ((SHOW_ALL_CALLS || shouldMonitorModule(module)) && !retval.isNull()) {
                        try {
                            var str = Memory.readCString(retval);
                            var prefix = shouldMonitorModule(module) ? "[GetStringUTFChars] *TARGET*" : "[GetStringUTFChars]";
                            console.log(prefix, str, getCallerInfo(this.returnAddress));
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook GetStringUTFChars:", e.message);
        }
    }

    // Hook DefineClass (index 5)
    if (HOOK_CONFIG.DefineClass) {
        try {
            var DefineClass = jniEnvPtr.add(Process.pointerSize * 5).readPointer();
            console.log("[*] Hooking DefineClass at:", DefineClass);
            Interceptor.attach(DefineClass, {
                onEnter: function(args) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    if (SHOW_ALL_CALLS || shouldMonitorModule(module)) {
                        try {
                            var name = Memory.readCString(args[1]);
                            var bufLen = parseInt(args[3]);
                            var prefix = shouldMonitorModule(module) ? "[DefineClass] *TARGET*" : "[DefineClass]";
                            console.log(prefix, "name:", name, "bufLen:", bufLen, getCallerInfo(this.returnAddress));
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook DefineClass:", e.message);
        }
    }

    // Hook GetObjectClass (index 31)
    if (HOOK_CONFIG.GetObjectClass) {
        try {
            var GetObjectClass = jniEnvPtr.add(Process.pointerSize * 31).readPointer();
            console.log("[*] Hooking GetObjectClass at:", GetObjectClass);
            Interceptor.attach(GetObjectClass, {
                onLeave: function(retval) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    if ((SHOW_ALL_CALLS || shouldMonitorModule(module)) && !retval.isNull()) {
                        try {
                            var className = Java.vm.tryGetEnv().getClassName(retval);
                            if (!FILTER_SYSTEM_CLASSES || (className.indexOf("java.") == -1 && className.indexOf("android.") == -1)) {
                                var prefix = shouldMonitorModule(module) ? "[GetObjectClass] *TARGET*" : "[GetObjectClass]";
                                console.log(prefix, className, getCallerInfo(this.returnAddress));
                            }
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook GetObjectClass:", e.message);
        }
    }

    // Hook GetSuperclass (index 10)
    if (HOOK_CONFIG.GetSuperclass) {
        try {
            var GetSuperclass = jniEnvPtr.add(Process.pointerSize * 10).readPointer();
            console.log("[*] Hooking GetSuperclass at:", GetSuperclass);
            Interceptor.attach(GetSuperclass, {
                onEnter: function(args) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    if (SHOW_ALL_CALLS || shouldMonitorModule(module)) {
                        try {
                            var className = Java.vm.tryGetEnv().getClassName(args[1]);
                            this.className = className;
                        } catch (e) {}
                    }
                },
                onLeave: function(retval) {
                    if (this.className && !retval.isNull()) {
                        try {
                            var module = Process.findModuleByAddress(this.returnAddress);
                            var superClass = Java.vm.tryGetEnv().getClassName(retval);
                            var prefix = shouldMonitorModule(module) ? "[GetSuperclass] *TARGET*" : "[GetSuperclass]";
                            console.log(prefix, this.className, "->", superClass, getCallerInfo(this.returnAddress));
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook GetSuperclass:", e.message);
        }
    }

    // Hook IsAssignableFrom (index 11)
    if (HOOK_CONFIG.IsAssignableFrom) {
        try {
            var IsAssignableFrom = jniEnvPtr.add(Process.pointerSize * 11).readPointer();
            console.log("[*] Hooking IsAssignableFrom at:", IsAssignableFrom);
            Interceptor.attach(IsAssignableFrom, {
                onEnter: function(args) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    if (SHOW_ALL_CALLS || shouldMonitorModule(module)) {
                        try {
                            var class1 = Java.vm.tryGetEnv().getClassName(args[1]);
                            var class2 = Java.vm.tryGetEnv().getClassName(args[2]);
                            var prefix = shouldMonitorModule(module) ? "[IsAssignableFrom] *TARGET*" : "[IsAssignableFrom]";
                            console.log(prefix, class1, "from", class2, getCallerInfo(this.returnAddress));
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook IsAssignableFrom:", e.message);
        }
    }

    // Hook IsInstanceOf (index 32)
    if (HOOK_CONFIG.IsInstanceOf) {
        try {
            var IsInstanceOf = jniEnvPtr.add(Process.pointerSize * 32).readPointer();
            console.log("[*] Hooking IsInstanceOf at:", IsInstanceOf);
            Interceptor.attach(IsInstanceOf, {
                onEnter: function(args) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    if (SHOW_ALL_CALLS || shouldMonitorModule(module)) {
                        try {
                            var className = Java.vm.tryGetEnv().getClassName(args[2]);
                            var prefix = shouldMonitorModule(module) ? "[IsInstanceOf] *TARGET*" : "[IsInstanceOf]";
                            console.log(prefix, "checking type:", className, getCallerInfo(this.returnAddress));
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook IsInstanceOf:", e.message);
        }
    }

    // Hook AllocObject (index 27)
    if (HOOK_CONFIG.AllocObject) {
        try {
            var AllocObject = jniEnvPtr.add(Process.pointerSize * 27).readPointer();
            console.log("[*] Hooking AllocObject at:", AllocObject);
            Interceptor.attach(AllocObject, {
                onEnter: function(args) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    if (SHOW_ALL_CALLS || shouldMonitorModule(module)) {
                        try {
                            var className = Java.vm.tryGetEnv().getClassName(args[1]);
                            if (!FILTER_SYSTEM_CLASSES || (className.indexOf("java.") == -1 && className.indexOf("android.") == -1)) {
                                var prefix = shouldMonitorModule(module) ? "[AllocObject] *TARGET*" : "[AllocObject]";
                                console.log(prefix, className, getCallerInfo(this.returnAddress));
                            }
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook AllocObject:", e.message);
        }
    }

    // Hook NewObject (index 28)
    if (HOOK_CONFIG.NewObject) {
        try {
            var NewObject = jniEnvPtr.add(Process.pointerSize * 28).readPointer();
            console.log("[*] Hooking NewObject at:", NewObject);
            Interceptor.attach(NewObject, {
                onEnter: function(args) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    if (SHOW_ALL_CALLS || shouldMonitorModule(module)) {
                        try {
                            var className = Java.vm.tryGetEnv().getClassName(args[1]);
                            if (!FILTER_SYSTEM_CLASSES || (className.indexOf("java.") == -1 && className.indexOf("android.") == -1)) {
                                var prefix = shouldMonitorModule(module) ? "[NewObject] *TARGET*" : "[NewObject]";
                                console.log(prefix, className, getCallerInfo(this.returnAddress));
                            }
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook NewObject:", e.message);
        }
    }

    // Hook NewObjectArray (index 172)
    if (HOOK_CONFIG.NewObjectArray) {
        try {
            var NewObjectArray = jniEnvPtr.add(Process.pointerSize * 172).readPointer();
            console.log("[*] Hooking NewObjectArray at:", NewObjectArray);
            Interceptor.attach(NewObjectArray, {
                onEnter: function(args) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    if (SHOW_ALL_CALLS || shouldMonitorModule(module)) {
                        try {
                            var size = parseInt(args[1]);
                            var className = Java.vm.tryGetEnv().getClassName(args[2]);
                            if (!FILTER_SYSTEM_CLASSES || (className.indexOf("java.") == -1 && className.indexOf("android.") == -1)) {
                                var prefix = shouldMonitorModule(module) ? "[NewObjectArray] *TARGET*" : "[NewObjectArray]";
                                console.log(prefix, className + "[" + size + "]", getCallerInfo(this.returnAddress));
                            }
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook NewObjectArray:", e.message);
        }
    }

    // Hook FromReflectedMethod (index 7)
    if (HOOK_CONFIG.FromReflectedMethod) {
        try {
            var FromReflectedMethod = jniEnvPtr.add(Process.pointerSize * 7).readPointer();
            console.log("[*] Hooking FromReflectedMethod at:", FromReflectedMethod);
            Interceptor.attach(FromReflectedMethod, {
                onEnter: function(args) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    if (SHOW_ALL_CALLS || shouldMonitorModule(module)) {
                        try {
                            Java.perform(function() {
                                try {
                                    // 尝试作为 Method
                                    var method = Java.cast(args[1], Java.use("java.lang.reflect.Method"));
                                    var className = method.getDeclaringClass().getName();
                                    var methodName = method.getName();
                                    var prefix = shouldMonitorModule(module) ? "[FromReflectedMethod] *TARGET*" : "[FromReflectedMethod]";
                                    console.log(prefix, className + "." + methodName, getCallerInfo(this.returnAddress));
                                } catch (e1) {
                                    try {
                                        // 尝试作为 Constructor
                                        var constructor = Java.cast(args[1], Java.use("java.lang.reflect.Constructor"));
                                        var className = constructor.getDeclaringClass().getName();
                                        var prefix = shouldMonitorModule(module) ? "[FromReflectedMethod] *TARGET*" : "[FromReflectedMethod]";
                                        console.log(prefix, className + ".<init>", getCallerInfo(this.returnAddress));
                                    } catch (e2) {}
                                }
                            }.bind(this));
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook FromReflectedMethod:", e.message);
        }
    }

    // Hook FromReflectedField (index 8)
    if (HOOK_CONFIG.FromReflectedField) {
        try {
            var FromReflectedField = jniEnvPtr.add(Process.pointerSize * 8).readPointer();
            console.log("[*] Hooking FromReflectedField at:", FromReflectedField);
            Interceptor.attach(FromReflectedField, {
                onEnter: function(args) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    if (SHOW_ALL_CALLS || shouldMonitorModule(module)) {
                        try {
                            Java.perform(function() {
                                var field = Java.cast(args[1], Java.use("java.lang.reflect.Field"));
                                var className = field.getDeclaringClass().getName();
                                var fieldName = field.getName();
                                var prefix = shouldMonitorModule(module) ? "[FromReflectedField] *TARGET*" : "[FromReflectedField]";
                                console.log(prefix, className + "." + fieldName, getCallerInfo(this.returnAddress));
                            }.bind(this));
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook FromReflectedField:", e.message);
        }
    }

    // Hook ToReflectedMethod (index 9)
    if (HOOK_CONFIG.ToReflectedMethod) {
        try {
            var ToReflectedMethod = jniEnvPtr.add(Process.pointerSize * 9).readPointer();
            console.log("[*] Hooking ToReflectedMethod at:", ToReflectedMethod);
            Interceptor.attach(ToReflectedMethod, {
                onEnter: function(args) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    if (SHOW_ALL_CALLS || shouldMonitorModule(module)) {
                        try {
                            var className = Java.vm.tryGetEnv().getClassName(args[1]);
                            var prefix = shouldMonitorModule(module) ? "[ToReflectedMethod] *TARGET*" : "[ToReflectedMethod]";
                            console.log(prefix, "class:", className, getCallerInfo(this.returnAddress));
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook ToReflectedMethod:", e.message);
        }
    }

    // Hook ToReflectedField (index 12)
    if (HOOK_CONFIG.ToReflectedField) {
        try {
            var ToReflectedField = jniEnvPtr.add(Process.pointerSize * 12).readPointer();
            console.log("[*] Hooking ToReflectedField at:", ToReflectedField);
            Interceptor.attach(ToReflectedField, {
                onEnter: function(args) {
                    hookCount++;
                    var module = Process.findModuleByAddress(this.returnAddress);

                    if (SHOW_ALL_CALLS || shouldMonitorModule(module)) {
                        try {
                            var className = Java.vm.tryGetEnv().getClassName(args[1]);
                            var prefix = shouldMonitorModule(module) ? "[ToReflectedField] *TARGET*" : "[ToReflectedField]";
                            console.log(prefix, "class:", className, getCallerInfo(this.returnAddress));
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {
            console.log("[!] Failed to hook ToReflectedField:", e.message);
        }
    }

    console.log("\n[*] ========================================");
    console.log("[*] All JNI hooks installed successfully!");
    console.log("[*] Waiting for JNI calls...");
    console.log("[*] ========================================\n");

    // 定期打印统计信息
    setInterval(function() {
        if (hookCount > 0) {
            console.log("[*] Total JNI calls intercepted:", hookCount);
        }
    }, 10000);  // 每 10 秒打印一次
}

// 在 Java 虚拟机初始化完成后执行
Java.perform(function() {
    hookAllJNI();
});
