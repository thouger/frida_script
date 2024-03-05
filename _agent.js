📦
980 /src/index.js.map
2740 /src/index.js
11 /src/index.d.ts
43 /src/java/file.d.ts
1010 /src/java/file.js.map
1013 /src/java/file.js
45 /src/java/stringBuilder.d.ts
824 /src/java/stringBuilder.js.map
1440 /src/java/stringBuilder.js
245 /src/java/trace.d.ts
11854 /src/java/trace.js.map
16344 /src/java/trace.js
139 /src/java/trace_change.d.ts
4621 /src/java/trace_change.js.map
6558 /src/java/trace_change.js
56 /src/so/all_so.d.ts
755 /src/so/all_so.js.map
858 /src/so/all_so.js
138 /src/so/hook_func.d.ts
2285 /src/so/hook_func.js.map
3084 /src/so/hook_func.js
44 /src/so/init_array.d.ts
2323 /src/so/init_array.js.map
2346 /src/so/init_array.js
137 /src/so/inlinehook.d.ts
2223 /src/so/inlinehook.js.map
3009 /src/so/inlinehook.js
11 /src/so/scan.d.ts
371 /src/so/scan.js.map
975 /src/so/scan.js
53 /src/so/sktrace/sktrace.d.ts
4028 /src/so/sktrace/sktrace.js.map
6366 /src/so/sktrace/sktrace.js
53 /src/so/so_info.d.ts
766 /src/so/so_info.js.map
465 /src/so/so_info.js
58 /src/so/so_method.d.ts
911 /src/so/so_method.js.map
773 /src/so/so_method.js
146 /src/so/stalker.d.ts
5032 /src/so/stalker.js.map
7659 /src/so/stalker.js
84 /src/so/utils.d.ts
777 /src/so/utils.js.map
695 /src/so/utils.js
292 /src/utils/log.d.ts
4057 /src/utils/log.js.map
3679 /src/utils/log.js
✄
{"version":3,"file":"index.js","sourceRoot":"/home/thouger/Desktop/code/frida_script/","sources":["src/index.ts"],"names":[],"mappings":"AAKA,OAAO,EAAC,KAAK,EAAC,MAAM,iBAAiB,CAAA;AAYrC,gDAAgD;AAChD,8CAA8C;AAC9C,IAAI,CAAC,OAAO,CAAC;IACb,wDAAwD;IACxD,oDAAoD;IACpD,kDAAkD;IAClD,kFAAkF;IAElF,UAAU;IACV,8BAA8B;IAC9B,0BAA0B;IAC1B,4BAA4B;IAC5B,oCAAoC;IACpC,eAAe;IACf,SAAS;IACT,gBAAgB;IAChB,gCAAgC;IAChC,gDAAgD;IAChD,yCAAyC;IACzC,6BAA6B;IAE7B,MAAM;IACN,iBAAiB;IACjB,4EAA4E;IAC5E,2CAA2C;IAE3C,sCAAsC;IACtC,qCAAqC;IACrC,wCAAwC;IACxC,4CAA4C;IAC5C,qCAAqC;IACrC,YAAY;IACZ,wCAAwC;IACxC,YAAY;IACZ,+CAA+C;IAC/C,UAAU;IACV,gDAAgD;IAChD,WAAW;IACX,qCAAqC;IAErC,uCAAuC;IACvC,wDAAwD;IACxD,KAAK,CAAC,4CAA4C,CAAC,CAAA;IACnD,kEAAkE;IAElE,0DAA0D;IAC1D,8DAA8D;IAC9D,mEAAmE;IACnE,kFAAkF;IAClF,2CAA2C;IAC3C,2DAA2D;IAE3D,4EAA4E;IAC5E,+DAA+D;IAC/D,4BAA4B;IAC5B,cAAc;IAEd,cAAc;IACd,2DAA2D;IAC3D,qCAAqC;IAErC,6EAA6E;IAC7E,iBAAiB;IACjB,mCAAmC;IACnC,4CAA4C;IAC5C,gBAAgB;IAChB,eAAe;IACf,gCAAgC;AAChC,CAAC,CAAC,CAAA"}
✄
import { trace } from "./java/trace.js";
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
    trace('com.moba.unityplugin.MobaGameUnityActivity');
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
});
✄
export {};

✄
export declare function hook_file(): void;

✄
{"version":3,"file":"file.js","sourceRoot":"/home/thouger/Desktop/code/frida_script/","sources":["src/java/file.ts"],"names":[],"mappings":"AAGA,MAAM,UAAU,SAAS;IACrB,IAAI,CAAC,OAAO,CAAC;QACT,IAAI,IAAI,GAAG,IAAI,CAAC,GAAG,CAAC,cAAc,CAAC,CAAC;QAEpC,gBAAgB;QAChB,IAAI,CAAC,KAAK,CAAC,QAAQ,CAAC,kBAAkB,CAAC,CAAC,cAAc,GAAG,UAAU,IAAI;YACnE,OAAO,CAAC,GAAG,CAAC,iCAAiC,GAAG,IAAI,CAAC,CAAC;YAEtD,IAAG;gBACC,IAAI,SAAS,GAAI,IAAI,CAAC,OAAO,CAAC,IAAI,CAAC,IAAI,CAAC,CAAC;gBACzC,QAAQ;gBACR,OAAO,CAAC,GAAG,CAAC,aAAa,GAAE,SAAS,CAAC,CAAC;aACzC;YAAA,OAAM,CAAC,EAAC;gBACL,iBAAiB;aACpB;YAED,OAAO,IAAI,CAAC,KAAK,CAAC,IAAI,CAAC,IAAI,EAAE,IAAI,CAAC,CAAC;QACvC,CAAC,CAAC;QAEF,gBAAgB;QAChB,IAAI,CAAC,KAAK,CAAC,QAAQ,CAAC,kBAAkB,EAAE,kBAAkB,CAAC,CAAC,cAAc,GAAG,UAAU,OAAO,EAAE,QAAQ;YACpG,OAAO,CAAC,GAAG,CAAC,oCAAoC,GAAG,OAAO,GAAG,cAAc,GAAG,QAAQ,CAAC,CAAC;YAExF,QAAQ;YACR,OAAO,CAAC,GAAG,CAAC,aAAa,GAAG,QAAQ,CAAC,CAAC;YAEtC,OAAO,IAAI,CAAC,KAAK,CAAC,IAAI,CAAC,IAAI,EAAE,OAAO,EAAE,QAAQ,CAAC,CAAC;QACpD,CAAC,CAAC;IACN,CAAC,CAAC,CAAC;AACP,CAAC"}
✄
export function hook_file() {
    Java.perform(function () {
        var File = Java.use('java.io.File');
        // Hook File构造函数
        File.$init.overload('java.lang.String').implementation = function (path) {
            console.log('File constructor hooked, path: ' + path);
            try {
                var file_name = this.getName.call(this);
                // 输出文件名
                console.log('File name: ' + file_name);
            }
            catch (e) {
                // console.log(e)
            }
            return this.$init.call(this, path);
        };
        // Hook File构造函数
        File.$init.overload('java.lang.String', 'java.lang.String').implementation = function (dirPath, fileName) {
            console.log('File constructor hooked, dirPath: ' + dirPath + ', fileName: ' + fileName);
            // 输出文件名
            console.log('File name: ' + fileName);
            return this.$init.call(this, dirPath, fileName);
        };
    });
}
✄
export declare function hook_string(): void;

✄
{"version":3,"file":"stringBuilder.js","sourceRoot":"/home/thouger/Desktop/code/frida_script/","sources":["src/java/stringBuilder.ts"],"names":[],"mappings":"AAGA,MAAM,UAAU,WAAW;IAE3B,2DAA2D;IACzD,oFAAoF;IACpF,qBAAqB;IACrB,kFAAkF;IAClF,0EAA0E;IAC1E,mCAAmC;IACnC,0CAA0C;IAC1C,kFAAkF;IAClF,0CAA0C;IAE1C,qBAAqB;IACrB,mCAAmC;IACnC,mBAAmB;IACnB,KAAK;IAEH,MAAM,aAAa,GAAG,IAAI,CAAC,GAAG,CAAC,yBAAyB,CAAC,CAAC;IACzD,aAAa,CAAC,QAAQ,CAAC,cAAc,GAAG;QACvC,IAAI,GAAG,GAAG,IAAI,CAAC,QAAQ,EAAE,CAAC;QAC1B,IAAI,GAAG,GAAG,EAAE,CAAC;QACb,IAAI,GAAG,KAAK,IAAI,EAAC;YACb,GAAG,GAAG,GAAG,CAAC,QAAQ,EAAE,CAAC,OAAO,CAAC,IAAI,EAAE,EAAE,CAAC,CAAC;YACvC,OAAO,CAAC,GAAG,CAAC,GAAG,CAAC,CAAC;SACpB;QACD,OAAO,GAAG,CAAC;IACb,CAAC,CAAC;AACN,CAAC;AAED,yCAAyC;AAIzC,yFAAyF;AACzF,6CAA6C;AAC7C,0HAA0H;AAC1H,wCAAwC;AACxC,uBAAuB;AACvB,kCAAkC;AAClC,SAAS;AACT,IAAI"}
✄
export function hook_string() {
    //   var targetClass = Java.use("java.lang.StringBuilder");
    // targetClass.append.overload('java.lang.String').implementation = function (str) {
    //   var output = '';
    //   output = output.concat("=================String.append====================");
    //   output = output.concat("str: " + str + " => " + JSON.stringify(str));
    //   output = output.concat("\r\n")
    //   output = output.concat(stacktrace());
    //   output = output.concat("=================String.append====================");
    //   if (output.indexOf("AFa1wSDK") != -1)
    //       log(output);
    //   var retval = this.append(str);
    //   return retval;
    // };
    const StringBuilder = Java.use('java.lang.StringBuilder');
    StringBuilder.toString.implementation = function () {
        var res = this.toString();
        var tmp = "";
        if (res !== null) {
            tmp = res.toString().replace("/n", "");
            console.log(tmp);
        }
        return res;
    };
}
// export function hook_stringBuilder() {
//     StringBuilder.$init.overload('java.lang.String').implementation = function (str) {
//         var output = str.toString() + '\n'
//         output=output.concat(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
//         output=output.concat("\r\n");
//         log(output);
//         return this.$init(str);
//     };
// }
✄
export declare function _trace(targetClass: any, method: any): void;
export declare function findAllJavaClasses(targetClass: any, targetMethod: any, is_trace: any): void;
export declare function trace(targetClass: any, targetMethod: any): void;

✄
{"version":3,"file":"trace.js","sourceRoot":"/home/thouger/Desktop/code/frida_script/","sources":["src/java/trace.ts"],"names":[],"mappings":"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"}
✄
//@ts-nocheck
import { log, stacktrace } from "../utils/log.js";
function hasOwnProperty(obj, name) {
    try {
        return obj.hasOwnProperty(name) || name in obj;
    }
    catch (e) {
        return obj.hasOwnProperty(name);
    }
}
function getHandle(object) {
    if (hasOwnProperty(object, '$handle')) {
        if (object.$handle != undefined) {
            return object.$handle;
        }
    }
    if (hasOwnProperty(object, '$h')) {
        if (object.$h != undefined) {
            return object.$h;
        }
    }
    return null;
}
//查看域值
function inspectObject(obj, input) {
    var isInstance = false;
    var obj_class = null;
    if (getHandle(obj) === null) {
        obj_class = obj.class;
    }
    else {
        var Class = Java.use("java.lang.Class");
        obj_class = Java.cast(obj.getClass(), Class);
        isInstance = true;
    }
    input = input.concat("Inspecting Fields: => ", isInstance, " => ", obj_class.toString());
    input = input.concat("\n");
    var fields = obj_class.getDeclaredFields();
    for (var i in fields) {
        if (isInstance || Boolean(fields[i].toString().indexOf("static ") >= 0)) {
            // output = output.concat("\t\t static static static " + fields[i].toString());
            var className = obj_class.toString().trim().split(" ")[1];
            // console.Red("className is => ",className);
            var fieldName = fields[i].toString().split(className.concat(".")).pop();
            var fieldType = fields[i].toString().split(" ").slice(-2)[0];
            var fieldValue = undefined;
            if (!(obj[fieldName] === undefined))
                fieldValue = obj[fieldName].value;
            input = input.concat(fieldType + " \t" + fieldName + " => ", fieldValue + " => ", JSON.stringify(fieldValue));
            input = input.concat("\n");
        }
    }
    return input;
}
function bytes2hex(array) {
    // var result=Java.use("java.util.Arrays").toString();
    //把结果存到数组里
    var result = "";
    for (var i = 0; i < array.length; ++i) {
        result += array[i].charCodeAt(0);
        result += ",";
    }
    return result;
}
function getReflectFields(val1, output) {
    var clazz = Java.use("java.lang.Class");
    var parametersTest = Java.cast(val1.getClass(), clazz);
    //getDeclaredFields()获取所有字段
    var fields = parametersTest.getDeclaredFields();
    fields.forEach(function (field) {
        output = output.concat("field type is: " + (field.getType()) + "\n");
        output = output.concat("field name is: " + (field.getName()) + "\n");
        output = output.concat("field value is: " + field.get(val1) + "\n");
    });
    return output;
}
function getReflectMethod(val1) {
    try {
        var clazz = Java.use("java.lang.Class");
        var parametersTest = Java.cast(val1.getClass(), clazz);
        //getDeclaredMethods()获取所有方法
        var methods = parametersTest.getDeclaredMethods();
        methods.forEach(function (method) {
            var methodName = method.getName();
            var val1Class = val1.getClass();
            var val1ClassName = Java.use(val1Class.getName());
            var overloads = val1ClassName[methodName].overloads;
            overloads.forEach(function (overload) {
                var proto = "(";
                overload.argumentTypes.forEach(function (type) {
                    proto += type.className + ", ";
                });
                if (proto.length > 1) {
                    proto = proto.substr(0, proto.length - 2);
                }
                proto += ")";
                overload.implementation = function () {
                    var args = [];
                    for (var j = 0; j < arguments.length; j++) {
                        for (var i in arguments[j]) {
                            var value = String(arguments[j][i]);
                            send(val1ClassName + "." + methodName + " and arguments value is: " + value);
                        }
                        args[j] = arguments[j] + "";
                    }
                    //打印方法参数
                    send(val1ClassName + "." + methodName + " and args is: " + args);
                    //调用方法
                    var retval = this[methodName].apply(this, arguments);
                    //打印方法返回值
                    send(methodName + " return value is: " + retval);
                    return retval; //返回方法返回值
                };
            });
        });
    }
    catch (e) {
        send("'" + val1 + "' hook fail: " + e);
    }
}
function traceMethod(targetMethod, unparseMethod) {
    log("targetMethod: " + targetMethod);
    var delim = targetMethod.lastIndexOf(".");
    var targetClass = targetMethod.slice(0, delim);
    var targetMethod = targetMethod.slice(delim + 1, targetMethod.length);
    var hook = Java.use(targetClass);
    if (!hook[targetMethod]) {
        log("Class not found: " + targetClass);
        return;
    }
    var overloadCount = hook[targetMethod].overloads.length;
    //多个函数重载会有一个问题，当参数是Object[] objArr，不能给它赋值，因此需要单独重载特定参数函数
    //     hook["values"].overload('java.lang.String', 'java.lang.String', 'int').implementation = function (str, str2, i) {
    //     console.log(`AFa1xSDK.values is called: str=${str}, str2=${str2}, i=${i}`);
    //     var result = this["values"](str, str2, i);
    //     console.log(`AFa1xSDK.values result=${result}`);
    //     return result;
    // };
    for (var i = 0; i < overloadCount; i++) {
        hook[targetMethod].overloads[i].implementation = function () {
            var output = "";
            //画个横线
            for (var p = 0; p < 100; p++) {
                output = output.concat("==");
            }
            output = output.concat("\n");
            var retval = this[targetMethod].apply(this, arguments);
            //域值
            output = inspectObject(this, output);
            // 进入函数
            output = output.concat("*********entered " + unparseMethod + "********* \n");
            for (var j = 0; j < arguments.length; j++) {
                output = output.concat("arg[" + j + "]: " + arguments[j] + " => " + JSON.stringify(arguments[j]));
                output = output.concat("\n");
            }
            //调用栈
            var stacktraceLog = stacktrace();
            output = output.concat(stacktraceLog);
            // //返回值
            output = output.concat("\n retval: " + retval + " => " + JSON.stringify(retval));
            output = output.concat("\n-------------------test---------------------\n");
            // 测试的地方
            // 将retval转为hashmap
            // var val1 = Java.cast(retval,Java.use("java.util.HashMap"));
            // // 修改vpn_ip键的值改为''
            // val1.put("vpn_ip","");
            // retval = null;
            // log(print_hashmap(retval))
            // output = output.concat(this.e);
            // console.log('CopyOnWriteArrayList values: ' + val.size());
            //离开函数
            output = output.concat("\n ********* exiting " + targetMethod + '*********\n');
            //画个横线
            for (var p = 0; p < 100; p++) {
                output = output.concat("==");
            }
            // print_hashmap(retval)
            log(output);
            return retval;
        };
    }
}
export function _trace(targetClass, method) {
    var output = "Tracing Class: " + hook + "\n";
    var hook = Java.use(targetClass);
    var methods = hook.class.getDeclaredMethods();
    hook.$dispose();
    var methodsDict = {};
    output += "\t\nSpec: => \n";
    methods.forEach(_method => {
        _method = _method.toString();
        output += _method + "\n";
        var parsedMethod = _method.replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1];
        if (method && method.toLowerCase() !== parsedMethod.toLowerCase())
            return;
        methodsDict[_method] = parsedMethod;
    });
    //添加构造函数
    var varructors = hook.class.getDeclaredConstructors();
    if (varructors.length > 0) {
        varructors.forEach(function (varructor) {
            output += "Tracing " + varructor.toString() + "\n";
        });
        //有时候hook构造函数会报错，看情况取消
        methodsDict["$init"] = '$init';
    }
    log(output);
    //对数组中所有的方法进行hook，
    for (var unparseMethod in methodsDict) {
        var parsedMethod = methodsDict[unparseMethod];
        traceMethod(targetClass + "." + parsedMethod, unparseMethod);
    }
}
var BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
var classloader = Java.use("java.lang.ClassLoader");
var DexPathList = Java.use("dalvik.system.DexPathList");
var DexFile = Java.use("dalvik.system.DexFile");
var DexPathListElement = Java.use("dalvik.system.DexPathList$Element");
// 遍历所有类加载器并查找目标类
function findClassesInClassLoader(loader, targetClass, targetMethod, trace) {
    var pathClassLoader = Java.cast(loader, BaseDexClassLoader);
    // log("ClassLoader pathList: " + pathClassLoader.pathList.value);
    var dexPathList = Java.cast(pathClassLoader.pathList.value, DexPathList);
    // log("ClassLoader dexElements: " + dexPathList.dexElements.value.length);
    for (var i = 0; i < dexPathList.dexElements.value.length; i++) {
        var dexPathListElement = Java.cast(dexPathList.dexElements.value[i], DexPathListElement);
        if (dexPathListElement.dexFile.value) {
            var dexFile = Java.cast(dexPathListElement.dexFile.value, DexFile);
            var mCookie = dexFile.mCookie.value;
            if (dexFile.mInternalCookie.value) {
                mCookie = dexFile.mInternalCookie.value;
            }
            var classNameArr = dexPathListElement.dexFile.value.getClassNameList(mCookie);
            // log("dexFile.getClassNameList.length: " + classNameArr.length);
            for (var i = 0; i < classNameArr.length; i++) {
                var className = classNameArr[i];
                if (className.includes(targetClass)) {
                    log("Find class: " + className);
                    if (trace) {
                        Java.classFactory.loader = loader;
                    }
                }
            }
        }
    }
}
// 钩住所有的类加载器
export function findAllJavaClasses(targetClass, targetMethod, is_trace) {
    // // 第一种,不行，报错global reference table overflow,可以在返回值找到类，不能找到方法
    // var loadClass = classloader["loadClass"].overloads.length;
    // for (var i = 0; i < loadClass; i++) {
    //     classloader["loadClass"].overloads[i].implementation = function () {
    //         var retval = this["loadClass"].apply(this, arguments);
    //         var className = arguments[0];
    //         log("class:"+className);
    //         if (className.includes(targetClass)) {
    //             log("Find class: " + className);
    //             Java.classFactory.loader = this;
    //             Java.enumerateLoadedClasses({
    //                 onMatch: function (clazz) {
    //                     if (clazz.toLowerCase() == targetClass.toLowerCase()) {
    //                         log('find targetClass class: ' + clazz)
    //                         var method;
    //                         var output = "Tracing Class: " + targetClass + "\n";
    //                         var methods = retval.getDeclaredMethods()
    //                         var methodsDict = {};
    //                         output += "\t\nSpec: => \n";
    //                         methods.forEach(_method => {
    //                             _method = _method.toString()
    //                             output += _method + "\n";
    //                             var parsedMethod = _method.replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1];
    //                             if (method && method.toLowerCase() !== parsedMethod.toLowerCase())
    //                             return;
    //                         methodsDict[_method] = parsedMethod;
    //                         });
    //                         //添加构造函数
    //                         var varructors = retval.getDeclaredConstructors();
    //                         if (varructors.length > 0) {
    //                             varructors.forEach(function (varructor) {
    //                                 output += "Tracing " + varructor.toString() + "\n";
    //                             })
    //                             //有时候hook构造函数会报错，看情况取消
    //                             methodsDict["$init"]='$init';
    //                         }
    //                         log(output);
    //                         //对数组中所有的方法进行hook，
    //                         for (var unparseMethod in methodsDict) {
    //                             var parsedMethod = methodsDict[unparseMethod];
    //                             traceMethod(targetClass + "." + parsedMethod, unparseMethod);
    //                         }
    //                     }
    //                 },
    //                 onComplete: function () {
    //                     log("Search Class Completed!")
    //                 }
    //             });         
    //          }
    //         return retval;
    //     }
    // }
    // jni指针错误
    // var BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
    // var loadClass = BaseDexClassLoader["findResource"].overloads.length;
    // for (var i = 0; i < loadClass; i++) {
    //     BaseDexClassLoader["findResource"].overloads[i].implementation = function () {
    //         var retval = this["findResource"].apply(this, arguments);
    //         if (arguments[0].includes("com/appsflyer/internal")) {
    //             log("Find class: "); 
    //         }
    //         return retval;
    //     }
    // }
    // // // 第三种，通过热加载dex的方式
    // var overloadCount = BaseDexClassLoader["$init"].overloads.length;
    // for (var i = 0; i < overloadCount; i++) {
    //     BaseDexClassLoader["$init"].overloads[i].implementation = function () {
    //         var retval = this["$init"].apply(this, arguments);
    //         findClassesInClassLoader(this, targetClass,targetMethod,trace);
    //         return retval;
    //     }
    // }
}
function enumerateClassLoaders(targetClass, targetMethod) {
    var find = false;
    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            try {
                if (loader.findClass(targetClass)) {
                    log("Successfully found loader");
                    log("loader is : " + loader);
                    Java.classFactory.loader = loader;
                    log("Switch Classloader Successfully ! ");
                }
            }
            catch (error) {
                // console.log('enumerateClassLoaders error: ' + error + '\n')
            }
        },
        onComplete: function () {
            // log("EnumerateClassloader END")
        }
    });
    log('Begin enumerateClasses ...');
    var targetClasses = new Array();
    Java.enumerateLoadedClasses({
        onMatch: function (clazz) {
            // console.log(clazz)
            if (clazz.toLowerCase().indexOf(targetClass.toLowerCase()) > -1) {
                // if (clazz.toLowerCase() == targetClass.toLowerCase()) {
                log('find targetClass class: ' + clazz);
                find = true;
                targetClasses.push(clazz);
                _trace(clazz, targetMethod);
            }
        },
        onComplete: function () {
            log("Search Class Completed!");
        }
    });
    var output = "On Total Tracing :" + String(targetClasses.length) + " classes :\r\n";
    targetClasses.forEach(function (target) {
        output = output.concat(target);
        output = output.concat("\r\n");
    });
    log(output);
}
export function trace(targetClass, targetMethod) {
    // findAllJavaClasses(targetClass,targetMethod,true);
    enumerateClassLoaders(targetClass, targetMethod);
}
✄
export declare function _trace(targetClass: any, method: any): void;
export declare function trace_change(target: any, method: any): void;

✄
{"version":3,"file":"trace_change.js","sourceRoot":"/home/thouger/Desktop/code/frida_script/","sources":["src/java/trace_change.ts"],"names":[],"mappings":"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"}
✄
//@ts-nocheck
import { log, stacktrace } from "../utils/log.js";
function extractPackageName(path) {
    var startIndex = path.lastIndexOf('/');
    var endIndex = path.indexOf('/', startIndex + 1);
    if (startIndex !== -1 && endIndex !== -1) {
        return path.substring(startIndex + 1, endIndex);
    }
    else {
        return 'com.lazada.android'; // 无法提取包名时返回空字符串或其他默认值
    }
}
function traceMethod(targetMethod, unparseMethod) {
    var delim = targetMethod.lastIndexOf(".");
    var targetClass = targetMethod.slice(0, delim);
    var targetMethod = targetMethod.slice(delim + 1, targetMethod.length);
    var hook = Java.use(targetClass);
    if (!hook[targetMethod]) {
        log("Class not found: " + targetClass);
        return;
    }
    var overloadCount = hook[targetMethod].overloads.length;
    for (var i = 0; i < overloadCount; i++) {
        hook[targetMethod].overloads[i].implementation = function () {
            var output = "";
            for (var j = 0; j < arguments.length; j++) {
                output = output.concat("arg[" + j + "]: " + arguments[j] + " => " + JSON.stringify(arguments[j]));
                output = output.concat("\n");
            }
            var retval = this[targetMethod].apply(this, arguments);
            // //返回值
            output = output.concat("\n retval: " + retval + " => " + JSON.stringify(retval));
            // 进入函数
            output = output.concat("*********entered " + unparseMethod + "********* \n");
            log("*********entered " + unparseMethod + "********* \n");
            output = output.concat("\n----------------------------------------\n");
            var stacktraceLog = stacktrace();
            if (targetMethod == "getDataDir" && stacktraceLog.indexOf("com.lazada.android") != -1) {
                var File = Java.use('java.io.File');
                var path = retval.getPath();
                if (path.indexOf('ratel') == -1) {
                    var replacedPath = path + '/app_ratel_env_mock/default_0/data/';
                    output = output.concat("replace path is => ", replacedPath, "\n");
                    var file = File.$new(replacedPath);
                    log(output);
                    return file;
                }
            }
            // var context= arguments[0];
            // var dir = context.getDir("SGLib",0);
            // output = output.concat("dir is => ",dir.getAbsolutePath(),"\n");
            //         // var cls = "com.appsflyer.internal.AFf1cSDK"
            //         // var obj = Java.use(cls)
            //         // var csl2 = 'com.appsflyer.internal.AFa1xSDK'
            //         // var obj2 = Java.use(csl2)
            //         // output = output.concat("value values " + bytes2hex(obj2._values.value) + '\n');
            //         // output = output.concat("value AFInAppEventType " + bytes2hex(obj2._AFInAppEventType.value) + '\n');
            //         // output = output.concat("value AFKeystoreWrapper "+obj2._AFKeystoreWrapper.value.charCodeAt(0)+'\n');
            //         // output = output.concat("value AFf1cSDK.AFInAppEventType " + bytes2hex(obj.AFInAppEventType.value) + '\n');
            //         // output = output.concat("value AFf1cSDK.values " + obj.values.value.charCodeAt(0) + '\n');
            //         // output = output.concat("value AFf1cSDK.AFKeystoreWrapper " + obj.AFKeystoreWrapper.value.charCodeAt(0) + '\n');
            //         // output = output.concat("value AFf1cSDK.valueOf " + obj.valueOf.value + '\n');
            //         // output = output.concat("value AFf1cSDK.AFInAppEventParameterName " + obj.AFInAppEventParameterName.value + '\n');
            //         // output = output.concat("value AFf1cSDK.AFLogger " + obj.AFLogger.value + '\n');
            //         // output = output.concat("value AFf1cSDK.afErrorLog " + obj.afErrorLog.value + '\n');
            //         // output = output.concat(arguments[-1]+'\n')
            output = output.concat("----------------------------------------\n");
            //离开函数
            output = output.concat("\n ********* exiting " + targetMethod + '*********\n');
            log(output);
            return retval;
        };
    }
}
export function _trace(targetClass, method) {
    var output = "Tracing Class: " + targetClass + "\n";
    var hook = Java.use(targetClass);
    var methods = hook.class.getDeclaredMethods();
    hook.$dispose();
    var methodsDict = {};
    methods.forEach(_method => {
        _method = _method.toString();
        var parsedMethod = _method.replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1];
        if (method && method.toLowerCase() !== parsedMethod.toLowerCase())
            return;
        methodsDict[parsedMethod] = _method;
    });
    var Targets = methodsDict;
    //添加构造函数
    var constructors = hook.class.getDeclaredConstructors();
    if (constructors.length > 0) {
        //有时候hook构造函数会报错，看情况取消
        // methodsDict["$init"]='$init';
    }
    //对数组中所有的方法进行hook，
    for (var parsedMethod in methodsDict) {
        var unparseMethod = methodsDict[parsedMethod];
        traceMethod(targetClass + "." + parsedMethod, unparseMethod);
    }
}
export function trace_change(target, method) {
    Java.perform(function () {
        //有一种特殊的情况，需要use一下，才能hook到
        try {
            Java.use(target);
        }
        catch (error) {
            // console.log(error)
        }
        // log('\ntrace begin ... !')
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    if (loader.findClass(target)) {
                        Java.classFactory.loader = loader;
                    }
                }
                catch (error) {
                    // console.log('enumerateClassLoaders error: ' + error + '\n')
                }
            },
            onComplete: function () {
            }
        });
        var targetClasses = new Array();
        Java.enumerateLoadedClasses({
            onMatch: function (clazz) {
                if (clazz.toLowerCase().indexOf(target.toLowerCase()) > -1) {
                    // if (clazz.toLowerCase() == target.toLowerCase()) {
                    targetClasses.push(clazz);
                    _trace(clazz, method);
                }
            },
            onComplete: function () {
            }
        });
    });
}
✄
export declare function all_so(system?: boolean): void;

✄
{"version":3,"file":"all_so.js","sourceRoot":"/home/thouger/Desktop/code/frida_script/","sources":["src/so/all_so.ts"],"names":[],"mappings":"AAAA,aAAa;AACb,uCAAuC;AAEvC,MAAM,UAAU,MAAM,CAAC,SAAkB,KAAK;IAC1C;QACI,OAAO,CAAC,gBAAgB,CAAC;YACrB,OAAO,EAAE,UAAU,MAAM;gBAErB,IAAI,MAAM,EAAE;oBACR,2HAA2H;oBAC3H,OAAO,CAAC,GAAG,CAAC,eAAe,GAAG,MAAM,CAAC,IAAI,GAAG,KAAK,GAAG,gBAAgB,GAAG,MAAM,CAAC,IAAI,CAAC,QAAQ,EAAE,GAAG,KAAK,GAAG,QAAQ,GAAG,MAAM,CAAC,IAAI,CAAC,CAAC;iBACnI;qBAAM;oBACH,IAAI,CAAC,MAAM,CAAC,IAAI,CAAC,QAAQ,CAAC,WAAW,CAAC;wBACtC,OAAO,CAAC,GAAG,CAAC,eAAe,GAAG,MAAM,CAAC,IAAI,GAAG,KAAK,GAAG,gBAAgB,GAAG,MAAM,CAAC,IAAI,CAAC,QAAQ,EAAE,GAAG,KAAK,GAAG,QAAQ,GAAG,MAAM,CAAC,IAAI,CAAC,CAAC;iBACnI;YACL,CAAC;YACD,UAAU,EAAE;YACZ,CAAC;SACJ,CAAC,CAAC;KACN;AACL,CAAC"}
✄
//@ts-nocheck
// import {log} from "../utils/log.js";
export function all_so(system = false) {
    {
        Process.enumerateModules({
            onMatch: function (module) {
                if (system) {
                    // log('Module name: ' + module.name + " - " + "Base Address: " + module.base.toString() + " - " + "path: " + module.path);
                    console.log('Module name: ' + module.name + " - " + "Base Address: " + module.base.toString() + " - " + "path: " + module.path);
                }
                else {
                    if (!module.path.includes('/data/app'))
                        console.log('Module name: ' + module.name + " - " + "Base Address: " + module.base.toString() + " - " + "path: " + module.path);
                }
            },
            onComplete: function () {
            }
        });
    }
}
✄
export declare function hook_func(so_name: any, addr: any): void;
export declare function _hook_func(so_name: any, func_name: any): void;

✄
{"version":3,"file":"hook_func.js","sourceRoot":"/home/thouger/Desktop/code/frida_script/","sources":["src/so/hook_func.ts"],"names":[],"mappings":"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"}
✄
//@ts-nocheck
export function hook_func(so_name, addr) {
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    if (android_dlopen_ext != null) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function (args) {
                var soName = args[0].readCString();
                console.log("soName: " + soName);
                if (soName.indexOf(so_name) != -1) {
                    this.hook = true;
                }
            },
            onLeave: function (retval) {
                if (this.hook)
                    _hook_func(so_name, addr);
            }
        });
    }
}
export function _hook_func(so_name, func_name) {
    console.log('find so');
    var so_addr = Module.findBaseAddress(so_name);
    console.log('so_addr: ' + so_addr);
    var func = Module.findExportByName(so_name, func_name);
    console.log("[+] Hooking function: " + func);
    Java.perform(function () {
        Interceptor.attach(func, {
            onEnter: function (args) {
                console.log('enter');
                // console.log(hexdump(this.context.PC))
                // console.log("args[0] Intercepted: " + hexdump(args[0]))
                // console.log("args[0] Intercepted: " + readStdString(args[1]))
                // console.log("args[2] Intercepted: " + args[2])
                // console.log("args[3] Intercepted: " + hexdump(args[3]))
                // console.log("args[4] Intercepted: " + hexdump(args[4]))
                // console.log("args[5] Intercepted: " + hexdump(args[5]))
                // console.log("args[6] Intercepted: " + hexdump(args[6]))
                // console.log("args[7] Intercepted: " + hexdump(args[7]))
                // console.log("args[8] Intercepted: " + hexdump(args[8]))
                // console.log("args[9] Intercepted: " + hexdump(args[9]))
                // console.log("args[10] Intercepted: " + hexdump(args[10]))
                // console.log("args[11] Intercepted: " + hexdump(args[11]))
                // console.log("args[12] Intercepted: " + hexdump(args[12]))
                console.log('*********************\nCCCryptorCreate called from:\n*********************' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
            },
            onLeave: function (retval) {
                console.log("[+] Returned: " + hexdump(retval));
                // console.log("retval is :", retval)
                return retval;
            }
        });
    });
}
function readStdString(str) {
    // console.log(Memory.readCString(str));
    // console.log(Memory.readUtf8String(str));
    return Memory.readUtf8String(str);
}
function print_dump(addr, size) {
    //console(Memory.methods());
    var buf = Memory.readByteArray(addr, size);
    console.log("[function] send[*] " + addr.toString() + "  " + "length: " + size.toString() + "\n[data]");
    console.log(hexdump(buf, {
        offset: 0,
        length: size,
        header: false,
        ansi: false
    }));
    console.log("");
}
✄
export declare function init_array(): void;

✄
{"version":3,"file":"init_array.js","sourceRoot":"/home/thouger/Desktop/code/frida_script/","sources":["src/so/init_array.ts"],"names":[],"mappings":"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"}
✄
//@ts-nocheck
export function init_array() {
    if (Process.pointerSize == 4) {
        var linker = Process.findModuleByName("linker");
    }
    else {
        var linker = Process.findModuleByName("linker64");
    }
    var addr_call_function = null;
    var addr_g_ld_debug_verbosity = null;
    var addr_async_safe_format_log = null;
    if (linker) {
        //console.log("found linker");
        var symbols = linker.enumerateSymbols();
        for (var i = 0; i < symbols.length; i++) {
            var name = symbols[i].name;
            if (name.indexOf("call_function") >= 0) {
                addr_call_function = symbols[i].address;
                // console.log("call_function",JSON.stringify(symbols[i]));
            }
            else if (name.indexOf("g_ld_debug_verbosity") >= 0) {
                addr_g_ld_debug_verbosity = symbols[i].address;
                ptr(addr_g_ld_debug_verbosity).writeInt(2);
            }
            else if (name.indexOf("async_safe_format_log") >= 0 && name.indexOf('va_list') < 0) {
                // console.log("async_safe_format_log",JSON.stringify(symbols[i]));
                addr_async_safe_format_log = symbols[i].address;
            }
        }
    }
    if (addr_async_safe_format_log) {
        Interceptor.attach(addr_async_safe_format_log, {
            onEnter: function (args) {
                this.log_level = args[0];
                this.tag = ptr(args[1]).readCString();
                this.fmt = ptr(args[2]).readCString();
                if (this.fmt.indexOf("c-tor") >= 0 && this.fmt.indexOf('Done') < 0) {
                    this.function_type = ptr(args[3]).readCString(), // func_type
                        this.so_path = ptr(args[5]).readCString();
                    var strs = new Array(); //定义一数组
                    strs = this.so_path.split("/"); //字符分割
                    this.so_name = strs.pop();
                    this.func_offset = ptr(args[4]).sub(Module.findBaseAddress(this.so_name));
                    console.log("func_type:", this.function_type, '\nso_name:', this.so_name, '\nso_path:', this.so_path, '\nfunc_offset:', this.func_offset);
                    // hook代码在这加
                }
            },
            onLeave: function (retval) {
            }
        });
    }
}
// setTimeout(init_array)
✄
export declare function inline_hook(so_name: any, addr: any): void;
export declare function _inline_hook(so_name: any, addr: any): void;

✄
{"version":3,"file":"inlinehook.js","sourceRoot":"/home/thouger/Desktop/code/frida_script/","sources":["src/so/inlinehook.ts"],"names":[],"mappings":"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"}
✄
//@ts-nocheck
export function inline_hook(so_name, addr) {
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    if (android_dlopen_ext != null) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function (args) {
                var soName = args[0].readCString();
                if (soName.indexOf(so_name) != -1) {
                    this.hook = true;
                }
            },
            onLeave: function (retval) {
                if (this.hook)
                    _inline_hook(so_name, addr);
            }
        });
    }
}
export function _inline_hook(so_name, addr) {
    console.log('find so');
    var so_addr = Module.findBaseAddress(so_name);
    console.log('so_addr: ' + so_addr);
    var func = so_addr.add(addr);
    console.log("[+] Hooking function: " + func);
    Java.perform(function () {
        Interceptor.attach(func, {
            onEnter: function (args) {
                console.log('enter');
                // console.log(hexdump(this.context.PC))
                // console.log("args[0] Intercepted: " + hexdump(args[0]))
                // console.log("args[0] Intercepted: " + readStdString(args[1]))
                // console.log("args[2] Intercepted: " + args[2])
                // console.log("args[3] Intercepted: " + hexdump(args[3]))
                // console.log("args[4] Intercepted: " + hexdump(args[4]))
                // console.log("args[5] Intercepted: " + hexdump(args[5]))
                // console.log("args[6] Intercepted: " + hexdump(args[6]))
                // console.log("args[7] Intercepted: " + hexdump(args[7]))
                // console.log("args[8] Intercepted: " + hexdump(args[8]))
                // console.log("args[9] Intercepted: " + hexdump(args[9]))
                // console.log("args[10] Intercepted: " + hexdump(args[10]))
                // console.log("args[11] Intercepted: " + hexdump(args[11]))
                // console.log("args[12] Intercepted: " + hexdump(args[12]))
                console.log('*********************\nCCCryptorCreate called from:\n*********************' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
            },
            onLeave: function (retval) {
                console.log("[+] Returned: " + hexdump(retval));
                // console.log("retval is :", retval)
                return retval;
            }
        });
    });
}
function readStdString(str) {
    // console.log(Memory.readCString(str));
    // console.log(Memory.readUtf8String(str));
    return Memory.readUtf8String(str);
}
function print_dump(addr, size) {
    //console(Memory.methods());
    var buf = Memory.readByteArray(addr, size);
    console.log("[function] send[*] " + addr.toString() + "  " + "length: " + size.toString() + "\n[data]");
    console.log(hexdump(buf, {
        offset: 0,
        length: size,
        header: false,
        ansi: false
    }));
    console.log("");
}
✄
export {};

✄
{"version":3,"file":"scan.js","sourceRoot":"/home/thouger/Desktop/code/frida_script/","sources":["src/so/scan.ts"],"names":[],"mappings":"AAAA,gBAAgB;AAChB,0FAA0F;AAC1F,2BAA2B;;AAE3B,uEAAuE;AAEvE,+FAA+F;AAC/F,4EAA4E;AAC5E,oLAAoL;AACpL,aAAa;AACb,qCAAqC;AACrC,qBAAqB;AACrB,sCAAsC;AACtC,aAAa;AACb,oCAAoC;AACpC,qCAAqC;AACrC,YAAY;AACZ,UAAU;AACV,IAAI;AAEJ,iEAAiE;AACjE,iFAAiF"}
✄
// //@ts-nocheck
// var _m = Process.enumerateModules();// enumerate loaded modules and take the first on_m
// for (var module of _m) {
export {};
//     var pattern = 'C7 C7 65 47 65 74 44 65  78 44 61 74 61 00 35 30'
//     Memory.scan(/*NativePointer*/ module.base, /*number*/ module.size, /*string*/ pattern, {
//         onMatch: function (address, size) {// called when pattern matches
//             console.log("Memory.scan() found at " + address +'Module name: ' + module.name + " - " + "Base Address: " + module.base.toString() + " - " + "path: " + module.path);
//         },
//         onError: function(reason){
//             //搜索失败
//             // console.log('搜索失败');
//         },
//         onComplete: function () {
//             // console.log("搜索完毕")
//         }
//     });
// }
//     // var results = Memory.scanSync(m.base, m.size, pattern);
//     // console.log("Memory.scanSync() result = \n" + JSON.stringify(results));
✄
export declare function sktrace(so_name: any): void;

✄
{"version":3,"file":"sktrace.js","sourceRoot":"/home/thouger/Desktop/code/frida_script/","sources":["src/so/sktrace/sktrace.ts"],"names":[],"mappings":"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"}
✄
//@ts-nocheck
import { hook_dlopen } from "../utils.js";
const arm64CM = new CModule(`
#include <gum/gumstalker.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void on_message(const gchar *message);
static void log(const gchar *format, ...);
static void on_arm64_before(GumCpuContext *cpu_context, gpointer user_data);
static void on_arm64_after(GumCpuContext *cpu_context, gpointer user_data);

void hello() {
    on_message("Hello form CModule");
}

gpointer shared_mem[] = {0, 0};

gpointer 
get_shared_mem() 
{
    return shared_mem;
}


static void
log(const gchar *format, ...)
{
    gchar *message;
    va_list args;

    va_start(args, format);
    message = g_strdup_vprintf(format, args);
    va_end(args);

    on_message(message);
    g_free(message);
}


void transform(GumStalkerIterator *iterator,
               GumStalkerOutput *output,
               gpointer user_data)
{
    cs_insn *insn;

    gpointer base = *(gpointer*)user_data;
    gpointer end = *(gpointer*)(user_data + sizeof(gpointer));
    
    while (gum_stalker_iterator_next(iterator, &insn))
    {
        gboolean in_target = (gpointer)insn->address >= base && (gpointer)insn->address < end;
        if(in_target)
        {
            log("%p\t%s\t%s", (gpointer)insn->address, insn->mnemonic, insn->op_str);
            gum_stalker_iterator_put_callout(iterator, on_arm64_before, (gpointer) insn->address, NULL);
        }
        gum_stalker_iterator_keep(iterator);
        if(in_target) 
        {
            gum_stalker_iterator_put_callout(iterator, on_arm64_after, (gpointer) insn->address, NULL);
        }
    }
}


const gchar * cpu_format = "
    0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x
    ";

static void
on_arm64_before(GumCpuContext *cpu_context,
        gpointer user_data)
{

}

static void
on_arm64_after(GumCpuContext *cpu_context,
        gpointer user_data)
{

}

`, {
    on_message: new NativeCallback(messagePtr => {
        const message = messagePtr.readUtf8String();
        console.log(message);
        // send(message)
    }, 'void', ['pointer']),
});
const userData = Memory.alloc(Process.pageSize);
function stalkerTraceRangeC(tid, base, size) {
    // const hello = new NativeFunction(cm.hello, 'void', []);
    // hello();
    userData.writePointer(base);
    const pointerSize = Process.pointerSize;
    userData.add(pointerSize).writePointer(base.add(size));
    Stalker.follow(tid, {
        transform: arm64CM.transform,
        // onEvent: cm.process,
        data: userData /* user_data */
    });
}
function stalkerTraceRange(tid, base, size) {
    Stalker.follow(tid, {
        transform: (iterator) => {
            const instruction = iterator.next();
            const startAddress = instruction.address;
            const isModuleCode = startAddress.compare(base) >= 0 &&
                startAddress.compare(base.add(size)) < 0;
            // const isModuleCode = true;
            do {
                iterator.keep();
                if (isModuleCode) {
                    send({
                        type: 'inst',
                        tid: tid,
                        block: startAddress,
                        val: JSON.stringify(instruction)
                    });
                    iterator.putCallout((context) => {
                        send({
                            type: 'ctx',
                            tid: tid,
                            val: JSON.stringify(context)
                        });
                    });
                }
            } while (iterator.next() !== null);
        }
    });
}
function traceAddr(addr) {
    let moduleMap = new ModuleMap();
    let targetModule = moduleMap.find(addr);
    console.log(JSON.stringify(targetModule));
    let exports = targetModule.enumerateExports();
    let symbols = targetModule.enumerateSymbols();
    // send({
    //     type: "module", 
    //     targetModule
    // })
    // send({
    //     type: "sym",
    // })
    Interceptor.attach(addr, {
        onEnter: function (args) {
            this.tid = Process.getCurrentThreadId();
            // stalkerTraceRangeC(this.tid, targetModule.base, targetModule.size)
            stalkerTraceRange(this.tid, targetModule.base, targetModule.size);
        },
        onLeave: function (ret) {
            Stalker.unfollow(this.tid);
            Stalker.garbageCollect();
            send({
                type: "fin",
                tid: this.tid
            });
        }
    });
}
function traceSymbol(symbol) {
}
/**
 * from jnitrace-egine
 */
function watcherLib(libname, callback) {
    const dlopenRef = Module.findExportByName(null, "dlopen");
    const dlsymRef = Module.findExportByName(null, "dlsym");
    const dlcloseRef = Module.findExportByName(null, "dlclose");
    if (dlopenRef !== null && dlsymRef !== null && dlcloseRef !== null) {
        const dlopen = new NativeFunction(dlopenRef, "pointer", ["pointer", "int"]);
        Interceptor.replace(dlopen, new NativeCallback((filename, mode) => {
            const path = filename.readCString();
            const retval = dlopen(filename, mode);
            if (path !== null) {
                if (checkLibrary(path)) {
                    // eslint-disable-next-line @typescript-eslint/no-base-to-string
                    trackedLibs.set(retval.toString(), true);
                }
                else {
                    // eslint-disable-next-line @typescript-eslint/no-base-to-string
                    libBlacklist.set(retval.toString(), true);
                }
            }
            return retval;
        }, "pointer", ["pointer", "int"]));
    }
}
function _sktrace(so_name) {
    const targetModule = Module.getBaseAddress(so_name);
    console.log("targetModule:", targetModule);
    // if("symbol" in payload) {
    //     targetAddress = targetModule.findExportByName(payload.symbol);
    // } else if("offset" in payload) {
    //     targetAddress = targetModule.base.add(ptr(payload.offset));
    // }
    var targetAddress = targetModule.add(ptr(0x1208));
    traceAddr(targetAddress);
}
export function sktrace(so_name) {
    hook_dlopen(so_name, _sktrace, so_name);
}
✄
export declare function so_info(so_name: any): void;

✄
{"version":3,"file":"so_info.js","sourceRoot":"/home/thouger/Desktop/code/frida_script/","sources":["src/so/so_info.ts"],"names":[],"mappings":"AAAA,aAAa;AAEb,MAAM,UAAU,OAAO,CAAC,OAAO;IAC3B,KAAK;IACL,IAAI,OAAO,GAAG,MAAM,CAAC,oBAAoB,CAAC,OAAO,CAAC,CAAC;IACnD,KAAK,IAAI,CAAC,GAAG,CAAC,EAAE,CAAC,GAAG,OAAO,CAAC,MAAM,EAAE,CAAC,EAAE,EAAE;QACrC,OAAO,CAAC,GAAG,CAAC,SAAS,GAAC,OAAO,CAAC,CAAC,CAAC,CAAC,IAAI,GAAG,IAAI,GAAG,OAAO,CAAC,CAAC,CAAC,CAAC,OAAO,GAAC,IAAI,CAAC,CAAA;KAC1E;IAED,KAAK;IACL,IAAI,OAAO,GAAG,MAAM,CAAC,oBAAoB,CAAC,OAAO,CAAC,CAAC;IACnD,KAAK,IAAI,CAAC,GAAG,CAAC,EAAE,CAAC,GAAG,OAAO,CAAC,MAAM,EAAE,CAAC,EAAE,EAAE;QACrC,OAAO,CAAC,GAAG,CAAC,QAAQ,GAAC,OAAO,CAAC,CAAC,CAAC,CAAC,IAAI,GAAG,IAAI,GAAG,OAAO,CAAC,CAAC,CAAC,CAAC,OAAO,GAAC,IAAI,CAAC,CAAC;KAC1E;AACL,CAAC"}
✄
//@ts-nocheck
export function so_info(so_name) {
    // 导入
    var imports = Module.enumerateImportsSync(so_name);
    for (var i = 0; i < imports.length; i++) {
        console.log('import:' + imports[i].name + ": " + imports[i].address + '\n');
    }
    // 导出
    var exports = Module.enumerateExportsSync(so_name);
    for (var i = 0; i < exports.length; i++) {
        console.log('export' + exports[i].name + ": " + exports[i].address + '\n');
    }
}
✄
export declare function so_method(so_name: string): void;

✄
{"version":3,"file":"so_method.js","sourceRoot":"/home/thouger/Desktop/code/frida_script/","sources":["src/so/so_method.ts"],"names":[],"mappings":"AACA,aAAa;AACb,OAAO,EAAE,GAAG,EAAE,MAAM,iBAAiB,CAAC;AACtC,OAAO,EAAC,WAAW,EAAC,MAAM,YAAY,CAAC;AAGvC,MAAM,UAAU,SAAS,CAAC,OAAc;IACpC,WAAW,CAAC,OAAO,EAAC;QAChB,IAAI,MAAM,GAAG,EAAE,CAAA;QACf,MAAM,aAAa,GAAG,MAAM,CAAC,gBAAgB,CAAC,OAAO,CAAC,CAAA;QACtD,aAAa,CAAC,OAAO,CAAC,CAAC,OAAyB,EAAE,EAAE;YAChD,MAAM,IAAI,iBAAiB,OAAO,CAAC,IAAI,IAAI,CAAC;QAChD,CAAC,CAAC,CAAC;QAEH,MAAM,cAAc,GAAG,MAAM,CAAC,gBAAgB,CAAC,OAAO,CAAC,CAAA;QACvD,cAAc,CAAC,OAAO,CAAC,CAAC,OAAyB,EAAE,EAAE;YACjD,MAAM,IAAI,iBAAiB,OAAO,CAAC,IAAI,IAAI,CAAC;QAChD,CAAC,CAAC,CAAC;QAEH,MAAM,aAAa,GAAG,MAAM,CAAC,gBAAgB,CAAC,kBAAkB,CAAC,CAAA;QACjE,aAAa,CAAC,OAAO,CAAC,CAAC,OAAyB,EAAE,EAAE;YAChD,MAAM,IAAI,iBAAiB,OAAO,CAAC,IAAI,IAAI,CAAC;QAChD,CAAC,CAAC,CAAC;QACH,GAAG,CAAC,MAAM,CAAC,CAAA;IACf,CAAC,CAAC,CAAA;AACN,CAAC"}
✄
//@ts-nocheck
import { log } from "../utils/log.js";
import { hook_dlopen } from "./utils.js";
export function so_method(so_name) {
    hook_dlopen(so_name, function () {
        var output = '';
        const export_method = Module.enumerateExports(so_name);
        export_method.forEach((element) => {
            output += `export method:${element.name}\n`;
        });
        const symbols_method = Module.enumerateSymbols(so_name);
        symbols_method.forEach((element) => {
            output += `export method:${element.name}\n`;
        });
        const improt_method = Module.enumerateImports('libencryptlib.so');
        improt_method.forEach((element) => {
            output += `export method:${element.name}\n`;
        });
        log(output);
    });
}
✄
export declare function stalker(_so_name: any, addr: any): void;
export declare function native_trace(_so_name: any, addr: any, size: any): void;

✄
{"version":3,"file":"stalker.js","sourceRoot":"/home/thouger/Desktop/code/frida_script/","sources":["src/so/stalker.ts"],"names":[],"mappings":"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"}
✄
//@ts-nocheck
import { log } from "../utils/log.js";
import { hook_dlopen } from "./utils.js";
var so_name;
export function stalker(_so_name, addr) {
    so_name = _so_name;
    hook_dlopen(so_name, _stalker, addr);
}
export function native_trace(_so_name, addr, size) {
    so_name = _so_name;
    hook_dlopen(so_name, _trace, addr, size);
}
function stalkerTraceRange(tid, base, size) {
    Stalker.follow(tid, {
        transform: (iterator) => {
            const instruction = iterator.next();
            const startAddress = instruction.address;
            const isModuleCode = startAddress.compare(base) >= 0 &&
                startAddress.compare(base.add(size)) < 0;
            // const isModuleCode = true;
            //transform是每个block触发。这里每个block触发的时候遍历出所有指令。
            do {
                iterator.keep();
                if (isModuleCode) {
                    //这里可以看到数据如果是inst就是一个指令，我们就需要解析打印
                    //输出样本如下
                    //'payload': {'type': 'inst', 'tid': 19019, 'block': '0x74fd8d4ff4', 'val': '{"address":"0x74fd8d4ffc","next":"0x4","size":4,"mnemonic":"add","opStr":"sp, sp, #0x70","operands":[{"type":"reg","value":"sp"},{"type":"reg","value":"sp"},{"type":"imm","value":"112"}],"regsRead":[],"regsWritten":[],"groups":[]}'}}
                    //py解析打印格式"add sp, sp, #0x70  //sp=112"        这里的处理应该还要更复杂。暂时先简单处理
                    log(instruction);
                    //这里是打印所有寄存器
                    //输出样本如下
                    //{'type': 'ctx', 'tid': 19019, 'val': '{"pc":"0x74fd8d4fe8","sp":"0x7fc28609d0","x0":"0x0","x1":"0x7fc2860908","x2":"0x0","x3":"0x756aec1349","x4":"0x7fc28608f0","x5":"0x14059dbe","x6":"0x7266206f6c6c6548","x7":"0x2b2b43206d6f7266","x8":"0x0","x9":"0x65af2e18847fd289","x10":"0x1","x11":"0x7fc2860a20","x12":"0xe","x13":"0x7fc2860a20","x14":"0xffffff0000000000","x15":"0x756aeed1b5","x16":"0x74fd8fadc8","x17":"0x74fd8d50d8","x18":"0x75f0bda000","x19":"0x75f02f9c00","x20":"0x756af59490","x21":"0x75f02f9c00","x22":"0x7fc2860c90","x23":"0x74ffcee337","x24":"0x4","x25":"0x75f04b4020","x26":"0x75f02f9cb0","x27":"0x1","x28":"0x756b3f2000","fp":"0x7fc2860a30","lr":"0x74fd8d4fdc"}'}}
                    //这里是寄存器变化时调用
                    iterator.putCallout((context) => {
                        log(JSON.stringify(context));
                    });
                }
            } while (iterator.next() !== null);
        }
    });
}
function _trace(addr, size) {
    var size = size || 0x1000;
    var base_addr = Module.getBaseAddress(so_name);
    console.log("base_addr:", base_addr);
    var func = base_addr.add(addr);
    console.log("func:", func);
    Interceptor.attach(func, {
        onEnter: function (args) {
            this.tid = Process.getCurrentThreadId();
            stalkerTraceRange(this.tid, func, size);
        }, onLeave(retval) {
            Stalker.unfollow(this.tid);
        }
    });
}
function _stalker(addr) {
    var base_addr = Module.getBaseAddress(so_name);
    console.log("base_addr:", base_addr);
    var func = base_addr.add(addr);
    console.log("func:", func);
    Interceptor.attach(func, {
        onEnter: function (args) {
            this.tid = Process.getCurrentThreadId();
            // console.log("enter func tid:",this.tid);
            Stalker.follow(this.tid, {
                events: {
                    call: true,
                    // Other events:
                    ret: false,
                    exec: false,
                    //                   a lot of data
                    block: false,
                    compile: false // block compiled: useful for coverage
                },
                onCallSummary: function (summary) {
                    for (var iter in summary) {
                        try {
                            var module = Process.getModuleByAddress(ptr(iter));
                            if (module.name.indexOf(so_name) != -1) {
                                console.log("onCallSummary", iter, ptr(iter).sub(module.base));
                            }
                        }
                        catch (err) {
                        }
                    }
                },
                onReceive: function (events) {
                    console.log("enter onReceive");
                    var eventsData = Stalker.parse(events, {
                        annotate: true,
                        stringify: true
                    });
                    for (var idx in eventsData) {
                        var dataSp = eventsData[idx];
                        var addr1 = dataSp[1];
                        var addr2 = dataSp[2];
                        try {
                            var module1 = Process.getModuleByAddress(ptr(addr1));
                            if (module1.name.indexOf(so_name) != -1) {
                                var module2 = Process.getModuleByAddress(ptr(addr2));
                                // onReceive + call + so名字 + 调用的地址 + 被调用的地址
                                // 只有被调用函数地址是原so时，才可以减去基地址
                                if (module2.name.indexOf(so_name) != -1) {
                                    console.log("onReceive:", dataSp[0] + ",调用的so:", module1.name, ",调用函数地址:", ptr(addr1 - base_addr), ",被调用的so:", module2.name, ",被调用的函数地址:", ptr(addr2 - base_addr));
                                }
                                else {
                                    console.log("onReceive:", dataSp[0] + ",调用的so:", module1.name, ",调用函数地址:", ptr(addr1 - base_addr), ",被调用的so:", module2.name, ",被调用的函数地址:", base_addr);
                                }
                            }
                        }
                        catch (err) {
                            console.log("onReceive error", dataSp[0], dataSp[1], dataSp[2]);
                        }
                    }
                },
                transform: function (iterator) {
                    var instruction = iterator.next();
                    const startAddress = instruction.address;
                    // 从ida里面 找到 Java_com_baidu_searchbox_NativeBds_dae1 函数的 代码 在 0xE84 和 0x126C 之间
                    // var isModule = startAddress.compare(base_addr.add(addr)) >= 0 && startAddress.compare(base_addr.add(0x126C)) < 0;
                    var isModule = startAddress.compare(base_addr.add(addr)) >= 0;
                    do {
                        if (isModule) {
                            console.log(instruction.address.sub(base_addr) + "\t:\t" + instruction);
                            if (instruction.address.sub(base_addr) == 0x122c) {
                                iterator.putCallout((context) => {
                                    // var string = Memory.readCString(context["sp"]);
                                    // console.log("####  key = " + string)
                                    console.log("####  key = " + Memory.readUInt(context.w0));
                                });
                            }
                        }
                        iterator.keep();
                    } while ((instruction = iterator.next()) !== null);
                },
            });
        }, onLeave(retval) {
            Stalker.unfollow(this.tid);
        }
    });
}
✄
export declare function hook_dlopen(so_name: any, hook_func: any, args: any): void;

✄
{"version":3,"file":"utils.js","sourceRoot":"/home/thouger/Desktop/code/frida_script/","sources":["src/so/utils.ts"],"names":[],"mappings":"AAAA,aAAa;AACb,OAAO,EAAE,GAAG,EAAE,MAAM,iBAAiB,CAAC;AACtC,MAAM,UAAU,WAAW,CAAC,OAAO,EAAC,SAAS,EAAC,IAAI;IAC9C,GAAG,CAAC,aAAa,CAAC,CAAA;IAClB,IAAI,kBAAkB,GAAG,MAAM,CAAC,gBAAgB,CAAC,IAAI,EAAE,oBAAoB,CAAC,CAAC;IAC7E,IAAI,kBAAkB,IAAI,IAAI,EAAE;QAC5B,WAAW,CAAC,MAAM,CAAC,kBAAkB,EAAE;YACnC,OAAO,EAAE,UAAU,IAAI;gBACnB,IAAI,MAAM,GAAG,IAAI,CAAC,CAAC,CAAC,CAAC,WAAW,EAAE,CAAC;gBACnC,IAAI,MAAM,CAAC,OAAO,CAAC,OAAO,CAAC,IAAI,CAAC,CAAC,EAAE;oBAC/B,GAAG,CAAC,SAAS,CAAC,CAAA;oBACd,IAAI,CAAC,IAAI,GAAG,IAAI,CAAC;iBACpB;YACL,CAAC;YACD,OAAO,EAAE,UAAU,MAAM;gBACrB,IAAI,IAAI,CAAC,IAAI;oBACT,SAAS,CAAC,IAAI,CAAC,CAAE;YACzB,CAAC;SACJ,CAAC,CAAC;KACN;AACL,CAAC"}
✄
//@ts-nocheck
import { log } from "../utils/log.js";
export function hook_dlopen(so_name, hook_func, args) {
    log('hook_dlopen');
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    if (android_dlopen_ext != null) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function (args) {
                var soName = args[0].readCString();
                if (soName.indexOf(so_name) != -1) {
                    log('find so');
                    this.hook = true;
                }
            },
            onLeave: function (retval) {
                if (this.hook)
                    hook_func(args);
            }
        });
    }
}
✄
export declare function log(message: string): void;
export declare function stacktrace(): any;
export declare function print_byte(byte: any): any;
export declare function print_hashmap(hashmap: any): string | undefined;
export declare function native_print(so_name: any, so_addr: any): void;

✄
{"version":3,"file":"log.js","sourceRoot":"/home/thouger/Desktop/code/frida_script/","sources":["src/utils/log.ts"],"names":[],"mappings":"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"}
✄
// @ts-nocheck
import { hook_dlopen } from "../so/utils.js";
export function log(message) {
    let colorCode;
    switch (Math.floor(Math.random() * 6)) {
        case 0:
            colorCode = '\x1b[31m'; // 红色
            break;
        case 1:
            colorCode = '\x1b[32m'; // 绿色
            break;
        case 2:
            colorCode = '\x1b[33m'; // 黄色
            break;
        case 3:
            colorCode = '\x1b[35m'; // 紫色
            break;
        case 4:
            colorCode = '\x1b[36m'; // 青色
            break;
        case 5:
            colorCode = '\x1b[37m'; // 白色
            break;
        default:
            colorCode = '';
            break;
    }
    console.log(`${colorCode}${message}\x1b[0m`);
}
export function stacktrace() {
    return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
}
export function print_byte(byte) {
    var str = Java.use("java.lang.String").$new(byte);
    return str;
}
export function print_hashmap(hashmap) {
    if (!hashmap) {
        console.log('Invalid hashmap');
        return;
    }
    var output = "";
    var HashMapNode = Java.use('java.util.HashMap$Node');
    var iterator = hashmap.entrySet().iterator();
    while (iterator.hasNext()) {
        var entry = Java.cast(iterator.next(), HashMapNode);
        var key = entry.getKey();
        var value = entry.getValue();
        if (!key)
            key = 'null';
        if (!value)
            value = 'null';
        output += key.toString() + " => " + value.toString() + "\n";
    }
    // console.log(output); // 输出到 Frida 控制台
    return output; // 返回输出结果
}
export function native_print(so_name, so_addr) {
    function hexdumpMem(addr) {
        if (Process.findRangeByAddress(addr)) {
            return hexdump(ptr(addr), { length: 0x40 }) + "\r\n";
        }
        else {
            return ptr(addr) + "\r\n";
        }
    }
    //比较通用的hook地址并且打印5个参数。如果参数是地址就打印下内存信息
    function nativeHookFunction(addr) {
        var base_addr = Module.getBaseAddress(so_name);
        var hook_addr = base_addr.add(addr);
        console.log("hook_addr:", hook_addr);
        Interceptor.attach(hook_addr, {
            onEnter: function (args) {
                this.logs = [];
                this.logs.push("call", addr);
                this.arg0 = args[0];
                this.arg1 = args[1];
                this.arg2 = args[2];
                this.arg3 = args[3];
                this.arg4 = args[4];
                this.arg5 = args[5];
                this.logs.push("arg0:", hexdumpMem(this.arg0));
                this.logs.push("arg1:", hexdumpMem(this.arg1));
                this.logs.push("arg2:", hexdumpMem(this.arg2));
                this.logs.push("arg3:", hexdumpMem(this.arg3));
                this.logs.push("arg4:", hexdumpMem(this.arg4));
                this.logs.push("arg5:", hexdumpMem(this.arg5));
            }, onLeave: function (retval) {
                this.logs.push("arg0 leave:", hexdumpMem(this.arg0));
                this.logs.push("arg1 leave:", hexdumpMem(this.arg1));
                this.logs.push("arg2 leave:", hexdumpMem(this.arg2));
                this.logs.push("arg3 leave:", hexdumpMem(this.arg3));
                this.logs.push("arg4 leave:", hexdumpMem(this.arg4));
                this.logs.push("arg5 leave:", hexdumpMem(this.arg5));
                this.logs.push("retval leave:", hexdumpMem(retval));
                console.log(this.logs);
            }
        });
    }
    hook_dlopen(so_name, nativeHookFunction, so_addr);
}