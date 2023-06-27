(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const trace_change_1 = require("./java/trace_change");
// import { one_instance } from "./java/one_instance";
// import { encryption } from "./java/encryption";
// import { findClass } from "./java/findClass";
// import {anti_InMemoryDexClassLoader} from './java/anti_InMemoryDexClassLoader';
// setTimeout(all_so,5000)
// so_info('libsscronet.so')
// inline_hook('libOnLoad.so',0x9E0)
// init_array()
// scan()
// all_so()
///////////////java
(0, trace_change_1.trace_change)('com.lazada.android.cpx.task.a', 'c');
(0, trace_change_1.trace_change)('com.lazada.android.cpx.o', 'a');
// trace('а.б.а.а.а.г.а')
// trace('java.io.File')
// hook_file()
// trace('com.alibaba.wireless.security.open.SecException')
// trace('com.uc.crashsdk.JNIBridge')
// trace('dalvik.system.BaseDexClassLoader')
// setTimeout(trace,1000,'com.appsflyer.internal.AFa1xSDK$AFa1wSDK','values')
// hook_hashmap()
// trace('java.util.HashMap','put')
// trace('java.lang.ClassLoader','findClass')
// trace('ava.lang.reflect.Method','invoke')
// hook_string()
// encryption()
// findClass('com.appsflyer.internal.AFa1nSDK$30218')
// anti_InMemoryDexClassLoader()
// console.log("Loading script...");
//
// var getaddrinfoPtr = Module.findExportByName(null, 'getaddrinfo')
// var connectPtr = Module.findExportByName(null, 'connect')
// var sendPtr = Module.findExportByName(null, 'send')
// var recvPtr = Module.findExportByName(null, 'recv')
//
// var getaddrinfoFunction = new NativeFunction(getaddrinfoPtr, 'int', ['pointer', 'pointer', 'pointer', 'pointer'])
// var connectFunction = new NativeFunction(connectPtr, 'int', ['int', 'pointer', 'int'])
// var sendFunction = new NativeFunction(sendPtr, 'int', ['int', 'pointer', 'int', 'int'])
// var recvFunction = new NativeFunction(recvPtr, 'int', ['int', 'pointer', 'int', 'int'])
//
// /**
//  * Returns hex from an ArrayBuffer object
//  * @param {ArrayBuffer} array Array to work with
//  * @param {Boolean} hex Whether to convert to hex or plain string
//  */
// function getReadable(array, hex) {
//     var result = new Uint8Array(array.byteLength)
//     result.set(array, 0)
//     if (hex == false) {
//         var str = ''
//         for (var i = 0; i < result.length; i++) {
//             str += String.fromCharCode(result[i])
//         }
//         return str
//     }
//     else {
//         var hexStr = ''
//         for (var i = 0; i < result.length; i++) {
//             hexStr += result[i].toString(16)
//         }
//         return hexStr
//     }
// }
//
// /**
//  * Returns a nice formatting of a function with parameters
//  * @param {string} functionName The name of the function to format
//  * @param {string[]} params The function parameters as strings
//  */
// function formatFunction(functionName, params, retval) {
//     var result = ''
//     result += functionName
//     result += '('
//     for (var i = 0; i < params.length; i++) {
//         if (i != 0) {
//             result += ', '
//         }
//         result += params[i]
//     }
//     result += ')'
//     if (retval) {
//         result += ' -> '
//         result += retval
//     }
//     return result
// }
//
// function replaceGadp() {
//     Interceptor.replace(getaddrinfoPtr, new NativeCallback(function (name, service, req, pai) {
//         var nameStr = Memory.readUtf8String(name)
//         console.log(formatFunction('getaddrinfo', [nameStr, service, req, pai]))
//         return getaddrinfoFunction(name, service, req, pai)
//     }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']))
// }
//
// function replaceConnect() {
//     Interceptor.replace(connectPtr, new NativeCallback(function (socket, address, addressLen) {
//         var endpoint = {
//             ip: '',
//             port: 0
//         }
//         var portPtr = ptr(parseInt(address) + 2)
//         var portHigh = Memory.readU8(portPtr)
//         var portLow = Memory.readU8(ptr(parseInt(portPtr) + 1))
//         endpoint.port = (portHigh & 0xFF) << 8 | (portLow & 0xFF)
//
//         var ipPtr = ptr(parseInt(address) + 4)
//         var ip = []
//
//         ip.push(Memory.readU8(ipPtr))
//         ip.push(Memory.readU8(ptr(parseInt(ipPtr) + 1)))
//         ip.push(Memory.readU8(ptr(parseInt(ipPtr) + 2)))
//         ip.push(Memory.readU8(ptr(parseInt(ipPtr) + 3)))
//
//         endpoint.ip = ip.join('.')
//
//         var result = connectFunction(socket, address, addressLen)
//         console.log('CCCryptorCreate called from:\n' + Thread.backtrace(this.context, Backtracer.ACCURATE) .map(DebugSymbol.fromAddress).join('\n') + '\n');
//
//         // console.log(formatFunction('connect', [socket, JSON.stringify(endpoint), addressLen], result))
//         return result
//     }, 'int', ['int', 'pointer', 'int']))
// }
//
// function replaceSend() {
//     Interceptor.replace(sendPtr, new NativeCallback(function (fd, buf, len, flags) {
//         var buffer = Memory.readByteArray(buf, len)
//         var result = sendFunction(fd, buf, len, flags)
//         console.log(formatFunction('send', [fd, getReadable(buffer, false), len, flags], result))
//         return result
//     }, 'int', ['int', 'pointer', 'int', 'int']))
// }
//
// function replaceRecv() {
//     Interceptor.replace(recvPtr, new NativeCallback(function (fd, buf, len, flags) {
//         var result = recvFunction(fd, buf, len, flags)
//         if (result > -1) {
//             var buffer = Memory.readByteArray(buf, result)
//             console.log(formatFunction('recv', [fd, getReadable(buffer, false), len, flags], result))
//         }
//         else {
//             console.log(formatFunction('recv', [fd, null, len, flags], result))
//         }
//         return result
//     }, 'int', ['int', 'pointer', 'int', 'int']))
// }
//
// replaceGadp()
// replaceConnect()
// replaceSend()
// replaceRecv()
//
// console.log('Script loaded!')

},{"./java/trace_change":2}],2:[function(require,module,exports){
"use strict";
//@ts-nocheck
Object.defineProperty(exports, "__esModule", { value: true });
exports.trace_change = exports._trace = void 0;
const log_1 = require("../utils/log");
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
        (0, log_1.log)("Class not found: " + targetClass);
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
            (0, log_1.log)("*********entered " + unparseMethod + "********* \n");
            output = output.concat("\n----------------------------------------\n");
            var stacktraceLog = (0, log_1.stacktrace)();
            if (targetMethod == "getDataDir" && stacktraceLog.indexOf("com.lazada.android") != -1) {
                var File = Java.use('java.io.File');
                var path = retval.getPath();
                if (path.indexOf('ratel') == -1) {
                    var replacedPath = path + '/app_ratel_env_mock/default_0/data/';
                    output = output.concat("replace path is => ", replacedPath, "\n");
                    var file = File.$new(replacedPath);
                    (0, log_1.log)(output);
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
            (0, log_1.log)(output);
            return retval;
        };
    }
}
function _trace(targetClass, method) {
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
exports._trace = _trace;
function trace_change(target, method) {
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
exports.trace_change = trace_change;

},{"../utils/log":3}],3:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.print_hashmap = exports.stacktrace = exports.log = void 0;
// @ts-nocheck
function log(message) {
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
exports.log = log;
function stacktrace() {
    return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
}
exports.stacktrace = stacktrace;
function print_hashmap(hashmap) {
    var output = "";
    var HashMapNode = Java.use('java.util.HashMap$Node');
    var hashmap = Java.cast(hashmap, Java.use('java.util.HashMap'));
    var iterator = hashmap.entrySet().iterator();
    while (iterator.hasNext()) {
        var entry = Java.cast(iterator.next(), HashMapNode);
        output = output.concat(entry.getKey() + " => " + entry.getValue() + "\r");
    }
    return output;
}
exports.print_hashmap = print_hashmap;

},{}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC50cyIsImphdmEvdHJhY2VfY2hhbmdlLnRzIiwidXRpbHMvbG9nLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7QUNHQSxzREFBZ0Q7QUFRaEQsc0RBQXNEO0FBQ3RELGtEQUFrRDtBQUNsRCxnREFBZ0Q7QUFDaEQsa0ZBQWtGO0FBRWxGLDBCQUEwQjtBQUMxQiw0QkFBNEI7QUFDNUIsb0NBQW9DO0FBQ3BDLGVBQWU7QUFDZixTQUFTO0FBQ1QsV0FBVztBQUVYLG1CQUFtQjtBQUNuQixJQUFBLDJCQUFZLEVBQUMsK0JBQStCLEVBQUMsR0FBRyxDQUFDLENBQUE7QUFDakQsSUFBQSwyQkFBWSxFQUFDLDBCQUEwQixFQUFDLEdBQUcsQ0FBQyxDQUFBO0FBQzVDLHlCQUF5QjtBQUN6Qix3QkFBd0I7QUFFeEIsY0FBYztBQUNkLDJEQUEyRDtBQUMzRCxxQ0FBcUM7QUFDckMsNENBQTRDO0FBRTVDLDZFQUE2RTtBQUM3RSxpQkFBaUI7QUFDakIsbUNBQW1DO0FBQ25DLDZDQUE2QztBQUM3Qyw0Q0FBNEM7QUFDNUMsZ0JBQWdCO0FBQ2hCLGVBQWU7QUFDZixxREFBcUQ7QUFDckQsZ0NBQWdDO0FBRWhDLG9DQUFvQztBQUNwQyxFQUFFO0FBQ0Ysb0VBQW9FO0FBQ3BFLDREQUE0RDtBQUM1RCxzREFBc0Q7QUFDdEQsc0RBQXNEO0FBQ3RELEVBQUU7QUFDRixvSEFBb0g7QUFDcEgseUZBQXlGO0FBQ3pGLDBGQUEwRjtBQUMxRiwwRkFBMEY7QUFDMUYsRUFBRTtBQUNGLE1BQU07QUFDTiw0Q0FBNEM7QUFDNUMsbURBQW1EO0FBQ25ELG9FQUFvRTtBQUNwRSxNQUFNO0FBQ04scUNBQXFDO0FBQ3JDLG9EQUFvRDtBQUNwRCwyQkFBMkI7QUFDM0IsMEJBQTBCO0FBQzFCLHVCQUF1QjtBQUN2QixvREFBb0Q7QUFDcEQsb0RBQW9EO0FBQ3BELFlBQVk7QUFDWixxQkFBcUI7QUFD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
