//@ts-nocheck

import { log, print_hashmap, stacktrace } from "../utils/log.js";

function extractPackageName(path) {
    var startIndex = path.lastIndexOf('/');
    var endIndex = path.indexOf('/', startIndex + 1);
    if (startIndex !== -1 && endIndex !== -1) {
        return path.substring(startIndex + 1, endIndex);
    } else {
        return 'com.lazada.android'; // 无法提取包名时返回空字符串或其他默认值
    }
}

function traceMethod(targetMethod, unparseMethod) {

    var delim = targetMethod.lastIndexOf(".");
    var targetClass = targetMethod.slice(0, delim)
    var targetMethod = targetMethod.slice(delim + 1, targetMethod.length)
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
                output = output.concat("\n")
            }

            var retval = this[targetMethod].apply(this, arguments);
            // //返回值
            output = output.concat("\n retval: " + retval + " => " + JSON.stringify(retval));

            // 进入函数
            output = output.concat("*********entered " + unparseMethod + "********* \n");
            log("*********entered " + unparseMethod + "********* \n")

            output = output.concat("\n----------------------------------------\n")
            var stacktraceLog = stacktrace();
            if (targetMethod == "getDataDir" && stacktraceLog.indexOf("com.lazada.android") != -1) {
                var File = Java.use('java.io.File');
                var path = retval.getPath();
                if(path.indexOf('ratel') == -1){
                    var replacedPath = path + '/app_ratel_env_mock/default_0/data/';
                    output = output.concat("replace path is => ", replacedPath, "\n");
                    var file = File.$new(replacedPath);
                    log(output)
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
            output = output.concat("----------------------------------------\n")

            //离开函数
            output = output.concat("\n ********* exiting " + targetMethod + '*********\n');

            log(output)
            return retval;
        }
    }
}

export function _trace(targetClass, method) {
    var output = "Tracing Class: " + targetClass + "\n";
    var hook = Java.use(targetClass)
    var methods = hook.class.getDeclaredMethods()
    hook.$dispose()
    var methodsDict = {};

    methods.forEach(_method => {
        _method = _method.toString()

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
        } catch (error) {
            // console.log(error)
        }

        // log('\ntrace begin ... !')

        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    if (loader.findClass(target)) {
                        Java.classFactory.loader = loader;
                    }
                } catch (error) {
                    // console.log('enumerateClassLoaders error: ' + error + '\n')
                }
            },
            onComplete: function () {
            }
        })

        var targetClasses = new Array();
        Java.enumerateLoadedClasses({
            onMatch: function (clazz) {
                if (clazz.toLowerCase().indexOf(target.toLowerCase()) > -1) {
                    // if (clazz.toLowerCase() == target.toLowerCase()) {
                    targetClasses.push(clazz)
                    _trace(clazz, method)
                }
            },
            onComplete: function () {
            }
        })
    })
}