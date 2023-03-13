//@ts-nocheck

import { log } from "../utils/log";

function uniqBy(array, key) {
    var seen = {};
    return array.filter(function (item) {
        var k = key(item);
        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
    });
}

function hasOwnProperty(obj, name) {
    try {
        return obj.hasOwnProperty(name) || name in obj;
    } catch (e) {
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
    } else {
        var Class = Java.use("java.lang.Class");
        obj_class = Java.cast(obj.getClass(), Class);
        isInstance = true;
    }
    input = input.concat("Inspecting Fields: => ", isInstance, " => ", obj_class.toString());
    input = input.concat("\n")
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
            input = input.concat("\n\n")
        }
    }
    return input;
}

function traceMethod(targetClassMethod) {
    var delim = targetClassMethod.lastIndexOf(".");
    var targetClass = targetClassMethod.slice(0, delim)
    var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)
    var hook = Java.use(targetClass);
    //有时候会出现方法找不到的情况，这里try catch一下，直接返回
    try {
        var overloadCount = hook[targetMethod].overloads.length;
    } catch (e) {
        log("Class not found: " + targetClass);
        return;
    }

    log("Tracing Method : " + targetClassMethod + " [" + overloadCount + " overload(s)]");
    for (var i = 0; i < overloadCount; i++) {
        hook[targetMethod].overloads[i].implementation = function () {
            //初始化输出
            var output = "";
            //画个横线
            for (var p = 0; p < 100; p++) {
                output = output.concat("==");
            }
            //域值
            output = inspectObject(this, output);
            //进入函数
            output = output.concat("\n*** entered " + targetClassMethod);
            output = output.concat("\n")

            // output = output.concat("\n----------------------------------------\n")
            // var cls = "com.appsflyer.internal.AFf1bSDK"
            // var obj = Java.use(cls)
            // var csl2 = 'com.appsflyer.internal.AFa1xSDK$AFa1wSDK'
            // var obj2 = Java.use(csl2)

            // output = output.concat("value AFKeystoreWrapper "+obj2._AFKeystoreWrapper.value+'\n');
            // output = output.concat("value values "+obj2._values.value+'\n');
            // output = output.concat("value AFInAppEventType " + obj2._AFInAppEventType.value + '\n');
            // output = output.concat('value afInfoLog '+obj2.afInfoLog.value+'\n')
            // output = output.concat("value AFf1bSDK.AFInAppEventType " + obj.AFInAppEventType.value + '\n');
            // output = output.concat("value AFf1bSDK.valueOf " + obj.valueOf.value + '\n');
            // output = output.concat("value AFf1bSDK.AFInAppEventParameterName " + obj.AFInAppEventParameterName.value + '\n');
            // output = output.concat("value AFf1bSDK.AFKeystoreWrapper " + obj.AFKeystoreWrapper.value + '\n');
            // output = output.concat(arguments[-1]+'\n')
            // output = output.concat("----------------------------------------\n")

            //参数
            var retval = this[targetMethod].apply(this, arguments);
            for (var j = 0; j < arguments.length; j++) {
                output = output.concat("arg[" + j + "]: " + arguments[j] + " => " + JSON.stringify(arguments[j]));
                output = output.concat("\n")
            }
            //调用栈
            output = output.concat(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
            //返回值
            output = output.concat("\nretval: " + retval + " => " + JSON.stringify(retval));
            // inspectObject(this)
            //离开函数
            output = output.concat("\n*** exiting " + targetClassMethod);

            //调用函数

            // output = output.concat("\n----------------------------------------\n")
            // var cls = "com.appsflyer.internal.AFf1bSDK"
            // var obj = Java.use(cls)
            // var csl2 = 'com.appsflyer.internal.AFa1xSDK$AFa1wSDK'
            // var obj2 = Java.use(csl2)

            // output = output.concat("value AFKeystoreWrapper "+obj2._AFKeystoreWrapper.value+'\n');
            // output = output.concat("value values "+obj2._values.value+'\n');
            // output = output.concat('value afInfoLog '+obj2.afInfoLog.value+'\n')
            // output = output.concat("value AFInAppEventType " + obj2._AFInAppEventType.value + '\n');
            // output = output.concat("value AFf1bSDK.AFInAppEventType " + obj.AFInAppEventType.value + '\n');
            // output = output.concat("value AFf1bSDK.valueOf " + obj.valueOf.value + '\n');
            // output = output.concat("value AFf1bSDK.AFInAppEventParameterName " + obj.AFInAppEventParameterName.value + '\n');
            // output = output.concat("value AFf1bSDK.AFKeystoreWrapper " + obj.AFKeystoreWrapper.value + '\n');
            // output = output.concat(arguments[-1]+'\n')
            // output = output.concat("----------------------------------------\n")

            log(output)

            // var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            // log(hex2str(ByteString.of(retval).hex()))
            return retval;
        }
    }
}

function hex2str(hex) {
    var trimedStr = hex.trim();
    var rawStr = trimedStr.substr(0, 2).toLowerCase() === "0x" ? trimedStr.substr(2) : trimedStr;
    var len = rawStr.length;
    if (len % 2 !== 0) {
        return "";
    }
    var curCharCode;
    var resultStr = [];
    for (var i = 0; i < len; i = i + 2) {
        curCharCode = parseInt(rawStr.substr(i, 2), 16);
        resultStr.push(String.fromCharCode(curCharCode));
    }
    return resultStr.join("");
}

function _trace(target, method) {
    var output = "";
    output = output.concat("Tracing Class : " + target + " \n");
    var hook = Java.use(target)
    var methods = hook.class.getDeclaredMethods()
    hook.$dispose()
    var parsedMethods = [];
    output = output.concat("\t\nSpec: => \n")
    methods.forEach(_method => {
        _method = _method.toString()
        if (method)
            if (_method.toLowerCase().indexOf(method.toLowerCase()) == -1)
                continue;
        output = output.concat(method + "\n")
        parsedMethods.push(_method.replace(target + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
    });

    output = output.concat(parsedMethods)
    //去掉一些重复的值
    var Targets = uniqBy(parsedMethods, JSON.stringify);
    // targets = [];
    var constructors = hook.class.getDeclaredConstructors();
    if (method != undefined && constructors.length > 0 && method.toLowerCase().indexOf("init") != -1) {
        constructors.forEach(function (constructor) {
            output = output.concat("Tracing ", constructor.toString())
            output = output.concat("\n\n")
        })
        Targets = Targets.concat("$init")
    }
    //对数组中所有的方法进行hook，
    Targets.forEach(function (targetMethod) {
        traceMethod(target + "." + targetMethod);
    });
    //画个横线
    for (var p = 0; p < 100; p++) {
        output = output.concat("+");
    }
    log(output);
}

export function trace(target, method) {
    Java.perform(function () {
        //有一种特殊的情况，需要use一下，才能hook到
        try {
            Java.use(target);
        } catch (error) {
            // console.log(error)
        }

        log('\ntrace begin ... !')

        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    // console.log(loader)
                    if (loader.findClass(target)) {
                        log("Successfully found loader")
                        Java.classFactory.loader = loader;
                        log("Switch Classloader Successfully ! ")
                    }
                } catch (error) {
                    // console.log('enumerateClassLoaders error: ' + error + '\n')
                }
            },
            onComplete: function () {
                log("EnumerateClassloader END")
            }
        })

        log('Begin enumerateClasses ...')
        Java.enumerateLoadedClasses({
            onMatch: function (clazz) {
                // if (clazz.toLowerCase().indexOf(target.toLowerCase()) > -1) {
                if (clazz.toLowerCase() == target.toLowerCase()) {
                    log('find target class: ' + clazz)
                    _trace(clazz, method)
                }
            },
            onComplete: function () {
                log("Search Class Completed!")
            }
        })
    })
}