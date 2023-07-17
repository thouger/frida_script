//@ts-nocheck

import { log, print_hashmap, stacktrace } from "../utils/log.js";
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
            input = input.concat("\n")
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

    //多个函数重载会有一个问题，当参数是Object[] objArr，不能给它赋值，因此需要单独重载特定参数函数
    //     hook["values"].overload('java.lang.String', 'java.lang.String', 'int').implementation = function (str, str2, i) {
    //     console.log(`AFa1xSDK.values is called: str=${str}, str2=${str2}, i=${i}`);
    //     let result = this["values"](str, str2, i);
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
            output = output.concat("\n")

            //域值
            output = inspectObject(this, output);
            // 进入函数
            output = output.concat("*********entered " + unparseMethod + "********* \n");

                    output = output.concat("\n----------------------------------------\n")
                    var context = this.c;
                    output.concat("context is => ",context,"\n");
                    // var dir = context.getDir("SGLib",0);
                    // output.concat("dir is => ",dir.getAbsolutePath(),"\n");
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

            for (var j = 0; j < arguments.length; j++) {
                output = output.concat("arg[" + j + "]: " + arguments[j] + " => " + JSON.stringify(arguments[j]));
                output = output.concat("\n")
            }
            //调用栈
            output = output.concat(stacktrace());
            var retval = this[targetMethod].apply(this, arguments);
            // //返回值
            output = output.concat("\n retval: " + retval + " => " + JSON.stringify(retval));

            //离开函数
            output = output.concat("\n ********* exiting " + targetMethod + '*********\n');

            //         //调用函数
            // output = output.concat("\n----------------------------------------\n")
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
            //         // output = output.concat("----------------------------------------\n")
            //画个横线
            for (var p = 0; p < 100; p++) {
                output = output.concat("==");
            }
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

    output += "\t\nSpec: => \n";
    methods.forEach(_method => {
        _method = _method.toString()

        output += _method + "\n";
        var parsedMethod = _method.replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1];
        console.log(111+method+222+parsedMethod+333+method.toLowerCase() === parsedMethod.toLowerCase())
        if (method.toLowerCase() === parsedMethod.toLowerCase())
        return;
        methodsDict[parsedMethod] = _method;
    });
    
    //去掉一些重复的值
    // var Targets = Object.values(methodsDict).flat().filter(function (value, index, self) {
    //     return self.indexOf(value) === index;
    //   });
    var Targets=methodsDict;
    //添加构造函数
    var constructors = hook.class.getDeclaredConstructors();
    if (constructors.length > 0) {
        constructors.forEach(function (constructor) {
            output += "Tracing " + constructor.toString() + "\n";
        })
        //有时候hook构造函数会报错，看情况取消
        // methodsDict["$init"]='$init';
    }
    log(output);

    //对数组中所有的方法进行hook，
    for (var parsedMethod in methodsDict) {
        var unparseMethod = methodsDict[parsedMethod];
        traceMethod(targetClass + "." + parsedMethod, unparseMethod);
    } 
}

export function trace(target, method) {
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
                    console.log(loader)
                    if (loader.findClass(target)) {
                        log("Successfully found loader")
                        log(loader)
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
        var targetClasses = new Array();
        Java.enumerateLoadedClasses({
            onMatch: function (clazz) {
                // console.log(clazz)
                // if (clazz.toLowerCase().indexOf(target.toLowerCase()) > -1) {
                    if (clazz.toLowerCase() == target.toLowerCase()) {
                    targetClasses.push(clazz)
                    log('find target class: ' + clazz)
                    _trace(clazz, method)
                }
            },
            onComplete: function () {
                log("Search Class Completed!")
            }
        })
        var output = "On Total Tracing :" + String(targetClasses.length) + " classes :\r\n";
        targetClasses.forEach(function (target) {
            output = output.concat(target);
            output = output.concat("\r\n")
        })
        log(output)
    })
}