//@ts-nocheck
import { log, print_hashmap,print_byte, stacktrace_java } from "../utils/log.js";

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

function print_bytes(bytes) {
    var buf  = Memory.alloc(bytes.length);
    Memory.writeByteArray(buf, byte_to_ArrayBuffer(bytes));
    console.log(hexdump(buf, {offset: 0, length: bytes.length, header: false, ansi: true}));
}
//将java的数组转换成js的数组
function byte_to_ArrayBuffer(bytes) {
    var size=bytes.length;
    var tmparray = [];
    for (var i = 0; i < size; i++) {
        var val = bytes[i];
        if(val < 0){
            val += 256;
        }
        tmparray[i] = val
    }
    return tmparray;
}

function getReflectFields(val1,output) {
    var clazz = Java.use("java.lang.Class");
    var parametersTest = Java.cast(val1.getClass(),clazz);
    //getDeclaredFields()获取所有字段
    var fields = parametersTest.getDeclaredFields();
    fields.forEach(function (field) {//依次打印字段的类型、名称、值
        output = output.concat("field type is: " + (field.getType())+"\n");
        output = output.concat("field name is: " + (field.getName())+"\n");
        output = output.concat("field value is: " + field.get(val1)+"\n");
    })
    return output;
  }

function getReflectMethod(val1) {
try{
    var clazz = Java.use("java.lang.Class");
    var parametersTest = Java.cast(val1.getClass(),clazz);
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
        if(proto.length > 1){
            proto = proto.substr(0 ,proto.length - 2);
        }
        proto += ")";
        overload.implementation = function () {
            var args = [];
            for(var j = 0; j < arguments.length; j++){
            for(var i in arguments[j]){
                var value = String(arguments[j][i]);
                send(val1ClassName + "." + methodName + " and arguments value is: " + value);
            }
            args[j] = arguments[j] + "";
            }
            //打印方法参数
            send(val1ClassName + "." + methodName + " and args is: " + args);
            //调用方法
            var retval = this[methodName].apply(this,arguments);
            //打印方法返回值
            send(methodName + " return value is: " + retval);
            return retval;//返回方法返回值
        }
        })
    })

    }catch(e){
    send("'" + val1 + "' hook fail: " + e);
    }
}

function traceMethod(targetMethod, unparseMethod) {
    log("targetMethod: " + targetMethod)
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
            output = output.concat("\n")
            var retval = this[targetMethod].apply(this, arguments);

            //域值
            output = inspectObject(this, output);
            // 进入函数
            output = output.concat("*********entered " + unparseMethod + "********* \n");
            for (var j = 0; j < arguments.length; j++) {
                output = output.concat("arg[" + j + "]: " + arguments[j] + " => " + JSON.stringify(arguments[j]));
                output = output.concat("\n")
            }
            //调用栈
            var stacktraceLog = stacktrace_java();
            output = output.concat(stacktraceLog);
            
            // //返回值
            output = output.concat("\n retval: " + retval + " => " + JSON.stringify(retval));
            output = output.concat("\n-------------------test---------------------\n")
            // 测试的地方
            // output = output.concat(print_bytes(arguments[0]));
            // 将retval转为hashmap
            // var val1 = Java.cast(retval,Java.use("java.util.HashMap"));
            // // 修改vpn_ip键的值改为''
            // val1.put("vpn_ip","");
            // retval = null;
            // log(print_hashmap(arguments[1]))
            // log(JSON.stringify(retval))
            // output = output.concat(this.e);
            // console.log('CopyOnWriteArrayList values: ' + val.size());
            //离开函数
            output = output.concat("\n ********* exiting " + targetMethod + '*********\n');

            //画个横线
            for (var p = 0; p < 100; p++) {
                output = output.concat("==");
            }
            // if(!stacktraceLog.includes("anythink")){
            //     return retval;
            // }
            log(output)
            return retval;
        }
    }
}

export function _trace(targetClass, method) {
    var hook = Java.use(targetClass)
    var output = "Tracing Class: " + hook + "\n";
    var methods = hook.class.getDeclaredMethods()
    hook.$dispose();
    var methodsDict = {};
    output += "\t\nSpec: => \n";
    methods.forEach(_method => {
        _method = _method.toString();
    
        output += _method + "\n";
        
        // 新的正则表达式匹配
        var parsedMethod = _method.match(/[\w$]+\.([a-zA-Z0-9_$]+)\(/);
        if (parsedMethod) {
            parsedMethod = parsedMethod[1];
        } else {
            // 如果第一种匹配失败，尝试另一种模式
            parsedMethod = _method.match(/\s([a-zA-Z0-9_$]+)\(/);
            if (parsedMethod) {
                parsedMethod = parsedMethod[1];
            } else {
                // 最后的备用方案
                parsedMethod = _method.split(" ").pop().split("(")[0].split(".").pop();
            }
        }
                
        if (method && method.toLowerCase() !== parsedMethod.toLowerCase())
            return;
            
        methodsDict[_method] = parsedMethod;
    });

    //添加构造函数
    var varructors = hook.class.getDeclaredConstructors();
    if (varructors.length > 0) {
        varructors.forEach(function (varructor) {
            output += "Tracing " + varructor.toString() + "\n";
        })
        //有时候hook构造函数会报错，看情况取消
        methodsDict["$init"]='$init';
    }
    // log(output);

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
function findClassesInClassLoader(loader, targetClass,targetMethod,trace) {
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
                    if(trace){
                        Java.classFactory.loader = loader;
                    }
                }
            }
        }
    }
}

// 钩住所有的类加载器
export function findAllJavaClasses(targetClass,targetMethod,is_trace) {

    // // 第一种,不行，报错global reference table overflow,可以在返回值找到类，不能找到方法
    // var loadClass = classloader["loadClass"].overloads.length;
    // for (var i = 0; i < loadClass; i++) {
    //     classloader["loadClass"].overloads[i].implementation = function () {
    //         var retval = this["loadClass"].apply(this, arguments);
    //         var className = arguments[0];
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
    //             Java.classFactory.loader = loader;

    //             Java.enumerateLoadedClasses({
    //                 onMatch: function (clazz) {
    //                     // console.log(clazz)
    //                     if (clazz.toLowerCase().indexOf(targetClass.toLowerCase()) > -1) {
    //                         // if (clazz.toLowerCase() == targetClass.toLowerCase()) {
    //                         log('find targetClass class: ' + clazz)
    //                         targetClasses.push(clazz);
    //                         _trace(clazz,targetMethod);
    //                     }
    //                 },
    //                 onComplete: function () {
    //                     log("Search Class Completed!")
    //                 }
    //             });
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

    // const Class = Java.use('java.lang.Class');
    // var hook = false;
    // Class.getResourceAsStream.implementation = function(name) {
    //     const originalResult = this.getResourceAsStream(name);
    //     console.log(`[*] Hooked getResourceAsStream called with name: ${name}`);
    //     if(name.indexOf("com/appsflyer/internal/b-")>0&& !hook){
    //         hook = true;
    //         enumerateClassLoaders(targetClass, targetMethod);
    //     }

    //     // 返回原始方法的结果
    //     return originalResult;
    // };


    // 对于读取内存的jar文件的精准定位
    const classLoaderClass = Java.use('java.lang.ClassLoader');
    classLoaderClass.loadClass.overload('java.lang.String').implementation = function (className) {
        const retval = this.loadClass(className);
        if (className === targetClass) {
            log(`[*] Loaded class: ${className}`)
            // 加载了目标类，hook 其方法
            enumerateClassLoaders(targetClass,targetMethod);
        }
        return retval;
    };

}

function enumerateClassLoaders(targetClass, targetMethod){


    log('Begin enumerateClasses ...')

    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            try {
                if (loader.findClass(targetClass)) {
                    log("Successfully found loader")
                    log("loader is : " + loader)
                    Java.classFactory.loader = loader;
                    log("Switch Classloader Successfully ! ")
                }
            } catch (error) {
                // console.log('enumerateClassLoaders error: ' + error + '\n')
            }
        },
        onComplete: function () {
            // log("EnumerateClassloader END")
        }
    })

    var targetClasses = new Array();
    Java.enumerateLoadedClasses({
        onMatch: function (clazz) {
            // console.log(clazz)
            if (clazz.toLowerCase().indexOf(targetClass.toLowerCase()) > -1) {
                // if (clazz.toLowerCase() == targetClass.toLowerCase()) {
                log('find targetClass class: ' + clazz)
                targetClasses.push(clazz);
                _trace(clazz,targetMethod);
            }
        },
        onComplete: function () {
            log("Search Class Completed!")
        }
    });

    var output = "On Total Tracing :" + String(targetClasses.length) + " classes :\r\n";
    targetClasses.forEach(function (target) {
        output = output.concat(target);
        output = output.concat("\r\n");
    })
    log(output)
}



export function trace(targetClass, targetMethod) {
    // findAllJavaClasses(targetClass,targetMethod,true);

    enumerateClassLoaders(targetClass, targetMethod);
}