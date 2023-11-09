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

                    // try{
                    //     output = output.concat("thouger:"+getReflectFields(arguments[0],output)+'\n')
                    // }catch(e){
                    //     output = output.concat("thouger:"+e.toString()+'\n')
                    // }
                    output = output.concat("----------------------------------------\n")

            for (var j = 0; j < arguments.length; j++) {
                output = output.concat("arg[" + j + "]: " + arguments[j] + " => " + JSON.stringify(arguments[j]));
                output = output.concat("\n")
            }
            //调用栈
            var stacktraceLog = stacktrace();
            output = output.concat(stacktraceLog);
            
            var retval = this[targetMethod].apply(this, arguments);
            // //返回值
            output = output.concat("\n retval: " + retval + " => " + JSON.stringify(retval));

            //离开函数
            output = output.concat("\n ********* exiting " + targetMethod + '*********\n');

            //画个横线
            for (var p = 0; p < 100; p++) {
                output = output.concat("==");
            }
            // print_hashmap(retval)
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
        if (method && method.toLowerCase() !== parsedMethod.toLowerCase())
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

// 获取需要使用的 Java 类
const BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
const DexPathList = Java.use("dalvik.system.DexPathList");
const DexFile = Java.use("dalvik.system.DexFile");
const DexPathListElement = Java.use("dalvik.system.DexPathList$Element");

// 存储找到的类名
var foundClasses = [];

// 遍历所有类加载器并查找目标类
function hookAllAppClasses(loader, targetClass) {
    const pathClassLoader = Java.cast(loader, BaseDexClassLoader);
    log("ClassLoader pathList: " + pathClassLoader.pathList.value);
    const dexPathList = Java.cast(pathClassLoader.pathList.value, DexPathList);
    log("ClassLoader dexElements: " + dexPathList.dexElements.value.length);
    
    for (let i = 0; i < dexPathList.dexElements.value.length; i++) {
        const dexPathListElement = Java.cast(dexPathList.dexElements.value[i], DexPathListElement);
        if (dexPathListElement.dexFile.value) {
            const dexFile = Java.cast(dexPathListElement.dexFile.value, DexFile);
            let mCookie = dexFile.mCookie.value;
            
            if (dexFile.mInternalCookie.value) {
                mCookie = dexFile.mInternalCookie.value;
            }
            
            const classNameArr = dexPathListElement.dexFile.value.getClassNameList(mCookie);
            log("dexFile.getClassNameList.length: " + classNameArr.length);
            log("Enumerate ClassName Start");
            
            for (let i = 0; i < classNameArr.length; i++) {
                const className = classNameArr[i];
                if (className.includes(targetClass)) {
                    log("Find class: " + className);
                    foundClasses.push(className);
                }
            }
            log("Enumerate ClassName End");
        }
    }
}

// 钩住所有的类加载器
export function findAllJavaClasses(targetClass) {
    const classLoaderInit = "$init";
    const overloadCount = BaseDexClassLoader[classLoaderInit].overloads.length;
    
    for (let i = 0; i < overloadCount; i++) {
        BaseDexClassLoader[classLoaderInit].overloads[i].implementation = function () {
            const retval = this[classLoaderInit].apply(this, arguments);
            hookAllAppClasses(this, targetClass);
            return retval;
        }
    }
    
    return foundClasses;
}


export function trace(target, method) {
    findAllJavaClasses(target).forEach(function (className) {
        _trace(className, method)
    });
}