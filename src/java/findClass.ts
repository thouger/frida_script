//@ts-nocheck
import { log, print_hashmap, stacktrace } from "../utils/log.js";
import { _trace } from "./trace";

export function findClass(targetClass: string) {
    var hook = Java.use("dalvik.system.BaseDexClassLoader");
    var classLoaderInit = "$init";
    var overloadCount = hook[classLoaderInit].overloads.length;
    for (var i = 0; i < overloadCount; i++) {
        hook[classLoaderInit].overloads[i].implementation = function () {
            for (var j = 0; j < arguments.length; j++) {
                log("arg[" + j + "]: " + arguments[j] + " => " + JSON.stringify(arguments[j]));
            }
            var retval = this[classLoaderInit].apply(this, arguments);
            if(arguments[3] != null){
                Java.classFactory.loader = arguments;
                var classNames = Java.enumerateLoadedClassesSync()
                for (let i = 0; i < classNames.length; i++) {
                    log("class: " + classNames[i])
                }
                // Java.enumerateLoadedClasses({
                //     onMatch: function (clazz) {
                //         log(clazz+'---'+clazz.toLowerCase())
                //         if (clazz.indexOf(targetClass) >= 0) {
                //             log('find target class: ' + clazz)
                // //             _trace(clazz)
                //         }
                //     },
                //     onComplete: function () {
                //     }
                // });
            }
            // var suppressedExceptions = Java.use('java.util.ArrayList').$new();
            // log(this);
            // var result = this.pathList.value.findClass(targetClass,suppressedExceptions)
            // var targetMethod = '$init'
            // var overloadCount = result[targetMethod].overloads.length;
            // for (var i = 0; i < overloadCount; i++) {
            //     result[targetMethod].overloads[i].implementation = function () {
            //         var output = "";
        
            //         //画个横线
            //         for (var p = 0; p < 100; p++) {
            //             output = output.concat("==");
            //         }
            //         output = output.concat("\n")
        
            //         //域值
            //         output = inspectObject(this, output);
            //         // 进入函数
            //         output = output.concat("*** entered " + unparseMethod + "***\n");
            //         for (var j = 0; j < arguments.length; j++) {
            //             output = output.concat("arg[" + j + "]: " + arguments[j] + " => " + JSON.stringify(arguments[j]));
            //             output = output.concat("\n")
            //         }
            //         //调用栈
            //         output = output.concat(stacktrace());
            //         var retval = this[targetMethod].apply(this, arguments);
            //         // //返回值
            //         output = output.concat("\nretval: " + retval + " => " + JSON.stringify(retval));
        
            //         //离开函数
            //         output = output.concat("\n*** exiting " + targetClassMethod + '***\n');
            //         log(output)
            //     }
            return retval;
        }
    }
}