//@ts-nocheck
import { log, print_hashmap, stacktrace } from "../utils/log";
import { trace } from "./trace";

export function one_method_hook() {
    var targetClass = "dalvik.system.DexFile";
    var targetMethod = "defineClass";
    var hook = Java.use(targetClass);
    var overloadCount = hook[targetMethod].overloads.length;
    for (var i = 0; i < overloadCount; i++) {
        hook[targetMethod].overloads[i].implementation = function () {
            for (var j = 0; j < arguments.length; j++) {
                // log("arg[" + j + "]: " + arguments[j] + " => " + JSON.stringify(arguments[j]));
            }
            var retval = this[targetMethod].apply(this, arguments);
            if (arguments[0] == 'com.appsflyer.internal.AFa1nSDK$30218') {
                var result = Java.use(arguments[0])
                var targetMethod1 = 'values'
                var overloadCount = result[targetMethod1].overloads.length;
                for (var i = 0; i < overloadCount; i++) {
                    result[targetMethod1].overloads[i].implementation = function () {
                        var output = "";

                        //画个横线
                        for (var p = 0; p < 100; p++) {
                            output = output.concat("==");
                        }
                        output = output.concat("\n")

                        //域值
                        output = inspectObject(this, output);
                        // 进入函数
                        output = output.concat("*** entered " + unparseMethod + "***\n");
                        for (var j = 0; j < arguments.length; j++) {
                            log("arg[" + j + "]: " + arguments[j] + " => " + JSON.stringify(arguments[j]));
                        }
                        //调用栈
                        output = output.concat(stacktrace());
                        var retval1 = this[targetMethod1].apply(this, arguments);
                        // //返回值
                        output = output.concat("\nretval: " + retval1 + " => " + JSON.stringify(retval1));

                        //离开函数
                        output = output.concat("\n*** exiting " + targetClassMethod + '***\n');
                        log(output)
                    }
                    return retval1;
                }
            }

            // var suppressedExceptions = Java.use('java.util.ArrayList').$new();
            // var result = this.pathList.value.findClass('com.appsflyer.internal.AFa1nSDK$30218',suppressedExceptions)
            return retval;
        }
    }
}