//@ts-nocheck
import { log, print_hashmap, stacktrace } from "../utils/log";
import { trace } from "./trace";

export function one_method_hook() {
    var targetClass = "java.lang.ClassLoader";
    var targetMethod = "findLoadedClass";
    var hook = Java.use(targetClass);
    var overloadCount = hook[targetMethod].overloads.length;
    for (var i = 0; i < overloadCount; i++) {
        hook[targetMethod].overloads[i].implementation = function () {
            var retval = this[targetMethod].apply(this, arguments);
            log(arguments[0])
            if (arguments[0] == "com.appsflyer.internal.AFa1nSDK$30218") {
                log('success')
                setTimeout(trace, 0, 'com.appsflyer.internal.AFa1nSDK$30218')
            }
            return retval;
        }
    }
}