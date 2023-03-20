//@ts-nocheck
import { log, print_hashmap, stacktrace } from "../utils/log";
import { trace } from "./trace";

var targetClass = 'com.appsflyer.internal.AFa1nSDK$30218$AFa1wSDK$25697';
var targetMethod = 'AFKeystoreWrapper';

export function anti_InMemoryDexClassLoader() {
    Java.perform(function () {

    const InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
    InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
        .implementation = function (buff, loader) {
        this.$init(buff, loader);
        var oldcl = Java.classFactory.loader;
        Java.classFactory.loader = this;

        try{
            var hook = Java.use(targetClass);
        }catch(e){
            log('hook ' + targetClass + ' ' + targetMethod+' fail')
            return
        }
        log('hook ' + targetClass + ' ' + targetMethod+' success')
        var overloadCount = hook[targetMethod].overloads.length;
        log('overloadCount: ' + overloadCount)
        for (var i = 0; i < overloadCount; i++) {
            hook[targetMethod].overloads[i].implementation = function () {
                for (var i = 0; i < arguments.length; i++) {
                    log("arg[" + j + "]: " + arguments[j] + " => " + JSON.stringify(arguments[j]));

                }
                var retval = this[targetMethod].apply(this, arguments);
                log('retval: ' + retval + ' => ' + JSON.stringify(retval));
                return retval;
            }
        }

        Java.classFactory.loader = oldcl; // 恢复现场
    }
})
}