//@ts-nocheck
import { stacktrace,log } from "../utils/log.js";

export function one_instance(target){
    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            try {
                if (loader.findClass(target)) {
                    log("Successfully found loader")
                    Java.classFactory.loader = loader;
                    log("Switch Classloader Successfully ! ")
                }
            } catch (error) {
            }
        },
        onComplete: function () {
            log("EnumerateClassloader END")
        }
    })

    Java.choose(target, {
        onMatch: function (instance) {
            console.log("enter "+instance);
        }, onComplete: function () {
            console.log("end");
            console.log(arg[-1].toString())
        }
    });
}