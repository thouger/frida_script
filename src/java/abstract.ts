//@ts-nocheck
import { trace } from "./trace.js";
import { log, print_hashmap,print_byte, stacktrace_java } from "../utils/log.js";

export function hook_abstract(class_name) {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                if (loader.findClass(class_name)) {
                    log("Successfully found loader: " + loader);
                    Java.classFactory.loader = loader;
                }
            } catch(error) {}
        },
        onComplete: function() {}
    });
 
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                var nameParts = className.split(".");
                var targetParts = class_name.split(".");
                if (nameParts[0] !== targetParts[0] || nameParts[1] !== targetParts[1]) return;
 
                var clazz = Java.use(className);
                var resultClass = clazz.class.getSuperclass();
                if (resultClass && resultClass.toString().indexOf(class_name) !== -1) {
                    log(className, resultClass);
                    trace(resultClass);
                }
            } catch(e) {}
        },
        onComplete: function() {
            log("Search Class Completed!");
        }
    });
 }