//@ts-nocheck
import { log } from "../utils/log.js";
export function hook_dlopen(so_name, hook_func) {
    log('hook_dlopen');
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    if (android_dlopen_ext != null) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function (args) {
                var soName = args[0].readCString();
                if (soName.indexOf(so_name) != -1) {
                    log('find so');
                    this.hook = true;
                }
            },
            onLeave: function (retval) {
                if (this.hook)
                    hook_func();
            }
        });
    }
}
