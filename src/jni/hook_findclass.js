// Hook FindClass from libmetasec_ml.so
Java.perform(function() {
    console.log("[*] Starting to hook FindClass...");

    var env = Java.vm.getEnv();
    var FindClassPtr = env.handle.readPointer().add(Process.pointerSize * 6); // FindClass在JNIEnv表中的偏移
    var FindClass = Memory.readPointer(FindClassPtr);

    console.log("[*] FindClass address: " + FindClass);

    Interceptor.attach(FindClass, {
        onEnter: function(args) {
            var caller = this.returnAddress;
            var module = Process.findModuleByAddress(caller);

            // 只记录来自libmetasec_ml.so的调用
            if (module && module.name === "libmetasec_ml.so") {
                var className = Memory.readCString(args[1]);
                console.log("[FindClass] className: " + className);
                console.log("           called from: " + caller.sub(module.base) + " (offset in libmetasec_ml.so)");
            }
        },
        onLeave: function(retval) {
            // 可以在这里打印返回值
        }
    });

    console.log("[*] FindClass hooked successfully! Only showing calls from libmetasec_ml.so");
});
