// Hook GetMethodID from libmetasec_ml.so
Java.perform(function() {
    console.log("[*] Starting to hook GetMethodID...");

    var env = Java.vm.getEnv();
    var GetMethodIDPtr = env.handle.readPointer().add(Process.pointerSize * 33); // GetMethodID在JNIEnv表中的偏移
    var GetMethodID = Memory.readPointer(GetMethodIDPtr);

    console.log("[*] GetMethodID address: " + GetMethodID);

    Interceptor.attach(GetMethodID, {
        onEnter: function(args) {
            var caller = this.returnAddress;
            var module = Process.findModuleByAddress(caller);

            // 只记录来自libmetasec_ml.so的调用
            var methodName = Memory.readCString(args[2]);
            var signature = Memory.readCString(args[3]);

            console.log("[GetMethodID] method: " + methodName);
            console.log("              signature: " + signature);
            console.log("              called from: " + caller.sub(module.base) + " (offset in libmetasec_ml.so)");
        },
        onLeave: function(retval) {
            // 可以在这里打印返回值（jmethodID）
            if (retval.isNull()) {
                console.log("[GetMethodID] returned NULL (method not found)");
            }
        }
    });

    console.log("[*] GetMethodID hooked successfully! Only showing calls from libmetasec_ml.so");
});
