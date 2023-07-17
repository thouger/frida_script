function main() {
    Java.perform(function () {
        var addr = Module.findExportByName("libnative-lib.so", "func_four");
        console.log("func_four addr is: ", addr);
        var func_four = new NativeFunction(addr, 'pointer', ['pointer', 'pointer', 'pointer']);

        var env = Java.vm.getEnv();
        var instance = NULL
        var jstring = env.newStringUtf('15');

        func_four(env, instance, jstring)
    });
}

setImmediate(main)