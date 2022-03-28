function antiAntiFrida() {
    var strstr = Module.findExportByName(null, "strstr");
    if (null !== strstr) {
        Interceptor.attach(strstr, {
            onEnter: function (args) {
                this.frida = Boolean(0);

                this.haystack = args[0];
                this.needle = args[1];

                if (this.haystack.readCString() !== null && this.needle.readCString() !== null) {
                    if (this.haystack.readCString().indexOf("frida") !== -1 ||
                        this.needle.readCString().indexOf("frida") !== -1 ||
                        this.haystack.readCString().indexOf("gum-js-loop") !== -1 ||
                        this.needle.readCString().indexOf("gum-js-loop") !== -1 ||
                        this.haystack.readCString().indexOf("gmain") !== -1 ||
                        this.needle.readCString().indexOf("gmain") !== -1 ||
                        this.haystack.readCString().indexOf("linjector") !== -1 ||
                        this.needle.readCString().indexOf("linjector") !== -1) {
                        this.frida = Boolean(1);
                    }
                }
            },
            onLeave: function (retval) {
                if (this.frida) {
                    retval.replace(ptr("0x0"));
                }

            }
        })
    }
}
setImmediate(antiAntiFrida)

function main() {
    var randombytes_buf_addr = null;
    var symbols = Process.findModuleByName("libart.so").enumerateSymbols();
    for (var i in symbols) {
        var symbol = symbols[i];
        if (symbol.name.indexOf("art") >= 0 &&
            symbol.name.indexOf("JNI") >= 0 &&
            symbol.name.indexOf("CheckJNI") < 0
        ){
            if (symbol.name.indexOf("randombytes_buf") >= 0) {
                console.log("find target symbols", symbol.name, "address is ", symbol.address);
                randombytes_buf_addr = symbol.address;
            }
        }
    }

    console.log("randombytes_buf_addr is ", randombytes_buf_addr);

    Interceptor.attach(randombytes_buf_addr, {
        onEnter: function (args) {
            console.log("args0",args[0])
            console.log("args0", args[0], hexdump(args[0]));
            console.log("args1", args[1], hexdump(args[1]));
            var env = Java.vm.tryGetEnv();
            if (env != null) {
                // 直接读取 c 里面的 char
                console.log("Memory readCstring is :", Memory.readCString(args[1]));
            }else{
                console.log("get env error");
            }
        },
        onLeave: function (returnResult) {
            console.log("result: ", Java.cast(returnResult, Java.use("java.lang.String")));
            var env = Java.vm.tryGetEnv();
            if (env != null) {
                var jstring = env.newStringUtf("修改返回值");
                returnResult.replace(ptr(jstring));
            }
        }
    })
}
