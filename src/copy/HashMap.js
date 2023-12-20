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


    function dis(address, number) {
        for (var i = 0; i < number; i++) {
            var ins = Instruction.parse(address);
            // console.log("address:" + address + "--dis:" + ins.toString());
            address = ins.next;
        }
    }
    //libc->strstr()  从linker里面找到call_function的地址：趁so代码还未执行前就hook
    //call_function("DT_INIT", init_func_, get_realpath());
    var linkermodule = Process.getModuleByName("linker");
    var call_function_addr = null;
    var symbols = linkermodule.enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        // LogPrint(linkername + "->" + symbol.name + "---" + symbol.address);
        if (symbol.name.indexOf("__dl__ZL13call_functionPKcPFviPPcS2_ES0_") != -1) {
            call_function_addr = symbol.address;
            // console.log("linker->" + symbol.name + "---" + symbol.address)
        }
    }
    Interceptor.attach(call_function_addr, {
        onEnter: function (args) {
            var type = ptr(args[0]).readUtf8String();
            var address = args[1];
            var sopath = ptr(args[2]).readUtf8String();
            // console.log("loadso:" + sopath + "--addr:" + address + "--type:" + type);
            if (sopath.indexOf("libnative-lib.so") != -1) {
                var libnativemodule = Process.getModuleByName("xxxx.so");//call_function正在加载目标so，这时就拦截下来
                var base = libnativemodule.base;
                dis(base.add(0x1234).add(1), 10);
                var patchaddr = base.add(0x2345);//改so的机器码，避免待会完全加载后运行时就错过时机了！
                Memory.patchCode(patchaddr, 4, patchaddr => {
                    var cw = new ThumbWriter(patchaddr);
                    cw.putNop();
                    cw = new ThumbWriter(patchaddr.add(0x2));
                    cw.putNop();
                    cw.flush();
                });
                // console.log("+++++++++++++++++++++++")
                dis(base.add(0x1234).add(1), 10);
                // console.log("----------------------")

                dis(base.add(0x2345).add(1), 10);
                Memory.protect(base.add(0x8E78), 4, 'rwx');
                base.add(0x1234).writeByteArray([0x00, 0xbf, 0x00, 0xbf]);
                // console.log("+++++++++++++++++++++++")
                dis(base.add(0x2345).add(1), 10);


            }
        }
    })
}
setImmediate(antiAntiFrida)

var isLite = false;
var ByPassTracerPid = function () {
    var fgetsPtr = Module.findExportByName("libc.so", "fgets");
    var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
    Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
        var retval = fgets(buffer, size, fp);
        var bufstr = Memory.readUtf8String(buffer);
        if (bufstr.indexOf("TracerPid:") > -1) {
            Memory.writeUtf8String(buffer, "TracerPid:\t0");
        }
        return retval;
    }, 'pointer', ['pointer', 'int', 'pointer']));
};
setImmediate(ByPassTracerPid);

function main() {
    Java.perform(function () {
        console.log("hook Map")
        var Map = Java.use('java.util.Map');
        Map.put.implementation = function (arg1, arg2) {
            console.log("=================Map.put====================");
            var data = this.put(arg1, arg2);
            console.log(arg1 + "-----" + arg2);
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
            return data;
        }
    })
}
// setTimeout(test, 5000);