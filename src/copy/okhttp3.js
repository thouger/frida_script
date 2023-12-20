function hook_okhttp3() {
    Java.perform(function () {
        var ByteString = Java.use("com.android.okhttp.okio.ByteString");
        var Buffer = Java.use("com.android.okhttp.okio.Buffer");
        var Interceptor = Java.use("okhttp3.Interceptor");
        var MyInterceptor = Java.registerClass({
            name: "okhttp3.MyInterceptor",
            implements: [Interceptor],
            methods: {
                intercept: function (chain) {
                    var request = chain.request();
                    try {
                        console.log("MyInterceptor.intercept onEnter:", request, "\nrequest headers:\n", request.headers());
                        var requestBody = request.body();
                        var contentLength = requestBody ? requestBody.contentLength() : 0;
                        if (contentLength > 0) {
                            var BufferObj = Buffer.$new();
                            requestBody.writeTo(BufferObj);
                            try {
                                console.log("\nrequest body String:\n", BufferObj.readString(), "\n");
                            } catch (error) {
                                try {
                                    console.log("\nrequest body ByteString:\n", ByteString.of(BufferObj.readByteArray()).hex(), "\n");
                                } catch (error) {
                                    console.log("error 1:", error);
                                }
                            }
                        }
                    } catch (error) {
                        console.log("error 2:", error);
                    }
                    var response = chain.proceed(request);
                    try {
                        console.log("MyInterceptor.intercept onLeave:", response, "\nresponse headers:\n", response.headers());
                        var responseBody = response.body();
                        var contentLength = responseBody ? responseBody.contentLength() : 0;
                        if (contentLength > 0) {
                            console.log("\nresponsecontentLength:", contentLength, "responseBody:", responseBody, "\n");

                            var ContentType = response.headers().get("Content-Type");
                            console.log("ContentType:", ContentType);
                            if (ContentType.indexOf("video") == -1) {
                                if (ContentType.indexOf("application") == 0) {
                                    var source = responseBody.source();
                                    if (ContentType.indexOf("application/zip") != 0) {
                                        try {
                                            console.log("\nresponse.body StringClass\n", source.readUtf8(), "\n");
                                        } catch (error) {
                                            try {
                                                console.log("\nresponse.body ByteString\n", source.readByteString().hex(), "\n");
                                            } catch (error) {
                                                console.log("error 4:", error);
                                            }
                                        }
                                    }
                                }

                            }

                        }

                    } catch (error) {
                        console.log("error 3:", error);
                    }
                    return response;
                }
            }
        });
        var ArrayList = Java.use("java.util.ArrayList");
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        console.log(OkHttpClient);
        OkHttpClient.$init.overload('okhttp3.OkHttpClient$Builder').implementation = function (Builder) {
            console.log("OkHttpClient.$init:", this, Java.cast(Builder.interceptors(), ArrayList));
            this.$init(Builder);
        };

        var MyInterceptorObj = MyInterceptor.$new();
        var Builder = Java.use("okhttp3.OkHttpClient$Builder");
        console.log(Builder);
        Builder.build.implementation = function () {
            this.interceptors().clear();
            //var MyInterceptorObj = MyInterceptor.$new();
            this.interceptors().add(MyInterceptorObj);
            var result = this.build();
            return result;
        };

        Builder.addInterceptor.implementation = function (interceptor) {
            this.interceptors().clear();
            //var MyInterceptorObj = MyInterceptor.$new();
            this.interceptors().add(MyInterceptorObj);
            return this;
            //return this.addInterceptor(interceptor);
        };

        console.log("hook_okhttp3...");
    });
}

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
