 var ByPassTracerPid = function () {
     var fgetsPtr = Module.findExportByName("libc.so", "fgets");
     var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
     Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
         var retval = fgets(buffer, size, fp);
         var bufstr = Memory.readUtf8String(buffer);
         if (bufstr.indexOf("TracerPid:") > -1) {
             Memory.writeUtf8String(buffer, "TracerPid:\t0");
             console.log("tracerpid replaced: " + Memory.readUtf8String(buffer));
         }
         return retval;
     }, 'pointer', ['pointer', 'int', 'pointer']));
 };
 setImmediate(ByPassTracerPid);

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
            // console.log("anti anti-frida");
        }
    }
setImmediate(antiAntiFrida)

function main() {
    Java.perform(function (){

        Java.use("java.net.NetworkInterface").getName.implementation = function(){
            var string_class = Java.use("java.lang.String");
            var gname = this.getName();
            if(gname == string_class.$new("tun0")){
//                console.log("find ===> ", gname);
                return string_class.$new("rmnet_data0")
            } else{
//                console.log("gname ===> ", gname)
            }
            return gname;
        }

//            Java.use("java.net.InetAddress").isLoopbackAddress.implementation = function(){
//                var res = this.isLoopbackAddress()
//                // var res1 = res.$new();
//                // var res2 = res1.class.getDeclaredField("isLoopbackAddress")
//                // res2.setAccessible(true)
//                // //调用get()来获取值
//                // var value = res2.get(res1);
//                // console.log("res ==> ",value)
//                console.log("res ==> ",res)
//                return res;
//             }

    //     Java.use("java.net.NetworkInterface").getInetAddresses.implementation = function(){
    //         var res = this.getInetAddresses()
    //         console.log("thouger ===>",res)
    //         return res;
    //    }

//              Java.use("android.net.ConnectivityManager").getNetworkCapabilities.implementation = function(v){
//                  console.log(v)
//                  var res = this.getNetworkCapabilities(v)
// //                 console.log("res ==> ", res)
//                  return null;
//              }
     })
    }

//            if (retval != null) {
//                var bytes = Memory.readCString(retval);
//                if(bytes != null) {
//                    if(bytes.toString().indexOf("x-sign") >= 0 )
//                    {
//                        console.log("[GetStringUTFChars] result:" + bytes);
//                        var threadef = Java.use('java.lang.Thread');
//                        var threadinstance = threadef.$new();
//
//                        var stack = threadinstance.currentThread().getStackTrace();
//                        console.log("Rc Full call stack:" + Where(stack));
//
//                        // Native 层 堆栈
//                        console.log(Thread.backtrace(this.context, Backtracer.FUZZY)
//                        .map(DebugSymbol.fromAddress).join("\n"))
//
//                    }
//                }
//
//            }
//        }
//    });

setImmediate(main);
