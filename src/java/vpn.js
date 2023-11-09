
function main() {
    Java.perform(function (){

        Java.use("java.net.NetworkInterface").getName.implementation = function(){
            var string_class = Java.use("java.lang.String");
            var gname = this.getName();
            if(gname == string_class.$new("tun0")){
               console.log("find ===> ", gname);
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
