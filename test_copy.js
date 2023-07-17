function main() {
    Java.perform(function () {
        var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
        if (android_dlopen_ext != null) {
            Interceptor.attach(android_dlopen_ext, {
                onEnter: function (args) {
                    var soName = args[0].readCString();
                    if (soName.indexOf("libnative-lib.so") != -1) {
                        this.hook = true;
                    }
                },
                onLeave: function (retval) {
                    if (this.hook) 
                    var addr = Module.findExportByName("libnative-lib.so", "func_four");
                    if(addr==undefined)
                    return

                    Process
                    .getModuleByName({ linux: 'libc.so', darwin: 'libSystem.B.dylib', windows: 'ws2_32.dll' }[Process.platform])
                    // .enumerateExports().filter(ex => ex.type === 'function' && ['connect', 'recv', 'send', 'read', 'write'].some(prefix => ex.name.indexOf(prefix) === 0))
                        .enumerateExports().filter(ex => ex.type === 'function' && ['send','recv'].some(prefix => ex.name.indexOf(prefix) === 0))
                    .forEach(ex => {
                      Interceptor.attach(ex.address, {
                        onEnter: function (args) {
                          var fd = args[0].toInt32();
                          var socktype = Socket.type(fd);
                        //   if (socktype !== 'tcp' && socktype !== 'tcp6')
                        //     return;

                            // var data = Memory.readByteArray(args[1], args[2].toInt32());
                            // var dataStr = bytesToString(data);
                            console.log("args[1]:"+hexdump(args[1])+"\n"+'RegisterNatives called from:\n' + Thread.backtrace(this.context, Backtracer.ACCURATE)
                                .map(DebugSymbol.fromAddress).join('\n') + '\n');
                        },
                        onLeave: function (retval) {

                            // console.log('retval: ', hexdump(retval))
                        }
                      });
                    });
                  
                  function bytesToString(bytes) {
                    var string = '';
                    for (var i = 0; i < bytes.length; i++) {
                      string += String.fromCharCode(bytes[i]);
                    }
                    return string;
                  }

                    console.log("func_four addr is: ", addr);
                    var func_four = new NativeFunction(addr, 'pointer', ['pointer', 'pointer', 'pointer']);
            
                    var env = Java.vm.getEnv();
                    var instance = NULL
                    var jstring = env.newStringUtf('15');
            
                    var result = Memory.readCString(func_four(env, instance, jstring));
                    console.log("The result is: ", result);
                }
            });
        }
    });
}

setImmediate(main)