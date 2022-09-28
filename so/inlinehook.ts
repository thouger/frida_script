//@ts-nocheck


export function inline_hook(so_name,addr){
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    if(android_dlopen_ext != null){
        Interceptor.attach(android_dlopen_ext,{
            onEnter: function(args){
                var soName = args[0].readCString();
                if(soName.indexOf(so_name) != -1){
                    this.hook = true;
                }
            },
            onLeave: function(retval){
                if(this.hook) { _inline_hook(so_name,addr) };
            }
        });
    }

}
function _inline_hook(so_name,addr){
    console.log('find so')
    var so_addr = Module.findBaseAddress(so_name)
    console.log('so_addr: ' + so_addr)
    var func = so_addr.add(addr)
    console.log("[+] Hooking function: " + func)

    Java.perform(function () {
        Interceptor.attach(func, {
            onEnter: function(args) {
                console.log(hexdump(this.context.PC))
                // console.log('arg0'+hexdump(args[0]))
                // console.log("args[0] Intercepted: " + hexdump(args[0]))
                // console.log("args[1] Intercepted: " + hexdump(args[1]))
                // console.log("args[2] Intercepted: " + args[2])
                // console.log("args[3] Intercepted: " + hexdump(args[3]))
                // console.log("args[4] Intercepted: " + hexdump(args[4]))
                // console.log("args[5] Intercepted: " + hexdump(args[5]))
                // console.log("args[6] Intercepted: " + hexdump(args[6]))
                // console.log("args[7] Intercepted: " + hexdump(args[7]))
                // console.log("args[8] Intercepted: " + hexdump(args[8]))
                // console.log("args[9] Intercepted: " + hexdump(args[9]))
                // console.log("args[10] Intercepted: " + hexdump(args[10]))
                // console.log("args[11] Intercepted: " + hexdump(args[11]))
                // console.log("args[12] Intercepted: " + hexdump(args[12]))



                console.log('CCCryptorCreate called from:\n' + Thread.backtrace(this.context, Backtracer.ACCURATE) .map(DebugSymbol.fromAddress).join('\n') + '\n');
            },
            onLeave: function(retval) {
                console.log("[+] Returned: " + hexdump(retval))
                console.log("retval is :", retval)
                return retval;
            }
    })
})
}

function readStdString(str){
    const isTiny = (str.readU8() & 1) == 0;
    if(isTiny){
        return str.add(1).readUtf8String();
    }
    return str.add(2*Process.pointerSize).readPointer().readUtf8String();
}