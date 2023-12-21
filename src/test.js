var addr = 0x1208; // loginWithPhoneNbr函数的起始地址
var mainModule = Process.enumerateModules()[0];
console.log(JSON.stringify(mainModule));
var mainName: string = mainModule.name;
var baseAddr = Module.findBaseAddress(mainName)!;
Interceptor.attach(baseAddr.add(addr), {
    onEnter: function(args) {
        console.log(addr.toString(16), "= loginWithPhoneNbr onEnter =");
        var tid = Process.getCurrentThreadId();
        Stalker.follow(tid, {
            events: {
                call: true, // CALL instructions: yes please            
                ret: false, // RET instructions
                exec: false, // all instructions: not recommended as it's
                block: false, // block executed: coarse execution trace
                compile: false // block compiled: useful for coverage
            },
            transform: (iterator: StalkerArm64Iterator) => {
                let instruction = iterator.next();
                const startAddress = instruction!.address;
                var isAppCode = startAddress.compare(baseAddr.add(addr)) >= 0 && startAddress.compare(baseAddr.add(addr).add(10000)) === -1;
                do {
                    if (isAppCode) {
                        if (instruction!.mnemonic === "bl") {
                            iterator.putCallout((ctx) => {
                                var arm64Context = ctx as Arm64CpuContext;
                                console.log("bl x0 = " + new ObjC.Object(arm64Context.x0))
                                console.log("bl x1 = " + arm64Context.x1.readCString())
                            });                        
                        }
                    }
                    iterator.keep();
                } while ((instruction = iterator.next()) !== null);
             }
        })
    }, onLeave: function(retval) { 
        console.log("retval:", new ObjC.Object(retval))
        console.log(addr.toString(16), "= loginWithPhoneNbr onLeave =");
    }
});
