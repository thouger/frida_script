//@ts-nocheck
import { log } from "../utils/log.js";
import { hook_dlopen } from "./utils.js"

var so_name;
export function stalker(_so_name,addr){
    so_name = _so_name
    hook_dlopen(so_name,_stalker,addr)
}

export function native_trace(_so_name,addr,size){
    so_name = _so_name
    hook_dlopen(so_name,_trace,addr,size)
}

function stalkerTraceRange(tid, base, size) {
    Stalker.follow(tid, {
        transform: (iterator) => {
            const instruction = iterator.next();
            const startAddress = instruction.address;
            const isModuleCode = startAddress.compare(base) >= 0 && 
                startAddress.compare(base.add(size)) < 0;
            // const isModuleCode = true;
            //transform是每个block触发。这里每个block触发的时候遍历出所有指令。
            do {
                iterator.keep();
                if (isModuleCode) {
                      //这里可以看到数据如果是inst就是一个指令，我们就需要解析打印
                      //输出样本如下
                      //'payload': {'type': 'inst', 'tid': 19019, 'block': '0x74fd8d4ff4', 'val': '{"address":"0x74fd8d4ffc","next":"0x4","size":4,"mnemonic":"add","opStr":"sp, sp, #0x70","operands":[{"type":"reg","value":"sp"},{"type":"reg","value":"sp"},{"type":"imm","value":"112"}],"regsRead":[],"regsWritten":[],"groups":[]}'}}
                      //py解析打印格式"add sp, sp, #0x70  //sp=112"        这里的处理应该还要更复杂。暂时先简单处理
                      log(instruction)

                         //这里是打印所有寄存器
                      //输出样本如下
                      //{'type': 'ctx', 'tid': 19019, 'val': '{"pc":"0x74fd8d4fe8","sp":"0x7fc28609d0","x0":"0x0","x1":"0x7fc2860908","x2":"0x0","x3":"0x756aec1349","x4":"0x7fc28608f0","x5":"0x14059dbe","x6":"0x7266206f6c6c6548","x7":"0x2b2b43206d6f7266","x8":"0x0","x9":"0x65af2e18847fd289","x10":"0x1","x11":"0x7fc2860a20","x12":"0xe","x13":"0x7fc2860a20","x14":"0xffffff0000000000","x15":"0x756aeed1b5","x16":"0x74fd8fadc8","x17":"0x74fd8d50d8","x18":"0x75f0bda000","x19":"0x75f02f9c00","x20":"0x756af59490","x21":"0x75f02f9c00","x22":"0x7fc2860c90","x23":"0x74ffcee337","x24":"0x4","x25":"0x75f04b4020","x26":"0x75f02f9cb0","x27":"0x1","x28":"0x756b3f2000","fp":"0x7fc2860a30","lr":"0x74fd8d4fdc"}'}}
                      //这里是寄存器变化时调用
                    iterator.putCallout((context) => {
                            log(JSON.stringify(context)
                            )
                    })
                }
            } while (iterator.next() !== null);
        }
    })
}

function _trace(addr,size){
    var size = size || 0x1000;
    var base_addr=Module.getBaseAddress(so_name);
    console.log("base_addr:",base_addr);
    var func=base_addr.add(addr);
    console.log("func:",func);
    Interceptor.attach(func,{
        onEnter:function(args){
            this.tid=Process.getCurrentThreadId();
            stalkerTraceRange(this.tid, func,size);
        },onLeave(retval){
            Stalker.unfollow(this.tid);
        }
    })
}

function _stalker(addr){
    var base_addr=Module.getBaseAddress(so_name);
    console.log("base_addr:",base_addr);
    var func=base_addr.add(addr);
    console.log("func:",func);
    Interceptor.attach(func,{
        onEnter:function(args){
            this.tid=Process.getCurrentThreadId();
            // console.log("enter func tid:",this.tid);
            Stalker.follow(this.tid, {
                events: {
                    call: true, // CALL instructions: yes please
                    // Other events:
                    ret: false, // RET instructions
                    exec: false, // all instructions: not recommended as it's
                                 //                   a lot of data
                    block: false, // block executed: coarse execution trace
                    compile: false // block compiled: useful for coverage
                },
                onCallSummary:function(summary){        //有什么函数被这个函数调用的地址
                    for(var iter in summary){
                        try{
                            var module= Process.getModuleByAddress(ptr(iter))
                            if(module.name.indexOf(so_name)!=-1){
                                console.log("onCallSummary",iter,ptr(iter).sub(module.base));
                            }
                        }catch(err){
                        }
                    }
                },
                onReceive:function(events){             //调用的流程，地址1是哪里发生的调用。地址2是调用到了哪里
                    console.log("enter onReceive")
                    var eventsData=Stalker.parse(events,{
                        annotate: true,
                        stringify: true
                    });
                    for(var idx in eventsData){
                        var dataSp=eventsData[idx];
                        var addr1=dataSp[1];
                        var addr2=dataSp[2];
                        try{
                            var module1=Process.getModuleByAddress(ptr(addr1));
                            if(module1.name.indexOf(so_name)!=-1){
                                var module2=Process.getModuleByAddress(ptr(addr2));
                                // onReceive + call + so名字 + 调用的地址 + 被调用的地址
                                // 只有被调用函数地址是原so时，才可以减去基地址
                                if(module2.name.indexOf(so_name)!=-1){
                                console.log("onReceive:",dataSp[0]+",调用的so:",module1.name,",调用函数地址:",ptr(addr1-base_addr),",被调用的so:",module2.name,",被调用的函数地址:",ptr(addr2-base_addr));
                                }else{
                                    console.log("onReceive:",dataSp[0]+",调用的so:",module1.name,",调用函数地址:",ptr(addr1-base_addr),",被调用的so:",module2.name,",被调用的函数地址:",base_addr);
                                }
                            }
                        }catch(err){
                            console.log("onReceive error",dataSp[0],dataSp[1],dataSp[2]);
                        }
                    }
                },

                transform: function (iterator) {
                    var instruction = iterator.next();
                    const startAddress = instruction.address;
                                        // 从ida里面 找到 Java_com_baidu_searchbox_NativeBds_dae1 函数的 代码 在 0xE84 和 0x126C 之间
                    // var isModule = startAddress.compare(base_addr.add(addr)) >= 0 && startAddress.compare(base_addr.add(0x126C)) < 0;
                    var isModule = startAddress.compare(base_addr.add(addr)) >= 0;
                    do{
                        if (isModule){
                            console.log(instruction.address.sub(base_addr) + "\t:\t" + instruction);
                    
                            if(instruction.address.sub(base_addr) == 0x122c){
                                iterator.putCallout((context) => {
                                // var string = Memory.readCString(context["sp"]);
                                // console.log("####  key = " + string)
                                console.log("####  key = " + Memory.readUInt(context.w0))
                                })
                            }
                        }
                        iterator.keep();
                    } while ((instruction = iterator.next()) !== null);
                },

            })
        },onLeave(retval){
            Stalker.unfollow(this.tid);
        }
    })
}