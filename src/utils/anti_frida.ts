//@ts-nocheck

function anti_exit() {
    const exit_ptr = Module.findExportByName(null, 'exit');
    console.log('anti_exit', "exit_ptr : " + exit_ptr);
    if (null == exit_ptr) {
        return;
    }
    Interceptor.replace(exit_ptr, new NativeCallback(function (code) {
        if (null == this) {
            return 0;
        }
        var lr = getLR(this.context)
        console.log('exit debug', 'entry, lr: ' + lr);
        return 0;
    }, 'int', ['int', 'int']));
}

function anti_kill() {
    const kill_ptr = Module.findExportByName(null, 'kill');
    console.log('anti_kill', "kill_ptr : " + kill_ptr);

    if (null == kill_ptr) {
        return;
    }

    Interceptor.replace(kill_ptr, new NativeCallback(function (ptid, code) {
        if (null == this) {
            return 0;
        }

        var lr = getLR(this.context)
        console.log('kill debug', 'entry, lr: ' + lr,ptid,code);

        console.log('堆栈打印', '\tBacktrace:\n\t' + Thread.backtrace(this.context,
                Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
            .join('\n\t'));

        return 0;
    }, 'int', ['int', 'int']));
}

/**
 * @state_name: cat /proc/xxx/stat ==> ...(<state_name>) S...
 *
 * anti fgets function include :
 * status->TracerPid, SigBlk, S (sleeping)
 * State->(package) S
 * wchan->SyS_epoll_wait
 */
function anti_fgets() {
    const tag = 'anti_fgets';
    const fgetsPtr = Module.findExportByName(null, 'fgets');
    console.log(tag, 'fgets addr: ' + fgetsPtr);
    if (null == fgetsPtr) {
        return;
    }
    var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
    Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
        if (null == this) {
            return 0;
        }
        var logTag = null;
        // 进入时先记录现场
        const lr = getLR(this.context)
        // 读取原 buffer
        var retval = fgets(buffer, size, fp);

        // var bufstr = (buffer as NativePointer).readCString();
        var bufstr = Memory.readUtf8String(buffer);
        if (null != bufstr) {
            if (bufstr.indexOf("TracerPid:") > -1) {
                buffer.writeUtf8String("TracerPid:\t0");
                logTag = 'TracerPid';
            }
            //State:	S (sleeping)
            else if (bufstr.indexOf("State:\tt (tracing stop)") > -1) {
                buffer.writeUtf8String("State:\tS (sleeping)");
                logTag = 'State';
            }
            // ptrace_stop
            else if (bufstr.indexOf("ptrace_stop") > -1) {
                buffer.writeUtf8String("sys_epoll_wait");
                logTag = 'ptrace_stop';
            }

            //(sankuai.meituan) t
            else if (bufstr.indexOf(") t") > -1) {
                buffer.writeUtf8String(bufstr.replace(") t", ") S"));
                logTag = 'stat_t';
            }

            // SigBlk
            else if (bufstr.indexOf('SigBlk:') > -1) {
                buffer.writeUtf8String('SigBlk:\t0000000000001204');
                logTag = 'SigBlk';
            }
            if (logTag) {
                console.log(tag + " " + logTag, bufstr + " -> " + buffer.readCString() + ' lr: ' + lr +
                    "(" + getModuleByAddr(lr) + ")");

                console.log(logTag+'堆栈打印', '\tBacktrace:\n\t' + Thread.backtrace(this.context,
                        Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
                    .join('\n\t'));
            }
        }
        return retval;
    }, 'pointer', ['pointer', 'int', 'pointer']));
}

function anti_ptrace() {
    var ptrace = Module.findExportByName(null, "ptrace");
    if (null != ptrace) {
        ptrace = ptrace.or(1);
        console.log('anti_ptrace', "ptrace addr: " + ptrace);
        // Interceptor.attach(ptrace, {
        //     onEnter: function (args) {
        //         console.log('anti_ptrace', 'entry');
        //     }
        // });
        Interceptor.replace(ptrace.or(1), new NativeCallback(function (p1, p2, p3, p4) {
            console.log('anti_ptrace', 'entry');
            return 1;
        }, 'long', ['int', "int", 'pointer', 'pointer']));
    }
}

/**
 * 适用于每日优鲜的反调试
 */
function anti_fork() {
    var fork_addr = Module.findExportByName(null, "fork");
    console.log('anti_ptrace', "fork_addr : " + fork_addr);
    if (null != fork_addr) {
        // Interceptor.attach(fork_addr, {
        //     onEnter: function (args) {
        //         console.log('fork_addr', 'entry');
        //     }
        // });
        Interceptor.replace(fork_addr, new NativeCallback(function () {
            console.log('fork_addr', 'entry');
            return -1;
        }, 'int', []));
    }
}

function getModuleByAddr(addr) {
    var result = null;
    Process.enumerateModules().forEach(function (module) {
        if (module.base <= addr && addr <= (module.base.add(module.size))) {
            result = JSON.stringify(module);
            return false; // 跳出循环
        }
    });
    return result;
}

function getLR(context) {
    if (Process.arch == 'arm') {
        return context.lr;
    }
    else if (Process.arch == 'arm64') {
        return context.lr;
    }
    else {
     //  console.log('getLR', 'not support current arch: ' + Process.arch);
    }
    return ptr(0);
}




var aaa,bbb,ccc;
var ss = false
Interceptor.attach(Module.findExportByName(null, "readlink"),{
    onEnter: function(args){
        aaa = args[0];
        bbb = args[1];
        ccc = args[2];
        },
    onLeave: function(retval){
        if(bbb.readCString().indexOf("frida")!==-1 ||
            bbb.readCString().indexOf("gum-js-loop")!==-1||
            bbb.readCString().indexOf("gmain")!==-1 ||
            bbb.readCString().indexOf("linjector")!==-1){
            
            console.log('\nreadlink(' + 's1="' + aaa.readCString() + '"' + ', s2="' + bbb.readCString() + '"' + ', s3="' + ccc + '"' + ')');
            bbb.writeUtf8String("/system/framework/boot.art")
            console.log("replce with: "+bbb.readCString())
            retval.replace(0x1A)
            //console.log("retval: "+retval)
        }
    }
});


Interceptor.attach(Module.findExportByName(null, "strstr"),{
    onEnter: function(args){
        if(args[0].readCString().indexOf("frida")!==-1
        ||args[1].readCString().indexOf("frida")!==-1 ||
        args[0].readCString().indexOf("gum-jsloop")!==-1||args[1].readCString().indexOf("gum-js-loop")!==-1||
        args[0].readCString().indexOf("gmain")!==-1
        ||args[1].readCString().indexOf("gmain")!==-1 ||
        args[0].readCString().indexOf("linjector")!==-1
        ||args[1].readCString().indexOf("linjector")!==-1){
            //console.log("\nlibDexHelper.so base address:"+Module.findBaseAddress("libDexHelper.so"))
            console.log('\nstrstr(' + 's1="' + args[0].readCString() + '"' + ', s2="' + args[1].readCString() + '"' + ')');
            //console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
            this.frida = Boolean(1);
            //console.log("this.frida: ",this.frida);
        }
    },
    onLeave: function(retval){
        if (this.frida) {
            retval.replace(ptr("0x0"));
        }
    }
});


const openPtr = Module.getExportByName('libc.so', 'open');
const open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);

var readPtr = Module.findExportByName("libc.so", "read");
var read = new NativeFunction(readPtr, 'int', ['int', 'pointer', "int"]);
var fakePath = "/data/data/com.xingin.xhs/maps";//这里要改包名
var file = new File(fakePath, "w");
var buffer = Memory.alloc(512);

var fakePath2 = "/data/data/com.xingin.xhs/task";
var file2 = new File(fakePath2, "w");
var buffer2 = Memory.alloc(512);

Interceptor.replace(openPtr, new NativeCallback(function (pathnameptr, flag) {
    var pathname = Memory.readUtf8String(pathnameptr);
    var realFd = open(pathnameptr, flag);
    console.log("open:", pathname)
    //路径是否包含maps 和task
    if (pathname.indexOf("maps") >= 0 || pathname.indexOf("status") >= 0 || pathname.indexOf("cmdline") >= 0) {
        var temp = pathname.indexOf("maps") >= 0 ? 1:2;
        //包含maps则map为1 task为2
        switch (temp) {
            case 1://maps
            {
               // console.log("open maps:", pathname);
                while (parseInt(read(realFd, buffer, 512)) !== 0) {
                    var oneLine = Memory.readCString(buffer);
                //   if(pathname=="/proc/self/maps"){
                //     console.log("maps 打印 oneLine: ",oneLine);
                //   }
            
                    if (oneLine.indexOf("tmp") === -1) {
                        // === 比== 更加严格 ==类型不匹配再转化匹配值 ===类型不匹配就是false
                        // 就是online 不包含tmp 则写入/data/data/com.wujie.chengxin/maps中
                        // 因为Frida在运行时会先确定/data/local/tmp路径下是否有re.frida.server文件夹，
                        // 若没有则创建该文件夹并存放fridaagent.so等文件
                        // console.log("write :",oneLine);
                        file.write(oneLine);
                    } else {
                        
                    }
                }
                console.log("外打印 maps oneLine: ",oneLine)
                var filename = Memory.allocUtf8String(fakePath);
                return open(filename, flag);
                break;
            }
            case 2://task
            {
                console.log("open task:", pathname);
                while(parseInt(read(realFd, buffer2, 512)) !== 0){
                    var oneLine = Memory.readCString(buffer2);
                    console.log("打印 oneLine: ",oneLine)

                    if(oneLine.indexOf("gum-js-loop")!=-1){
                        var replaceStr = "AAAAAAAAAA"
                        oneLine = oneLine.replace("gum-js-loop", replaceStr)
                        //console.log(oneLine)
                    }
                    if(oneLine.indexOf("pool-frida")!=-1){
                         var replaceStr = "BBBBBBB"
                        oneLine = oneLine.replace("pool-frida", replaceStr)
                        //console.log(oneLine)
                    }
                    if(oneLine.indexOf("gmain")!=-1){
                         var replaceStr = "CCCCCCC"  //最终只有这里匹配上了
                        oneLine = oneLine.replace("gmain", replaceStr)
                        //console.log(oneLine)
                    }


                    file2.write(oneLine);

                }
                console.log("外打印 oneLine: ",oneLine)
                var filename = Memory.allocUtf8String(fakePath2);
                return open(filename, flag);//把伪造的路径打开返回
                break;
            }
        }
    }
    var fd = open(pathnameptr, flag);
    // Thread.sleep(1)
    return fd;
    }, 'int', ['pointer', 'int']));

export function antiFrida() {
    anti_kill();
    anti_ptrace();
    anti_fgets();
    anti_exit();
    anti_fork();
}