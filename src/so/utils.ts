//@ts-nocheck
import { log,stacktrace_so,printRegisters } from "../utils/log.js";
import { hexdumpAdvanced } from "./BufferUtils.js"

export function hook_dlopen(so_name = null, hook_func = null, so_addr = null) {
    log('hook_dlopen')
    
    // Hook android_dlopen_ext
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    if (android_dlopen_ext != null) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function (args) {
                var soName = args[0].readCString();
                log('soName:'+soName)
                if (so_name && soName.indexOf(so_name) != -1) {
                    log('find so in android_dlopen_ext')
                    this.hook = true;
                }
            },
            onLeave: function (retval) {
                if (this.hook && hook_func) {
                    hook_func(so_addr); // 传入 so_addr 参数
                }
            }
        });
    }
    
    // Hook dlopen
    var dlopen = Module.findExportByName(null, "dlopen");
    if (dlopen != null) {
        Interceptor.attach(dlopen, {
            onEnter: function (args) {
                var soName = args[0].readCString();
                log('soName:'+soName)
                if (so_name && soName.indexOf(so_name) != -1) {
                    log('find so in dlopen')
                    this.hook = true;
                }
            },
            onLeave: function (retval) {
                if (this.hook && hook_func) {
                    hook_func(so_addr); // 传入 so_addr 参数
                }
            }
        });
    }
}

/**
 * 监控字符串内容的简单函数
 * @param {string} so_name - 目标so文件名
*/
export function monitorStrings(so_name) {
    // 基础字符串操作函数
    const functions = [
        'strcpy',
        // 'strcat',
        // 'sprintf',
        // 'snprintf',
        // 'memcpy',
        // 'strncpy'
    ];

    for (const funcName of functions) {
        const address = Module.findExportByName(null, funcName);
        if (!address) continue;

        Interceptor.attach(address, {
            onEnter(args) {
                try {
                    var stacktrace =  stacktrace_so();
                    if(!stacktrace.includes(so_name)) return;

                    switch (funcName) {
                        case 'strcpy':
                        case 'strcat':
                        case 'strncpy': {
                            const sourceStr = Memory.readUtf8String(args[1]);
                            log(`[${funcName}] 字符串内容: ${sourceStr}`);
                            break;
                        }
                        
                        case 'sprintf':
                        case 'snprintf': {
                            const formatStr = Memory.readUtf8String(args[1]);
                            log(`[${funcName}] 格式字符串: ${formatStr}`);
                            break;
                        }
                        
                        case 'memcpy': {
                            try {
                                const size = args[2].toInt32();
                                const content = Memory.readUtf8String(args[1], size);
                                if (content) {
                                    log(`[${funcName}] 复制内容: ${content}`);
                                }
                            } catch (e) {}
                            break;
                        }
                    }
                } catch (e) {
                    log(`[${funcName}] 读取失败: ${e}`);
                }
            },
            
            onLeave(retval) {
                var stacktrace =  stacktrace_so();
                if(!stacktrace.includes(so_name)) return;

                // 检查结果字符串
                if (this.funcName === 'strcpy' || this.funcName === 'sprintf') {
                    try {
                        const result = Memory.readUtf8String(this.args[0]);
                        log(`[${this.funcName}_result] 结果: ${result}`);
                    } catch (e) {}
                }
            }
        });
        
        log(`[*] 已hook ${funcName}`);
    }
}

// 比较通用的hook地址并且打印5个参数。如果参数是地址就打印下内存信息
// 增加两个回调函数参数：onEnterCallback和onLeaveCallback
// 增加so_name参数
export function nativeHookFunction(onEnterCallback, onLeaveCallback, so_name, so_addr) {
    // 在函数开头调用hook_dlopen
    hook_dlopen(so_name, function(dlopen_addr) {
        try {
            var base_addr = Module.getBaseAddress(so_name);
            var hook_addr = base_addr.add(so_addr);
            log("hook_addr:" + hook_addr);
            
            // 添加一个简单的测试 hook 来确认函数是否正常返回
            Interceptor.attach(hook_addr, {
                onEnter: function(args) {
                    try {
                        this.tid=Process.getCurrentThreadId();

                        // 使用printRegisters函数打印寄存器
                        // log("this.context:"+JSON.stringify(this.context, null, 4));
                        // log("x0:"+hexdump(this.context.x0));
                        // log("x1:"+hexdump(this.context.x1));
                        // log("x2:"+hexdump(this.context.x2,{length:5000}));
                        // log("x3:"+hexdump(this.context.x3));
                        // log("x4:"+hexdump(this.context.x4));
                        // log("x8:"+hexdump(this.context.x8));
                        // log("x16:"+hexdump(this.context.x16));
                        // log("x17:"+hexdump(this.context.x17));
                        // log("x18:"+hexdump(this.context.x18));
                        // log("x19:"+hexdump(this.context.x19));
                        // log("x20:"+hexdump(this.context.x20));
                        // log("x21:"+hexdump(this.context.x21));
                        // log("x22:"+hexdump(this.context.x22));
                        // log("x25:"+hexdump(this.context.x25));
                        // log("x28:"+hexdump(this.context.x28));
                        // printRegisters(this.context, null, null);
                        
                        // 如果提供了onEnter回调函数，则调用它
                        // 传递args、this.context和base_addr作为参数
                        if (typeof onEnterCallback === 'function') {
                            onEnterCallback(args, this.context, null, base_addr, hook_addr,this.tid);
                        }
                        
                        // 记录调用栈信息（可选，取消注释以启用）
                        // log("Call stack:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                        //     .map(DebugSymbol.fromAddress).join("\n"));
                    } catch(e) {
                        log("Error in onEnter: " + e.message);
                    }
                },
                onLeave: function(retval) {
                    try {
                        log(`[${this.tid}] - Leave`);

                        Stalker.unfollow(this.tid);

                        if (retval) {
                            log("Return value: " + retval.toString());
                        }
                        
                        // 如果提供了onLeave回调函数，则调用它
                        // 传递retval、this.context和base_addr作为参数
                        if (typeof onLeaveCallback === 'function') {
                            onLeaveCallback(this,retval, this.context, null, base_addr, hook_addr);
                        }
                    } catch(e) {
                        log("Error in onLeave: " + e.message);
                    }
                }
            });
            
            log("Test hook installed");
            
        } catch(e) {
            log("Error in nativeHookFunction:", e.message);
        }
    }, so_addr);
}