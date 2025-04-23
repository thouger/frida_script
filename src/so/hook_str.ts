//@ts-nocheck
import { log,stacktrace_so,printRegisters } from "../utils/log.js";

export function hook_str(target_str){
        log('Hooking string functions');
        
        // 常见的字符串处理函数列表
        const stringFuncs = [
            // "strlen", "strcmp", "strncmp", "strcpy", "strncpy", 
            // "strcat", "strncat", "strchr", "strrchr", "strstr", 
            
            // "strcpy","strncpy",
            // "strcat",
            // "strncat",
            // "strchr","strrchr","strstr",
            // "memcmp",

            "memcpy",
        ];
        
        // 监控这些函数
        stringFuncs.forEach(funcName => {
            const funcPtr = Module.findExportByName(null, funcName);
            if (funcPtr) {
                log(`Hooking ${funcName} @ ${funcPtr}`);
                
                Interceptor.attach(funcPtr, {
                    onEnter: function(args) {
                        this.funcName = funcName;
                        
                        // 检查第一个和第二个参数
                        for (let i = 0; i < 2; i++) {
                            if (!args[i]) continue;
                            
                            try {
                                // 尝试读取参数作为字符串
                                const str = Memory.readUtf8String(args[i]);
                                if (str && str != null && str != ''){
                                    // log(`[${funcName}] arg${i}: ${str}`);
                                    // if (str && str.includes(target_str)) {
                                        if (str && str.includes("b59feaf6")) {
                                        log(`[${funcName}] arg${i}: ${str}`);
                                        log(stacktrace_so(this.context));
                                    }
                                }
                            } catch (e) {
                                // 可能不是有效的字符串，继续执行
                            }
                        }
                    }
                });
            }
        });
    }