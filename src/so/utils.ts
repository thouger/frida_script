//@ts-nocheck
import { log,stacktrace_so,printRegisters } from "../utils/log.js";
import { hexdumpAdvanced } from "./BufferUtils.js"

// 全局回调管理器
const dlopenCallbacks = {};
let dlopenHooked = false;

export function hook_dlopen(so_name = null, hook_func = null, so_addr = null) {
    log('[+] hook_dlopen for: ' + so_name)

    // 首先检查 so 是否已经加载
    try {
        var existingModule = Process.findModuleByName(so_name);
        if (existingModule) {
            log('[!] WARNING: ' + so_name + ' is already loaded at: ' + existingModule.base);
            log('[!] The SO was loaded before hook_dlopen was called!');

            // 如果已经加载，直接调用回调
            if (hook_func) {
                log('[+] Calling hook_func immediately since SO is already loaded');
                hook_func(so_addr);
            }
            return;
        } else {
            log('[+] ' + so_name + ' is not loaded yet, setting up dlopen hooks...');
        }
    } catch (e) {
        log('[-] Error checking for existing module: ' + e.message);
    }

    // 注册回调
    if (!dlopenCallbacks[so_name]) {
        dlopenCallbacks[so_name] = [];
    }
    dlopenCallbacks[so_name].push({ func: hook_func, addr: so_addr });

    // 只 hook 一次
    if (dlopenHooked) {
        log('[+] dlopen hooks already installed, callback registered');
        return;
    }
    dlopenHooked = true;

    var android_dlopen_ext = Module.findGlobalExportByName("android_dlopen_ext");
    log('[+] android_dlopen_ext: ' + android_dlopen_ext);

    if (android_dlopen_ext != null) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function (args) {
                var soName = args[0].readCString();
                this.soName = soName;

                // 检查是否有匹配的回调
                for (let name in dlopenCallbacks) {
                    if (soName.indexOf(name) != -1) {
                        this.matchedSo = name;
                        log('[+] Found target SO: ' + soName);
                        break;
                    }
                }
            },
            onLeave: function (retval) {
                if (this.matchedSo) {
                    log('[+] android_dlopen_ext onLeave for: ' + this.matchedSo);

                    const callbacks = dlopenCallbacks[this.matchedSo];
                    if (callbacks && callbacks.length > 0) {
                        log('[+] ' + this.matchedSo + ' 加载完成 (android_dlopen_ext), executing ' + callbacks.length + ' callbacks');

                        // 执行所有回调
                        callbacks.forEach(cb => {
                            if (cb.func) {
                                try {
                                    cb.func(cb.addr);
                                } catch (e) {
                                    log('[-] Error executing callback: ' + e.message);
                                }
                            }
                        });

                        // 清空回调列表，避免重复执行
                        delete dlopenCallbacks[this.matchedSo];
                    }
                }
            }
        });
    }

    var dlopen = Module.findGlobalExportByName("dlopen");
    log('[+] dlopen: ' + dlopen);

    if (dlopen != null) {
        Interceptor.attach(dlopen, {
            onEnter: function (args) {
                var soName = args[0].readCString();
                this.soName = soName;

                // 检查是否有匹配的回调
                for (let name in dlopenCallbacks) {
                    if (soName.indexOf(name) != -1) {
                        this.matchedSo = name;
                        log('[+] Found target SO in dlopen: ' + soName);
                        break;
                    }
                }
            },
            onLeave: function (retval) {
                if (this.matchedSo) {
                    log('[+] dlopen onLeave for: ' + this.matchedSo);

                    const callbacks = dlopenCallbacks[this.matchedSo];
                    if (callbacks && callbacks.length > 0) {
                        log('[+] ' + this.matchedSo + ' 加载完成 (dlopen), executing ' + callbacks.length + ' callbacks');

                        // 执行所有回调
                        callbacks.forEach(cb => {
                            if (cb.func) {
                                try {
                                    cb.func(cb.addr);
                                } catch (e) {
                                    log('[-] Error executing callback: ' + e.message);
                                }
                            }
                        });

                        // 清空回调列表，避免重复执行
                        delete dlopenCallbacks[this.matchedSo];
                    }
                }
            }
        });
    }
}

/**
 * 智能参数打印器 - 自动识别参数类型并选择合适的打印方式
 * @param {NativePointer} value - 要打印的参数值
 * @param {Object} options - 打印选项
 * @returns {string} 格式化的输出
 */
function smartPrintArg(value, options = {}) {
    const {
        lengthFrom = null,     // 从哪个参数获取长度，如 'args[1]' 或直接传值
        readMethod = 'auto',   // 读取方式: 'auto', 'u32', 'u64', 'string', 'hexdump'
        maxLength = 256,       // hexdump 的最大长度
        label = ''             // 标签
    } = options;

    try {
        let output = label ? `${label}: ` : '';

        // 如果是null或undefined
        if (!value || value.isNull()) {
            return output + 'NULL';
        }

        // 自动检测模式
        if (readMethod === 'auto') {
            // 尝试读取为字符串
            try {
                const str = value.readUtf8String(64);
                if (str && /^[\x20-\x7E]+$/.test(str)) {
                    return output + `"${str}"`;
                }
            } catch (e) {}

            // 尝试读取为整数
            try {
                const num = value.toInt32();
                if (num > 0 && num < 0x10000) {
                    return output + `${num} (0x${num.toString(16)})`;
                }
            } catch (e) {}
        }

        // 指定读取方式
        switch (readMethod) {
            case 'u32':
                return output + `${value.readU32()} (0x${value.readU32().toString(16)})`;
            case 'u64':
                return output + `${value.readU64()} (0x${value.readU64().toString(16)})`;
            case 'string':
                return output + `"${value.readUtf8String()}"`;
            case 'hexdump':
                const len = lengthFrom || maxLength;
                return output + '\n' + hexdump(value, { length: len });
        }

        // 默认: 打印地址
        return output + value.toString();
    } catch (e) {
        return `${label ? label + ': ' : ''}[无法读取: ${e.message}]`;
    }
}

/**
 * 智能打印参数数组
 * @param {Array} args - 参数数组
 * @param {Object|Array} config - 配置对象或配置数组
 *
 * 配置示例:
 * - ['hexdump:1'] - args[0] 以 hexdump 打印，长度从 args[1] 获取
 * - ['string', 'u32', 'hexdump:100'] - args[0]字符串, args[1]整数, args[2] hexdump(长度100)
 * - {0: {type: 'hexdump', lengthFrom: 'args[1]'}, 2: {type: 'string'}}
 */
function smartPrintArgs(args, config) {
    const results = [];

    if (Array.isArray(config)) {
        // 数组配置模式
        config.forEach((cfg, idx) => {
            if (typeof cfg === 'string') {
                const parts = cfg.split(':');
                const type = parts[0];
                const lengthArg = parts[1];

                let options = { label: `args[${idx}]`, readMethod: type };

                if (lengthArg) {
                    // 支持 'hexdump:1' 表示长度从 args[1] 获取
                    if (/^\d+$/.test(lengthArg)) {
                        const lengthIdx = parseInt(lengthArg);
                        try {
                            options.lengthFrom = args[lengthIdx].toInt32();
                        } catch (e) {
                            options.maxLength = 256;
                        }
                    } else {
                        options.maxLength = parseInt(lengthArg) || 256;
                    }
                }

                results.push(smartPrintArg(args[idx], options));
            }
        });
    } else if (typeof config === 'object') {
        // 对象配置模式
        for (let idx in config) {
            const cfg = config[idx];
            const argIdx = parseInt(idx);

            let options = {
                label: `args[${argIdx}]`,
                readMethod: cfg.type || 'auto'
            };

            if (cfg.lengthFrom) {
                // 支持 lengthFrom: 'args[1]' 或 lengthFrom: 1
                if (typeof cfg.lengthFrom === 'string') {
                    const match = cfg.lengthFrom.match(/args\[(\d+)\]/);
                    if (match) {
                        const lenIdx = parseInt(match[1]);
                        try {
                            options.lengthFrom = args[lenIdx].toInt32();
                        } catch (e) {}
                    }
                } else {
                    try {
                        options.lengthFrom = args[cfg.lengthFrom].toInt32();
                    } catch (e) {}
                }
            }

            results.push(smartPrintArg(args[argIdx], options));
        }
    }

    return results.join('\n');
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
        const address = Module.findGlobalExportByName(funcName);
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
                            const sourceStr = args[1].readUtf8String();
                            log(`[${funcName}] 字符串内容: ${sourceStr}`);
                            break;
                        }

                        case 'sprintf':
                        case 'snprintf': {
                            const formatStr = args[1].readUtf8String();
                            log(`[${funcName}] 格式字符串: ${formatStr}`);
                            break;
                        }

                        case 'memcpy': {
                            try {
                                const size = args[2].toInt32();
                                const content = args[1].readUtf8String(size);
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
                        const result = this.args[0].readUtf8String();
                        log(`[${this.funcName}_result] 结果: ${result}`);
                    } catch (e) {}
                }
            }
        });
        
        log(`[*] 已hook ${funcName}`);
    }
}

/**
 * （已废弃）通用的 native hook 函数 - 支持多种调用方式
 *
 * 推荐使用:
 * - hook_so_function (在 hook_func.ts) - 基础 hook
 * - trace_so_function (在 hook_func.ts) - Stalker trace
 *
 * 保留此函数仅为向后兼容
 *
 * 用法1 - 最简模式（只传 so_name 和 offset）:
 *   native_hook("libEncryptor.so", 0x2BD8)
 *   // 自动打印进入/离开日志
 *
 * 用法2 - 智能参数打印模式（推荐）:
 *   native_hook("libEncryptor.so", 0x2BD8, {
 *     logEnter: true,
 *     logLeave: true,
 *     // 智能打印参数：'hexdump:1' 表示 args[0] 用 hexdump 打印，长度从 args[1] 获取
 *     argsFormat: ['hexdump:1', 'u32'],  // args[0]=hexdump, args[1]=u32整数
 *     // 保存参数供 onLeave 使用
 *     saveArgs: [2, 3],  // 保存 args[2] 和 args[3] 到 this.arg2 和 this.arg3
 *     // 在 onLeave 时打印保存的参数
 *     onLeaveArgs: [{
 *       from: 'thisContext.arg2',     // 读取 this.arg2
 *       type: 'hexdump',               // 使用 hexdump 打印
 *       lengthFrom: 'thisContext.arg3', // 长度从 this.arg3 读取
 *       lengthMethod: 'u32'            // arg3 是 u32 类型
 *     }]
 *   })
 *
 * 用法3 - 带寄存器打印:
 *   // 打印指定寄存器
 *   native_hook("libEncryptor.so", 0x2BD8, {
 *     logRegs: ['x0', 'x1', 'x2']  // 只打印 x0, x1, x2
 *   })
 *   // 打印所有寄存器
 *   native_hook("libEncryptor.so", 0x2BD8, {
 *     logRegs: []  // 空数组表示打印整个 context
 *   })
 *
 * 用法4 - 启用 Stalker trace（追踪函数调用链）:
 *   native_hook("libEncryptor.so", 0x2BD8, {
 *     enableTrace: true,              // 启用函数调用追踪
 *     traceModule: "libEncryptor.so"  // 可选，默认为当前 so_name
 *   })
 *   // 输出示例:
 *   // libEncryptor.so!0x8000 <- libEncryptor.so!0x2BD8 depth:1
 *   // libEncryptor.so!0x8100 <- libEncryptor.so!0x8000 depth:2
 *
 * 用法5 - 自定义逻辑:
 *   native_hook("libEncryptor.so", 0x2BD8, {
 *     customEnter: function(args, context, retval, base_addr, hook_addr, tid) {
 *       console.log("自定义进入逻辑");
 *       // 使用 hexdumpAdvanced 等工具
 *     },
 *     customLeave: function(thisContext, retval, context, args, base_addr, hook_addr) {
 *       console.log("自定义离开逻辑");
 *     }
 *   })
 *
 * 用法6 - 完整模式（完全自定义回调）:
 *   native_hook(
 *     function onEnter(args, context, retval, base_addr, hook_addr, currentThreadId) {
 *       this.arg2 = args[2];
 *       this.arg3 = args[3];
 *       console.log("sub_2BD8:", hexdump(args[0], {length: parseInt(args[1])}));
 *     },
 *     function onLeave(thisContext, retval, context, args, base_addr, hook_addr) {
 *       console.log("结果:", hexdump(thisContext.arg2, {length: thisContext.arg3.readU32()}));
 *     },
 *     "libEncryptor.so",
 *     0x2BD8
 *   );
 */
export function native_hook(onEnterCallback, onLeaveCallback, so_name, so_addr) {
    // 智能判断调用模式
    // 如果第一个参数是字符串，说明是简单模式
    if (typeof onEnterCallback === 'string') {
        // 参数重新映射：native_hook(so_name, so_addr, options)
        const actualSoName = onEnterCallback;
        const actualSoAddr = onLeaveCallback;
        const options = so_name || {};

        const {
            logEnter = true,      // 是否记录进入
            logLeave = true,      // 是否记录离开
            logArgs = false,      // 是否打印参数（简单模式）
            logRetval = false,    // 是否打印返回值
            logRegs = undefined,  // 要打印的寄存器列表，如 ['x0', 'x1']。undefined=不打印，[]=打印所有，['x0']=打印指定
            argsFormat = null,    // 智能参数格式配置，如 ['hexdump:1', 'u32']
            saveArgs = [],        // 要保存到 this 的参数索引，如 [2, 3] 保存 args[2] 和 args[3]
            onLeaveArgs = null,   // onLeave 时的参数打印配置，支持 'this.arg2:hexdump:this.arg3.u32'
            customEnter = null,   // 自定义 onEnter 逻辑
            customLeave = null,   // 自定义 onLeave 逻辑
            enableTrace = false,  // 是否启用 Stalker trace
            traceModule = null    // 要 trace 的模块名，默认为当前 so_name
        } = options;

        const defaultOnEnter = function(args, context, retval, base_addr, hook_addr, currentThreadId) {
            if (logEnter) {
                log(`[+] 进入 ${actualSoName}+0x${actualSoAddr.toString(16)}`);
            }

            // 智能打印参数
            if (argsFormat) {
                log(smartPrintArgs(args, argsFormat));
            }

            // 打印寄存器
            // logRegs === undefined: 不打印
            // logRegs === []: 打印所有寄存器
            // logRegs === ['x0', 'x1']: 只打印指定寄存器
            if (logRegs !== undefined && logRegs !== null) {
                if (logRegs.length === 0) {
                    // 空数组表示打印所有寄存器
                    printRegisters(context);
                } else if (logRegs.length > 0) {
                    // 打印指定寄存器
                    printRegisters(context, logRegs);
                }
            }

            // 保存参数到 this 上下文
            if (saveArgs && saveArgs.length > 0) {
                saveArgs.forEach(idx => {
                    this[`arg${idx}`] = args[idx];
                });
            }

            // Stalker trace 功能
            if (enableTrace) {
                const targetModule = traceModule || actualSoName;
                const module_object = Process.findModuleByName(targetModule);

                if (module_object) {
                    // 排除其他模块，只trace目标模块
                    const allmodules = Process.enumerateModules();
                    allmodules.forEach(function (item) {
                        if (item.name != targetModule) {
                            const memoryRange = {
                                base: item.base,
                                size: item.size
                            };
                            Stalker.exclude(memoryRange);
                        }
                    });

                    this.start_follow = true;
                    this.tid = currentThreadId;

                    Stalker.follow(this.tid, {
                        events: {
                            call: true,
                            ret: false,
                            exec: false,
                            block: false,
                            compile: false
                        },
                        onReceive(events) {
                            const parse_events = Stalker.parse(events);
                            for(let index in parse_events) {
                                const event = parse_events[index];
                                const type = event[0];
                                if (type == "call") {
                                    const callee = event[1];
                                    const caller = event[2];
                                    const m_callee = Process.findModuleByAddress(callee);
                                    if (m_callee != null && m_callee.name == targetModule) {
                                        const m_caller = Process.findModuleByAddress(caller);
                                        if(m_caller != null) {
                                            log(m_callee.name+"!"+(callee).sub(m_callee.base) + " <- " + m_caller.name + "!" + (caller).sub(m_caller.base) + " depth:" + event[3]);
                                        } else {
                                            log(m_callee.name+"!"+(callee).sub(m_callee.base) + " <- " + caller + " depth:" + event[3]);
                                        }
                                    }
                                }
                            }
                        }
                    });
                    log(`[Stalker] 开始 trace 模块: ${targetModule}`);
                } else {
                    log(`[-] 无法找到模块: ${targetModule}`);
                }
            }

            if (customEnter) {
                customEnter(args, context, retval, base_addr, hook_addr, currentThreadId);
            }
        };

        const defaultOnLeave = function(thisContext, retval, context, args, base_addr, hook_addr) {
            // 停止 Stalker trace
            if (enableTrace && thisContext.start_follow && thisContext.tid) {
                Stalker.unfollow(thisContext.tid);
                log(`[Stalker] 停止 trace 线程: ${thisContext.tid}`);
            }

            if (logLeave) {
                log(`[-] 离开 ${actualSoName}+0x${actualSoAddr.toString(16)}`);
            }

            if (logRetval && retval) {
                log("返回值: " + retval);
            }

            // 智能打印 onLeave 参数
            if (onLeaveArgs && Array.isArray(onLeaveArgs)) {
                onLeaveArgs.forEach(cfg => {
                    try {
                        // 解析 from 路径，如 'thisContext.arg2'
                        let argValue = thisContext;
                        const fromParts = cfg.from.replace('thisContext.', '').split('.');
                        for (let part of fromParts) {
                            argValue = argValue[part];
                        }

                        let options = {
                            label: cfg.from,
                            readMethod: cfg.type || 'auto'
                        };

                        // 解析长度来源
                        if (cfg.lengthFrom) {
                            let lengthValue = thisContext;
                            const lengthParts = cfg.lengthFrom.replace('thisContext.', '').split('.');

                            for (let part of lengthParts) {
                                lengthValue = lengthValue[part];
                            }

                            // 根据 lengthMethod 读取长度
                            if (cfg.lengthMethod === 'u32') {
                                options.lengthFrom = lengthValue.readU32();
                            } else if (cfg.lengthMethod === 'u64') {
                                options.lengthFrom = lengthValue.readU64();
                            } else if (cfg.lengthMethod === 'int') {
                                options.lengthFrom = lengthValue.toInt32();
                            } else {
                                // 默认尝试读取为整数
                                options.lengthFrom = lengthValue.toInt32();
                            }
                        }

                        log(smartPrintArg(argValue, options));
                    } catch (e) {
                        log(`参数打印失败 (${cfg.from}): ${e.message}`);
                        log(`Stack: ${e.stack}`);
                    }
                });
            }

            if (customLeave) {
                customLeave(thisContext, retval, context, args, base_addr, hook_addr);
            }
        };

        // 递归调用自己，使用完整模式
        native_hook(defaultOnEnter, defaultOnLeave, actualSoName, actualSoAddr);
        return;
    }

    // 完整模式：native_hook(onEnterCallback, onLeaveCallback, so_name, so_addr)
    log("[*] native_hook called with so_name: " + so_name + ", offset: 0x" + so_addr.toString(16));

    // 使用hook_dlopen等待SO加载
    hook_dlopen(so_name, function(dlopen_addr) {
        log("[*] hook_dlopen callback triggered for: " + so_name);

        try {
            log("[*] Attempting to find module: " + so_name);
            var module = Process.findModuleByName(so_name);
            if (!module) {
                log("[-] Failed to find module " + so_name);
                return;
            }
            var base_addr = module.base;
            var hook_addr = base_addr.add(so_addr);

            log("[+] ========== Hook Setup Info ==========");
            log("[+] Module name: " + so_name);
            log("[+] Base address: " + base_addr);
            log("[+] Offset: 0x" + so_addr.toString(16));
            log("[+] Hook address: " + hook_addr);
            log("[+] Module range: " + base_addr + " - " + base_addr.add(module.size));

            // 验证地址是否在模块范围内
            if (hook_addr.compare(base_addr) < 0 || hook_addr.compare(base_addr.add(module.size)) >= 0) {
                log("[-] ERROR: Hook address is outside module range!");
                return;
            }

            // 读取目标地址的指令
            try {
                var instruction = Instruction.parse(hook_addr);
                log("[+] Instruction at hook address: " + instruction);
            } catch (e) {
                log("[-] WARNING: Cannot parse instruction at hook address: " + e.message);
            }

            log("[+] ========================================");

            // 添加一个简单的测试 hook 来确认函数是否正常返回
            log("[*] Calling Interceptor.attach on: " + hook_addr);
            Interceptor.attach(hook_addr, {
                onEnter: function(args) {
                    try {
                        this.tid = Process.getCurrentThreadId();
                        log("[+] !!!!! Function called at: " + hook_addr + " !!!!!");

                        // 使用printRegisters函数打印寄存器
                        // log("this.context:" + JSON.stringify(this.context, null, 4));
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
                        // 使用 .call(this) 来传递 this 上下文
                        if (typeof onEnterCallback === 'function') {
                            onEnterCallback.call(this, args, this.context, null, base_addr, hook_addr, this.tid);
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

                        // 只在启用了 Stalker trace 时才停止
                        if (this.start_follow && this.tid) {
                            Stalker.unfollow(this.tid);
                        }

                        if (retval) {
                            log("Return value: " + retval.toString());
                        }

                        // 如果提供了onLeave回调函数，则调用它
                        // 传递retval、this.context和base_addr作为参数
                        if (typeof onLeaveCallback === 'function') {
                            onLeaveCallback(this, retval, this.context, null, base_addr, hook_addr);
                        }
                    } catch(e) {
                        log("Error in onLeave: " + e.message);
                    }
                }
            });

            log("[+] ========== Hook Successfully Installed ==========");
            log("[+] Module: " + so_name);
            log("[+] Offset: 0x" + so_addr.toString(16));
            log("[+] Address: " + hook_addr);
            log("[+] Waiting for function to be called...");
            log("[+] ===================================================");

        } catch(e) {
            log("[-] Error in native_hook: " + e.message);
            // 打印详细错误信息用于调试
            log("[-] Stack trace: " + e.stack);
        }
    }, so_addr);
}