//@ts-nocheck
import { hook_dlopen } from "./utils.js";
import { log, printRegisters } from "../utils/log.js";

// ==================== 辅助函数 ====================

/**
 * 智能参数打印器 - 自动识别参数类型并选择合适的打印方式
 */
function smartPrintArg(value, options = {}) {
    const {
        lengthFrom = null,
        readMethod = 'auto',
        maxLength = 256,
        label = ''
    } = options;

    try {
        let output = label ? `${label}: ` : '';

        if (!value || value.isNull()) {
            return output + 'NULL';
        }

        if (readMethod === 'auto') {
            try {
                const str = value.readUtf8String(64);
                if (str && /^[\x20-\x7E]+$/.test(str)) {
                    return output + `"${str}"`;
                }
            } catch (e) {}

            try {
                const num = value.toInt32();
                if (num > 0 && num < 0x10000) {
                    return output + `${num} (0x${num.toString(16)})`;
                }
            } catch (e) {}
        }

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

        return output + value.toString();
    } catch (e) {
        return `${label ? label + ': ' : ''}[无法读取: ${e.message}]`;
    }
}

/**
 * 智能打印参数数组
 */
function smartPrintArgs(args, config) {
    const results = [];

    if (Array.isArray(config)) {
        config.forEach((cfg, idx) => {
            if (typeof cfg === 'string') {
                const parts = cfg.split(':');
                const type = parts[0];
                const lengthArg = parts[1];

                let options = { label: `args[${idx}]`, readMethod: type };

                if (lengthArg) {
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
        for (let idx in config) {
            const cfg = config[idx];
            const argIdx = parseInt(idx);

            let options = {
                label: `args[${argIdx}]`,
                readMethod: cfg.type || 'auto'
            };

            if (cfg.lengthFrom) {
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

// ==================== 核心函数 ====================

/**
 * Stalker 追踪 SO 函数调用链 - 纯净版
 * 只负责 trace，不做其他事情
 *
 * @param {string} so_name - SO 文件名
 * @param {number} offset - 函数偏移地址
 * @param {string} trace_module - 要追踪的模块名（可选，默认为 so_name）
 *
 * 用法示例:
 * trace_so_function("libEncryptor.so", 0x2BD8);
 * trace_so_function("libEncryptor.so", 0x2BD8, "libEncryptor.so");
 */
export function trace_so_function(so_name, offset, trace_module = null) {
    const target_module = trace_module || so_name;

    hook_dlopen(so_name, function() {
        try {
            const module = Process.findModuleByName(so_name);
            if (!module) {
                log(`[-] Failed to find module ${so_name}`);
                return;
            }

            const target_addr = module.base.add(offset);
            log(`[+] Tracing ${so_name}+0x${offset.toString(16)}`);

            Interceptor.attach(target_addr, {
                onEnter: function(args) {
                    const tid = Process.getCurrentThreadId();
                    this.tid = tid;

                    // 排除其他模块，只 trace 目标模块
                    const module_to_trace = Process.findModuleByName(target_module);
                    if (!module_to_trace) {
                        log(`[-] Module not found: ${target_module}`);
                        return;
                    }

                    const allmodules = Process.enumerateModules();
                    allmodules.forEach(function(item) {
                        if (item.name !== target_module) {
                            Stalker.exclude({
                                base: item.base,
                                size: item.size
                            });
                        }
                    });

                    log(`[Stalker] 开始 trace 模块: ${target_module}`);

                    // 记录最小 depth，用于标准化输出
                    this.minDepth = null;

                    Stalker.follow(tid, {
                        events: {
                            call: true,
                            ret: false,
                            exec: false,
                            block: false,
                            compile: false
                        },
                        onReceive(events) {
                            const parse_events = Stalker.parse(events);

                            // 第一遍扫描：找到最小 depth
                            let minDepth = 0;
                            for (let index in parse_events) {
                                const event = parse_events[index];
                                if (event[0] === "call" && event[3] < minDepth) {
                                    minDepth = event[3];
                                }
                            }

                            // 第二遍：输出并标准化 depth（从 0 开始）
                            for (let index in parse_events) {
                                const event = parse_events[index];
                                const type = event[0];
                                if (type === "call") {
                                    const target = event[1];  // 被调用的地址
                                    const source = event[2];  // 调用来源地址
                                    const rawDepth = event[3];
                                    const normalizedDepth = rawDepth - minDepth;  // 标准化为从 0 开始

                                    const m_target = Process.findModuleByAddress(target);
                                    if (m_target != null && m_target.name === target_module) {
                                        const m_source = Process.findModuleByAddress(source);
                                        if (m_source != null) {
                                            log(m_source.name + "!" + source.sub(m_source.base) +
                                                " -> " + m_target.name + "!" + target.sub(m_target.base) +
                                                " depth:" + normalizedDepth);
                                        } else {
                                            log(source +
                                                " -> " + m_target.name + "!" + target.sub(m_target.base) +
                                                " depth:" + normalizedDepth);
                                        }
                                    }
                                }
                            }
                        }
                    });
                },
                onLeave: function(retval) {
                    if (this.tid) {
                        Stalker.unfollow(this.tid);
                        log(`[Stalker] 停止 trace 线程: ${this.tid}`);
                    }
                }
            });

        } catch (e) {
            log(`[-] Error in trace_so_function: ${e.message}`);
        }
    });
}

/**
 * 通用的 native hook 函数 - 支持多种调用方式
 *
 * 用法1 - 最简模式（只传 so_name 和 offset）:
 *   native_hook("libEncryptor.so", 0x2BD8)
 *
 * 用法2 - 智能参数打印模式:
 *   native_hook("libEncryptor.so", 0x2BD8, {
 *     logEnter: true,
 *     argsFormat: ['hexdump:1', 'u32'],
 *     saveArgs: [2, 3],
 *     onLeaveArgs: [{
 *       from: 'thisContext.arg2',
 *       type: 'hexdump',
 *       lengthFrom: 'thisContext.arg3',
 *       lengthMethod: 'u32'
 *     }]
 *   })
 *
 * 用法3 - 带寄存器打印:
 *   native_hook("libEncryptor.so", 0x2BD8, {
 *     logRegs: ['x0', 'x1', 'x2']
 *   })
 *
 * 用法4 - 自定义逻辑:
 *   native_hook("libEncryptor.so", 0x2BD8, {
 *     customEnter: function(args, context, retval, base_addr, hook_addr, tid) {},
 *     customLeave: function(thisContext, retval, context, args, base_addr, hook_addr) {}
 *   })
 *
 * 用法5 - 完整模式（完全自定义回调）:
 *   native_hook(
 *     function onEnter(args, context, retval, base_addr, hook_addr, currentThreadId) {
 *       this.arg2 = args[2];
 *     },
 *     function onLeave(thisContext, retval, context, args, base_addr, hook_addr) {
 *       console.log(thisContext.arg2);
 *     },
 *     "libEncryptor.so",
 *     0x2BD8
 *   );
 */
export function native_hook(onEnterCallback, onLeaveCallback, so_name, so_addr) {
    // 智能判断调用模式
    if (typeof onEnterCallback === 'string') {
        // 参数重新映射：native_hook(so_name, so_addr, options)
        const actualSoName = onEnterCallback;
        const actualSoAddr = onLeaveCallback;
        const options = so_name || {};

        const {
            logEnter = true,
            logLeave = true,
            logArgs = false,
            logRetval = false,
            logRegs = undefined,
            argsFormat = null,
            saveArgs = [],
            onLeaveArgs = null,
            customEnter = null,
            customLeave = null
        } = options;

        const defaultOnEnter = function(args, context, retval, base_addr, hook_addr, currentThreadId) {
            if (logEnter) {
                log(`[+] 进入 ${actualSoName}+0x${actualSoAddr.toString(16)}`);
            }

            if (argsFormat) {
                log(smartPrintArgs(args, argsFormat));
            }

            if (logRegs !== undefined && logRegs !== null) {
                if (logRegs.length === 0) {
                    printRegisters(context);
                } else if (logRegs.length > 0) {
                    printRegisters(context, logRegs);
                }
            }

            if (saveArgs && saveArgs.length > 0) {
                saveArgs.forEach(idx => {
                    this[`arg${idx}`] = args[idx];
                });
            }

            if (customEnter) {
                customEnter.call(this, args, context, retval, base_addr, hook_addr, currentThreadId);
            }
        };

        const defaultOnLeave = function(thisContext, retval, context, args, base_addr, hook_addr) {
            if (logLeave) {
                log(`[-] 离开 ${actualSoName}+0x${actualSoAddr.toString(16)}`);
            }

            if (logRetval && retval) {
                log("返回值: " + retval);
            }

            if (onLeaveArgs && Array.isArray(onLeaveArgs)) {
                onLeaveArgs.forEach(cfg => {
                    try {
                        let argValue = thisContext;
                        const fromParts = cfg.from.replace('thisContext.', '').split('.');
                        for (let part of fromParts) {
                            argValue = argValue[part];
                        }

                        let options = {
                            label: cfg.from,
                            readMethod: cfg.type || 'auto'
                        };

                        if (cfg.lengthFrom) {
                            let lengthValue = thisContext;
                            const lengthParts = cfg.lengthFrom.replace('thisContext.', '').split('.');

                            for (let part of lengthParts) {
                                lengthValue = lengthValue[part];
                            }

                            if (cfg.lengthMethod === 'u32') {
                                options.lengthFrom = lengthValue.readU32();
                            } else if (cfg.lengthMethod === 'u64') {
                                options.lengthFrom = lengthValue.readU64();
                            } else if (cfg.lengthMethod === 'int') {
                                options.lengthFrom = lengthValue.toInt32();
                            } else {
                                options.lengthFrom = lengthValue.toInt32();
                            }
                        }

                        log(smartPrintArg(argValue, options));
                    } catch (e) {
                        log(`参数打印失败 (${cfg.from}): ${e.message}`);
                    }
                });
            }

            if (customLeave) {
                customLeave.call(null, thisContext, retval, context, args, base_addr, hook_addr);
            }
        };

        // 递归调用自己，使用完整模式
        native_hook(defaultOnEnter, defaultOnLeave, actualSoName, actualSoAddr);
        return;
    }

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

            if (hook_addr.compare(base_addr) < 0 || hook_addr.compare(base_addr.add(module.size)) >= 0) {
                log("[-] ERROR: Hook address is outside module range!");
                return;
            }

            try {
                var instruction = Instruction.parse(hook_addr);
                log("[+] Instruction at hook address: " + instruction);
            } catch (e) {
                log("[-] WARNING: Cannot parse instruction at hook address: " + e.message);
            }

            log("[+] ========================================");

            log("[*] Calling Interceptor.attach on: " + hook_addr);
            Interceptor.attach(hook_addr, {
                onEnter: function(args) {
                    try {
                        this.tid = Process.getCurrentThreadId();
                        log("[+] !!!!! Function called at: " + hook_addr + " !!!!!");

                        if (typeof onEnterCallback === 'function') {
                            onEnterCallback.call(this, args, this.context, null, base_addr, hook_addr, this.tid);
                        }
                    } catch(e) {
                        log("Error in onEnter: " + e.message);
                    }
                },
                onLeave: function(retval) {
                    try {
                        log(`[${this.tid}] - Leave`);

                        if (retval) {
                            log("Return value: " + retval.toString());
                        }

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
            log("[-] Stack trace: " + e.stack);
        }
    }, so_addr);
}
