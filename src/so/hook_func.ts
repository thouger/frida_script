//@ts-nocheck
import { hook_dlopen } from "./utils.js";
import { log, printRegisters } from "../utils/log.js";
import { smartPrintArg, smartPrintArgs } from "./param_tracker.js";

// ==================== 辅助函数 ====================

/**
 * 智能读取 NativePointer - 类似 Java formatValue 的功能
 * 尝试多种读取方式，自动推断数据类型
 *
 * @param {NativePointer} ptr - 要读取的指针
 * @param {Object} options - 配置选项
 * @returns {string} 格式化后的字符串
 *
 * 用法示例:
 *   smartRead(args[0])  // 自动推断
 *   smartRead(args[1], { maxDepth: 2 })  // 尝试读取指针的指针
 *   smartRead(args[2], { tryLength: args[3].toInt32() })  // 指定长度
 */
/**
 * 智能读取指针内容 - 自动推断数据类型
 *
 * 支持检测：
 * - C 字符串
 * - SSO 短字符串（std::string < 16 字节）
 * - std::string 长字符串（指针+长度结构体）
 * - 整数（int32/int64）
 * - 结构体字段
 * - 递归解引用指针
 *
 * @param {NativePointer} ptr - 要读取的指针
 * @param {Object} options - 配置选项
 * @returns {string} 格式化后的字符串
 */
export function smartRead(ptr, options = {}) {
    const {
        maxDepth = 1,              // 最大指针解引用深度
        maxStringLength = 256,     // 最大字符串长度
        showHex = true,            // 是否显示 hexdump
        hexLength = 64,            // hexdump 长度
        tryStructFields = false,   // 是否尝试遍历结构体字段
        label = '',                // 标签
        depth = 0                  // 当前深度（内部使用）
    } = options;

    const indent = '  '.repeat(depth);
    const results = [];

    try {
        // 检查空指针
        if (!ptr || ptr.isNull()) {
            return `${indent}${label ? label + ': ' : ''}NULL`;
        }

        // 新增：检查是否为小整数值（可能不是指针，而是直接传递的数值）
        const ptrValue = parseInt(ptr.toString(), 16);
        if (ptrValue > 0 && ptrValue < 0x10000) {
            return `${indent}${label ? label + ': ' : ''}Small integer value: ${ptrValue} (0x${ptrValue.toString(16)})`;
        }

        if (label) {
            results.push(`${indent}${label}:`);
        }

        results.push(`${indent}[Address: ${ptr}]`);

        // 1. 尝试直接读取为 C 字符串
        try {
            const cstr = ptr.readCString();
            if (cstr && cstr.length > 0 && cstr.length < 500) {
                const printable = /^[\x20-\x7E\r\n\t]+$/.test(cstr);
                if (printable) {
                    const displayStr = cstr.length > 100 ? cstr.substring(0, 100) + '...' : cstr;
                    results.push(`${indent}  ✓ CString: "${displayStr}" [len=${cstr.length}]`);
                }
            }
        } catch (e) {}

        // 2. 尝试读取为 SSO 短字符串（std::string）
        try {
            const firstByte = ptr.readU8();
            if ((firstByte & 1) === 0 && firstByte > 0 && firstByte < 32) {
                // 短字符串：最低位=0，长度<16
                const length = firstByte >> 1;
                if (length > 0 && length < 16) {
                    const str = ptr.add(1).readUtf8String(length);
                    if (str && /^[\x20-\x7E]+$/.test(str)) {
                        results.push(`${indent}  ✓ SSO String: "${str}" [len=${length}]`);
                    }
                }
            }
        } catch (e) {}

        // 3. 尝试读取为 std::string 结构体（长字符串：指针+长度）
        try {
            const strPtr = ptr.readPointer();
            if (!strPtr.isNull()) {
                const strLen = ptr.add(8).readU64();  // 长度在 +0x08
                // 合理的长度范围：1-10000
                if (strLen > 0 && strLen < 10000) {
                    // 验证指针地址是否合理
                    const ptrValue = strPtr.toString();
                    if (ptrValue.startsWith("0x7") || ptrValue.startsWith("0x6")) {
                        const str = strPtr.readUtf8String(Number(strLen));
                        if (str && str.length === Number(strLen)) {
                            const isPrintable = str.split('').every(c => {
                                const code = c.charCodeAt(0);
                                return (code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13;
                            });
                            if (isPrintable) {
                                const displayStr = str.length > 100 ? str.substring(0, 100) + '...' : str;
                                results.push(`${indent}  ✓ std::string: "${displayStr}" [len=${strLen}, ptr=${strPtr}]`);
                            }
                        }
                    }
                }
            }
        } catch (e) {}

        // 4.5 尝试识别为 JNINativeMethod 结构
        try {
            // JNINativeMethod 结构:
            // struct {
            //     const char* name;      // +0x00
            //     const char* signature; // +0x08
            //     void*       fnPtr;     // +0x10
            // }
            const namePtr = ptr.readPointer();        // +0x00
            const sigPtr = ptr.add(8).readPointer();  // +0x08
            const fnPtr = ptr.add(16).readPointer();  // +0x10

            if (!namePtr.isNull() && !sigPtr.isNull() && !fnPtr.isNull()) {
                // 尝试读取方法名和签名
                const methodName = namePtr.readCString();
                const methodSig = sigPtr.readCString();

                // 检查是否为合法的 JNI 签名格式（包含括号和返回类型）
                if (methodName && methodSig &&
                    methodName.length > 0 && methodName.length < 100 &&
                    methodSig.length > 0 && methodSig.length < 500 &&
                    methodSig.includes('(') && methodSig.includes(')')) {

                    // 检查方法名是否为合法标识符
                    const validName = /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(methodName);

                    if (validName) {
                        results.push(`${indent}  ✓ JNINativeMethod 结构:`);
                        results.push(`${indent}      方法名: "${methodName}"`);
                        results.push(`${indent}      签名: "${methodSig}"`);
                        results.push(`${indent}      函数指针: ${fnPtr} ${DebugSymbol.fromAddress(fnPtr)}`);
                    }
                }
            }
        } catch (e) {}

        // 4. 尝试读取为整数
        try {
            const int32 = ptr.readS32();
            const uint32 = ptr.readU32();
            if (int32 >= -10000 && int32 <= 10000) {
                results.push(`${indent}  int32: ${int32} (0x${uint32.toString(16)})`);
            }
        } catch (e) {}

        // 5. 如果启用，尝试遍历结构体字段（前4个字段）
        if (tryStructFields) {
            try {
                const structInfo = [];
                for (let offset = 0; offset < 32; offset += 8) {
                    const fieldPtr = ptr.add(offset).readPointer();
                    structInfo.push(`${indent}  [+0x${offset.toString(16).padStart(2, '0')}] ${fieldPtr}`);

                    // 尝试读取指针指向的内容
                    if (!fieldPtr.isNull()) {
                        try {
                            const str = fieldPtr.readCString();
                            if (str && str.length > 0 && str.length < 200) {
                                const isPrintable = /^[\x20-\x7E]+$/.test(str);
                                if (isPrintable) {
                                    structInfo.push(`${indent}       → "${str}"`);
                                }
                            }
                        } catch (e) {}
                    }
                }
                if (structInfo.length > 0) {
                    results.push(`${indent}  Struct fields:`);
                    results.push(structInfo.join('\n'));
                }
            } catch (e) {}
        }

        // 6. 显示原始 hexdump
        if (showHex) {
            try {
                const hexOutput = hexdump(ptr, { length: hexLength });
                results.push(`${indent}  Raw memory:`);
                // 给 hexdump 每行加缩进
                const indentedHex = hexOutput.split('\n')
                    .map(line => `${indent}    ${line}`)
                    .join('\n');
                results.push(indentedHex);
            } catch (e) {}
        }

        // 7. 尝试解引用指针（递归）
        if (depth < maxDepth) {
            try {
                const derefPtr = ptr.readPointer();
                if (derefPtr && !derefPtr.isNull()) {
                    const addr = parseInt(derefPtr.toString(), 16);
                    // 检查地址是否在合理范围内（用户空间）
                    if (addr > 0x1000 && addr < 0x800000000000) {
                        results.push(`${indent}  ↓ Dereferenced pointer:`);
                        const subResult = smartRead(derefPtr, {
                            ...options,
                            depth: depth + 1,
                            maxDepth: maxDepth,
                            label: '',
                            showHex: false  // 递归时不显示 hexdump，避免输出过长
                        });
                        results.push(subResult);
                    }
                }
            } catch (e) {}
        }

        return results.join('\n');

    } catch (e) {
        return `${indent}[Error: ${e.message}]`;
    }
}

/**
 * 智能打印多个参数 - 批量调用 smartRead
 *
 * 用法示例:
 *   smartReadArgs(args, [0, 1, 2])  // 读取前3个参数
 *   smartReadArgs(args, {0: {}, 1: {maxDepth: 2}})  // 自定义每个参数的选项
 */
export function smartReadArgs(args, config) {
    const results = ['========== Smart Args Analysis =========='];

    if (Array.isArray(config)) {
        // 数组形式：[0, 1, 2]
        config.forEach(idx => {
            results.push(`\nargs[${idx}]:`);
            results.push(smartRead(args[idx], { label: `args[${idx}]` }));
        });
    } else if (typeof config === 'object') {
        // 对象形式：{0: {}, 1: {maxDepth: 2}}
        for (let idx in config) {
            const argIdx = parseInt(idx);
            const options = config[idx] || {};
            results.push(`\nargs[${argIdx}]:`);
            results.push(smartRead(args[argIdx], { ...options, label: `args[${argIdx}]` }));
        }
    } else if (typeof config === 'number') {
        // 数字形式：读取前 N 个参数
        for (let i = 0; i < config; i++) {
            results.push(`\nargs[${i}]:`);
            results.push(smartRead(args[i], { label: `args[${i}]` }));
        }
    }

    results.push('\n==========================================');
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
 * trace_so_call("libEncryptor.so", 0x2BD8);
 * trace_so_call("libEncryptor.so", 0x2BD8, "libEncryptor.so");
 */
export function trace_so_call(target_module, offset) {

    hook_dlopen(so_name, function() {
        try {
            const module = Process.findModuleByName(so_name);
            if (!module) {
                log(`[-] 未找到模块 ${so_name}`);
                return;
            }

            const target_addr = module.base.add(offset);
            log(`[+] 开始追踪 ${so_name}+0x${offset.toString(16)}`);

            Interceptor.attach(target_addr, {
                onEnter: function(args) {
                    const tid = Process.getCurrentThreadId();
                    this.tid = tid;

                    // 排除其他模块，只 trace 目标模块
                    const module_to_trace = Process.findModuleByName(target_module);
                    if (!module_to_trace) {
                        log(`[-] 未找到模块: ${target_module}`);
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
                        log(`[Stalker] stop tracing thread: ${this.tid}`);
                    }
                }
            });

        } catch (e) {
            log(`[-] trace_so_call error: ${e.message}`);
        }
    });
}

/**
 * 内部函数 - 底层 hook 实现
 * 统一参数顺序: so_name, so_addr, onEnterCallback, onLeaveCallback
 */
function _do_native_hook(so_name, so_addr, onEnterCallback, onLeaveCallback) {
    hook_dlopen(so_name, function(dlopen_addr) {
        try {
            var module = Process.findModuleByName(so_name);
            if (!module) {
                log("[-] module not found: " + so_name);
                return;
            }
            var base_addr = module.base;
            var hook_addr = base_addr.add(so_addr);

            if (hook_addr.compare(base_addr) < 0 || hook_addr.compare(base_addr.add(module.size)) >= 0) {
                log("[-] error: hook address out of module range!");
                return;
            }

            // 读取目标地址的指令
            try {
                var instruction = Instruction.parse(hook_addr);
                log("[+] hook instruction: " + instruction);
            } catch (e) {
                log("[-] warn: failed to parse hook instruction: " + e.message);
            }

            // 输出 hook 信息
            log("[+] module base: " + base_addr + ", size: 0x" + module.size.toString(16));

            Interceptor.attach(hook_addr, {
                onEnter: function(args) {
                    try {
                        this.tid = Process.getCurrentThreadId();
                        this.savedArgs = args;  // 保存 args 供 onLeave 使用

                        // 打印 LR 偏移
                        const lr = ptr(this.context.lr);   // X30 / LR
                        const lr_offset = lr.sub(base_addr);

                        // log("[+] LR 偏移: +0x" + lr_offset.toString(16));

                        if (typeof onEnterCallback === 'function') {
                            onEnterCallback.call(null, args, this.context, this, base_addr, hook_addr, this.tid);
                        }
                    } catch(e) {
                        log("onEnter error: " + e.message);
                    }
                },
                onLeave: function(retval) {
                    try {
                        if (typeof onLeaveCallback === 'function') {
                            onLeaveCallback(this.savedArgs, this.context, this, base_addr, hook_addr, retval);
                        }
                    } catch(e) {
                        log("onLeave error: " + e.message);
                    }
                }
            });

        } catch(e) {
            log("[-] native_hook error: " + e.message);
            log("[-] stack: " + e.stack);
        }
    }, so_addr);
}

/**
 * 通用的 native hook 函数
 *
 * @param {string} so_name - SO 文件名
 * @param {number} so_addr - 函数偏移地址
 * @param {Object} options - 配置选项（可选）
 *
 * 用法1 - 最简模式（只传 so_name 和 offset）:
 *   native_hook("libEncryptor.so", 0x2BD8)
 *
 * 用法2 - 智能参数打印模式:
 *   native_hook("libEncryptor.so", 0x2BD8, {
 *     logEnter: true,
 *     logLeave: true,
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
 * 用法4 - 自定义逻辑（最常用）:
 *   native_hook("libmetasec_ml.so", 0xECC74, {
 *     logEnter: false,
 *     logLeave: false,
 *     customEnter: function(args, context, thisContext, base_addr, hook_addr, tid) {
 *       var X23_offset = context.x23.sub(base_addr);
 *       console.log("X23 offset: 0x" + X23_offset.toString(16));
 *     },
 *     customLeave: function(args, context, thisContext, base_addr, hook_addr, retval) {
 *       console.log("返回值:", retval);
 *     }
 *   })
 */
export function native_hook(so_name, so_addr, options = {}) {
    // 解构配置选项
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

    // 构建 onEnter 回调
    const onEnterCallback = function(args, context, thisContext, base_addr, hook_addr, tid) {
        if (logEnter) {
            log(`[+] 进入 ${so_name}+0x${so_addr.toString(16)}`);
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
                thisContext[`arg${idx}`] = args[idx];
            });
        }

        if (customEnter) {
            customEnter.call(null, args, context, thisContext, base_addr, hook_addr, tid);
        }
    };

    // 构建 onLeave 回调
    const onLeaveCallback = function(args, context, thisContext, base_addr, hook_addr, retval) {
        if (logLeave) {
            log(`[-] 离开 ${so_name}+0x${so_addr.toString(16)}`);
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
            customLeave.call(null, args, context, thisContext, base_addr, hook_addr, retval);
        }
    };

    // 调用底层实现 - 统一参数顺序
    _do_native_hook(so_name, so_addr, onEnterCallback, onLeaveCallback);
}
