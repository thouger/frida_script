// Frida 断点式 Hook 脚本 - 独立版本
// 使用方法: frida -U -f <包名> -l breakpoint.js --runtime=v8 --no-pause --offset 0x1B98F4 --registers x1,x0,x2

// ==================== Frida 版本兼容层 ====================
let isFrida17 = false;
try {
    isFrida17 = typeof Module.getGlobalExportByName === 'function';
} catch (e) {
    isFrida17 = false;
}
if (!isFrida17) {
    try {
        isFrida17 = typeof Module.findGlobalExportByName === 'function';
    } catch (e) {
        isFrida17 = false;
    }
}

function findGlobalExport(name) {
    if (isFrida17) {
        if (typeof Module.getGlobalExportByName === 'function') {
            return Module.getGlobalExportByName(name);
        } else {
            return Module.findGlobalExportByName(name);
        }
    } else {
        return Module.findExportByName(null, name);
    }
}

function readCString(ptr) {
    if (typeof ptr.readCString === 'function') {
        return ptr.readCString();
    } else {
        return Memory.readCString(ptr);
    }
}

console.log("[*] Frida 版本: " + (isFrida17 ? 'Frida 17+' : 'Frida <17'));
// ==================== 兼容层结束 ====================

// ==================== 配置 ====================
var DEBUG = false;  // 控制调试输出

// ==================== 工具函数 ====================

function log(message) {
    console.log("[*] " + message);
}

function debug(message) {
    if (DEBUG) {
        console.log("[DEBUG] " + message);
    }
}

// 打印寄存器（简化版）
function printRegisters(context, regs, baseAddr) {
    const regList = regs || ['x0', 'x1'];

    // ARM64 寄存器别名映射
    const regAliases = {
        'x29': 'fp',  // Frame Pointer
        'x30': 'lr',  // Link Register
        'x31': 'sp'   // Stack Pointer (在某些上下文中)
    };

    regList.forEach(function(reg) {
        const regLower = reg.toLowerCase();

        // 尝试直接访问或使用别名
        const actualReg = regAliases[regLower] || regLower;

        if (context[actualReg] !== undefined) {
            const value = context[actualReg];
            const ptr = value;

            // 计算相对偏移
            var offsetInfo = '';
            if (baseAddr) {
                try {
                    var offset = ptr.sub(baseAddr);
                    var offsetValue = parseInt(offset.toString());
                    if (offsetValue >= 0 && offsetValue < 0x10000000) {
                        offsetInfo = ' | Offset: +0x' + offset.toString(16);
                    }
                } catch(e) {}
            }

            log(reg.toUpperCase() + ': ' + value + offsetInfo);
        } else {
            debug("寄存器 " + reg + " 在 context 中不存在");
        }
    });
}

// 打印调用栈
function printCallStack(context, moduleName) {
    log("=== 调用栈 (Call Stack) ===");

    try {
        const backtrace = Thread.backtrace(context, Backtracer.FUZZY);

        if (!backtrace || backtrace.length === 0) {
            log("  (空调用栈)");
            return;
        }

        for (let i = 0; i < backtrace.length; i++) {
            const addr = backtrace[i];

            // 查找地址所属的模块
            const module = Process.findModuleByAddress(addr);

            if (module) {
                const offset = addr.sub(module.base);
                const symbol = DebugSymbol.fromAddress(addr);

                let info = '  #' + i + ' ' + module.name + '!0x' + offset.toString(16);

                // 如果有符号信息，添加符号名称
                if (symbol && symbol.name) {
                    info += ' (' + symbol.name + ')';
                }

                // 如果是目标模块，用高亮标记
                if (moduleName && module.name.indexOf(moduleName) !== -1) {
                    info += ' ← 目标模块';
                }

                log(info);
            } else {
                log('  #' + i + ' ' + addr + ' (未知模块)');
            }
        }
    } catch (e) {
        log("  调用栈获取失败: " + e.message);

        // 降级方案：只打印 LR
        if (context.lr && !context.lr.isNull()) {
            log("  降级显示 - LR (返回地址): " + context.lr);
            const lrModule = Process.findModuleByAddress(context.lr);
            if (lrModule) {
                const lrOffset = context.lr.sub(lrModule.base);
                log("  来自: " + lrModule.name + "!0x" + lrOffset.toString(16));
            }
        }
    }

    log("========================");
}

// 智能读取指针内容
function smartRead(ptr, options) {
    options = options || {};
    const maxDepth = options.maxDepth || 1;
    const showHex = options.showHex !== undefined ? options.showHex : true;
    const hexLength = options.hexLength || 64;
    const label = options.label || '';
    const depth = options.depth || 0;
    const baseAddr = options.baseAddr || null;  // SO 基址

    const indent = '  '.repeat(depth);
    const results = [];

    try {
        if (!ptr || ptr.isNull()) {
            return indent + (label ? label + ': ' : '') + 'NULL';
        }

        const ptrValue = parseInt(ptr.toString(), 16);
        if (ptrValue > 0 && ptrValue < 0x10000) {
            return indent + (label ? label + ': ' : '') + 'Small integer value: ' + ptrValue + ' (0x' + ptrValue.toString(16) + ')';
        }

        if (label) {
            results.push(indent + label + ':');
        }

        // 显示绝对地址和相对偏移
        var addrInfo = '[Address: ' + ptr + ']';
        if (baseAddr) {
            try {
                var offset = ptr.sub(baseAddr);
                var offsetValue = parseInt(offset.toString());
                // 只有当地址在 SO 范围内才显示偏移
                if (offsetValue >= 0 && offsetValue < 0x10000000) {
                    addrInfo = '[Address: ' + ptr + ' | Offset: +0x' + offset.toString(16) + ']';
                }
            } catch(e) {}
        }
        results.push(indent + addrInfo);

        // 尝试读取 C 字符串
        try {
            const cstr = Memory.readCString(ptr);
            if (cstr && cstr.length > 0 && cstr.length < 500) {
                const printable = /^[\x20-\x7E\r\n\t]+$/.test(cstr);
                if (printable) {
                    const displayStr = cstr.length > 100 ? cstr.substring(0, 100) + '...' : cstr;
                    results.push(indent + '  ✓ CString: "' + displayStr + '" [len=' + cstr.length + ']');
                }
            }
        } catch (e) {}

        // 尝试读取为整数
        try {
            const int32 = Memory.readS32(ptr);
            const uint32 = Memory.readU32(ptr);
            if (int32 >= -10000 && int32 <= 10000) {
                results.push(indent + '  int32: ' + int32 + ' (0x' + uint32.toString(16) + ')');
            }
        } catch (e) {}

        // 显示 hexdump
        if (showHex) {
            try {
                const hexOutput = hexdump(ptr, { length: hexLength });
                results.push(indent + '  Raw memory:');
                const indentedHex = hexOutput.split('\n')
                    .map(function(line) { return indent + '    ' + line; })
                    .join('\n');
                results.push(indentedHex);
            } catch (e) {}
        }

        // 递归解引用
        if (depth < maxDepth) {
            try {
                const derefPtr = Memory.readPointer(ptr);
                if (derefPtr && !derefPtr.isNull()) {
                    const addr = parseInt(derefPtr.toString(), 16);
                    if (addr > 0x1000 && addr < 0x800000000000) {
                        results.push(indent + '  ↓ Dereferenced pointer:');
                        const subOptions = {
                            maxDepth: maxDepth,
                            depth: depth + 1,
                            label: '',
                            showHex: false,
                            baseAddr: baseAddr
                        };
                        const subResult = smartRead(derefPtr, subOptions);
                        results.push(subResult);
                    }
                }
            } catch (e) {}
        }

        return results.join('\n');

    } catch (e) {
        return indent + '[Error: ' + e.message + ']';
    }
}

// hook_dlopen 实现
function hook_dlopen(so_name, callback, offset) {
    debug("hook_dlopen called for: " + so_name);

    const module = Process.findModuleByName(so_name);
    if (module) {
        debug(so_name + " already loaded at " + module.base);
        callback(offset);
        return;
    }

    debug(so_name + " not loaded yet, hooking dlopen...");

    try {
        const android_dlopen_ext = findGlobalExport("android_dlopen_ext");
        if (android_dlopen_ext) {
            debug("Found android_dlopen_ext at " + android_dlopen_ext);
            Interceptor.attach(android_dlopen_ext, {
                onEnter: function(args) {
                    this.path = readCString(args[0]);
                    if (this.path && this.path.indexOf(so_name) !== -1) {
                        debug("android_dlopen_ext loading: " + this.path);
                    }
                },
                onLeave: function(retval) {
                    if (this.path && this.path.indexOf(so_name) !== -1) {
                        debug(so_name + " loaded via android_dlopen_ext");
                        const module = Process.findModuleByName(so_name);
                        if (module) {
                            debug("Module base: " + module.base);
                            callback(offset);
                        }
                    }
                }
            });
        } else {
            debug("android_dlopen_ext not found");
        }
    } catch(e) {
        debug("Error hooking android_dlopen_ext: " + e.message);
    }

    try {
        const dlopen = findGlobalExport("dlopen");
        if (dlopen) {
            debug("Found dlopen at " + dlopen);
            Interceptor.attach(dlopen, {
                onEnter: function(args) {
                    this.path = readCString(args[0]);
                    if (this.path && this.path.indexOf(so_name) !== -1) {
                        debug("dlopen loading: " + this.path);
                    }
                },
                onLeave: function(retval) {
                    if (this.path && this.path.indexOf(so_name) !== -1) {
                        debug(so_name + " loaded via dlopen");
                        const module = Process.findModuleByName(so_name);
                        if (module) {
                            debug("Module base: " + module.base);
                            callback(offset);
                        }
                    }
                }
            });
        } else {
            debug("dlopen not found");
        }
    } catch(e) {
        debug("Error hooking dlopen: " + e.message);
    }
}

// native_hook 核心实现（简化版）
function native_hook(so_name, so_addr, options) {
    debug("native_hook called: " + so_name + " + 0x" + so_addr.toString(16));

    options = options || {};
    const logRegs = options.logRegs;
    const customEnter = options.customEnter;

    hook_dlopen(so_name, function(dlopen_addr) {
        try {
            debug("hook_dlopen callback executing...");

            const module = Process.findModuleByName(so_name);
            if (!module) {
                debug("ERROR: Module not found: " + so_name);
                return;
            }

            const base_addr = module.base;
            const hook_addr = base_addr.add(so_addr);

            debug("Base address: " + base_addr);
            debug("Hook address: " + hook_addr + " (offset: 0x" + so_addr.toString(16) + ")");

            if (hook_addr.compare(base_addr) < 0 || hook_addr.compare(base_addr.add(module.size)) >= 0) {
                debug("ERROR: Hook address outside module range!");
                return;
            }

            try {
                const instruction = Instruction.parse(hook_addr);
                log("当前指令: " + instruction.toString());
            } catch (e) {
                debug("Failed to parse instruction: " + e.message);
            }

            debug("Setting up Interceptor.attach...");
            Interceptor.attach(hook_addr, {
                onEnter: function(args) {
                    try {
                        const tid = Process.getCurrentThreadId();
                        this.tid = tid;
                        this.savedArgs = args;

                        log("========== 命中断点 0x" + so_addr.toString(16) + " ==========");
                        debug("Thread ID: " + tid);

                        // log("当前地址: " + this.context.pc + " (偏移: 0x" + this.context.pc.sub(base_addr).toString(16) + ")");

                        // 打印 PC-4 的指令（顺序执行的上一条）
                        // var pcMinus4 = this.context.pc.sub(4);
                        // try {
                        //     var prevInstr = Instruction.parse(pcMinus4);
                        //     var prevOffset = pcMinus4.sub(base_addr);
                        //     log("PC-4 指令: " + prevInstr.toString() + " @ 0x" + prevOffset.toString(16));
                        // } catch(e) {
                        //     debug("无法解析 PC-4: " + e.message);
                        // }

                        // 打印 LR 信息（函数调用时的返回地址）
                        // if (this.context.lr && !this.context.lr.isNull()) {
                        //     var lrOffsetFromBase = this.context.lr.sub(base_addr);
                        //     log("LR (返回地址): " + this.context.lr + " (偏移: 0x" + lrOffsetFromBase.toString(16) + ")");

                        //     // 尝试解析 LR-4 的指令（可能是调用指令）
                        //     try {
                        //         var lrMinus4 = this.context.lr.sub(4);
                        //         var callInstr = Instruction.parse(lrMinus4);
                        //         var callOffset = lrMinus4.sub(base_addr);
                        //         log("LR-4 指令: " + callInstr.toString() + " @ 0x" + callOffset.toString(16));
                        //     } catch(e) {
                        //         debug("无法解析 LR-4: " + e.message);
                        //     }
                        // }

                        // 打印调用栈
                        // printCallStack(this.context, so_name);

                        // // 如果没有传入寄存器参数，打印完整 context
                        debug("logRegs value: " + logRegs);
                        debug("logRegs === undefined: " + (logRegs === undefined));
                        debug("logRegs === null: " + (logRegs === null));

                        if (logRegs === undefined || logRegs === null) {
                            log("=== 完整寄存器状态 ===");
                            log(JSON.stringify(this.context, null, 2));
                            log("当前 PC: " + this.context.pc);
                            log("LR (返回地址): " + this.context.lr);
                            if (this.context.lr && !this.context.lr.isNull()) {
                                log("调用指令地址 (LR-4): " + this.context.lr.sub(4));
                            }
                        } else if (logRegs.length === 0) {
                            printRegisters(this.context, null, base_addr);
                        } else if (logRegs.length > 0) {
                            printRegisters(this.context, logRegs, base_addr);
                        }

                        if (customEnter) {
                            customEnter.call(null, args, this.context, this, base_addr, hook_addr, tid);
                        }

                    } catch(e) {
                        log("Error in onEnter: " + e.message);
                        log("Stack: " + e.stack);
                    }
                },
                onLeave: function(retval) {
                }
            });

            log("Hook 安装成功: " + so_name + " 基址: " + base_addr + " (偏移: 0x" + so_addr.toString(16) + ")");

        } catch(e) {
            log("Error: " + e.message);
        }
    }, so_addr);
}

// ==================== 主逻辑 ====================

// 解析命令行参数
var config = {
    soName: "libmetasec_ml.so",  // 默认 SO 名称
    offset: null,
    registers: null  // 默认不设置，打印全部
};

// 从 rpc.exports 接收参数（命令行传参）
rpc.exports = {
    init: function(params) {
        log("========== 断点脚本已初始化 ==========");
        debug("Received params: " + JSON.stringify(params));

        if (params.offset) {
            config.offset = parseInt(params.offset, 16);
            debug("Offset parsed: 0x" + config.offset.toString(16));
        }
        if (params.soname) {
            config.soName = params.soname;
            debug("SO name: " + config.soName);
        }
        if (params.registers) {
            config.registers = params.registers.split(',').map(function(r) { return r.trim(); });
            debug("Registers: " + config.registers.join(', '));
        } else {
            debug("No registers specified, will print all context");
        }

        if (config.offset) {
            startHook();
        } else {
            log("ERROR: No offset specified!");
        }
    }
};

// 启动 Hook
function startHook() {
    debug("startHook called");

    if (!config.offset) {
        debug("ERROR: config.offset is not set");
        return;
    }

    debug("Calling native_hook with:");
    debug("  SO: " + config.soName);
    debug("  Offset: 0x" + config.offset.toString(16));
    debug("  Registers: " + (config.registers || "ALL"));

    native_hook(config.soName, config.offset, {
        logRegs: config.registers,
        customEnter: function(args, context, thisContext, base_addr, hook_addr, tid) {
            // 无额外输出
        }
    });
}

// 检查是否从命令行直接传入参数
if (typeof offset !== 'undefined') {
    config.offset = parseInt(offset, 16);
}
if (typeof soname !== 'undefined') {
    config.soName = soname;
}
if (typeof registers !== 'undefined') {
    config.registers = registers.split(',').map(function(r) { return r.trim(); });
}

// 自动启动（如果已设置参数）
if (config.offset) {
    startHook();
}
