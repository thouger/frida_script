// Frida 调用栈打印脚本 - 独立版本
// 使用方法: python run_callstack.py -o 0x1B98F4 -s libmetasec_ml.so

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

// 打印调用栈
function printCallStack(context, moduleName, baseAddr) {
    log("=== 调用栈 (Call Stack) ===");

    try {
        const backtrace = Thread.backtrace(context, Backtracer.ACCURATE);

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
                    info += ' <-- 目标模块';
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

    log("===========================");
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

// native_hook 核心实现（调用栈版）
function native_hook(so_name, so_addr, options) {
    debug("native_hook called: " + so_name + " + 0x" + so_addr.toString(16));

    options = options || {};
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

                        log("========== 命中地址 0x" + so_addr.toString(16) + " ==========");
                        log("线程 ID: " + tid);
                        log("当前 PC: " + this.context.pc + " (偏移: 0x" + this.context.pc.sub(base_addr).toString(16) + ")");

                        // 打印 LR 信息
                        if (this.context.lr && !this.context.lr.isNull()) {
                            var lrModule = Process.findModuleByAddress(this.context.lr);
                            if (lrModule) {
                                var lrOffset = this.context.lr.sub(lrModule.base);
                                log("LR (返回地址): " + this.context.lr + " (" + lrModule.name + "!0x" + lrOffset.toString(16) + ")");
                            } else {
                                log("LR (返回地址): " + this.context.lr);
                            }
                        }

                        // 打印完整调用栈
                        printCallStack(this.context, so_name, base_addr);

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
    offset: null
};

// 从 rpc.exports 接收参数（命令行传参）
rpc.exports = {
    init: function(params) {
        log("========== 调用栈脚本已初始化 ==========");
        debug("Received params: " + JSON.stringify(params));

        if (params.offset) {
            config.offset = parseInt(params.offset, 16);
            debug("Offset parsed: 0x" + config.offset.toString(16));
        }
        if (params.soname) {
            config.soName = params.soname;
            debug("SO name: " + config.soName);
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

    native_hook(config.soName, config.offset, {
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

// 自动启动（如果已设置参数）
if (config.offset) {
    startHook();
}
