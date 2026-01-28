//@ts-nocheck
import { log } from "../utils/log.js";
import { hook_dlopen } from "./utils.js"

/**
 * 高级 Stalker 追踪 - 追踪指定地址范围
 *
 * @param {string} so_name - SO 文件名
 * @param {number} start_addr - 开始地址（相对偏移）
 * @param {number} end_addr - 结束地址（相对偏移），如果为 null 则追踪到函数结束
 *
 * 注意：对于有完整性检测的函数（如 VM dispatcher），不要在函数入口 hook！
 * 应该找到调用这个函数的地方，在调用者处 hook。
 */
export function stalker(so_name, start_addr, end_addr) {
    hook_dlopen(so_name, () => _stalker(so_name, start_addr, end_addr))
}

/**
 * 轻量级追踪 - 只追踪指令执行和寄存器状态
 * 不记录调用链，适合追踪小范围代码
 */
export function native_trace(so_name, addr, size) {
    hook_dlopen(so_name, () => _native_trace(so_name, addr, size))
}

/**
 * 内部实现：轻量级指令追踪
 */
function _native_trace(so_name, addr, size) {
    size = size || 0x1000;
    const module = Process.findModuleByName(so_name);
    if (!module) {
        console.log("[-] Module not found: " + so_name);
        return;
    }

    const base_addr = module.base;
    const func = base_addr.add(addr);
    const end_address = base_addr.add(addr).add(size);

    console.log("[+] Native trace setup:");
    console.log("    Base: " + base_addr);
    console.log("    Range: " + func + " - " + end_address);
    console.log("    Size: 0x" + size.toString(16));

    Interceptor.attach(func, {
        onEnter: function(args) {
            this.tid = Process.getCurrentThreadId();
            console.log("[+] Thread " + this.tid + " entered, starting trace...");

            Stalker.follow(this.tid, {
                transform: function(iterator) {
                    let instruction = iterator.next();

                    // 安全检查：确保第一条指令有效
                    if (!instruction) {
                        return;
                    }

                    do {
                        // 安全检查：确保指令对象有效
                        if (!instruction || !instruction.address) {
                            iterator.keep();
                            continue;
                        }

                        // 在循环内检查每条指令是否在范围内
                        const isInRange = instruction.address.compare(func) >= 0 &&
                                        instruction.address.compare(end_address) < 0;

                        if (isInRange) {
                            try {
                                // 打印指令
                                log(instruction);

                                // 打印寄存器状态
                                iterator.putCallout((context) => {
                                    log(JSON.stringify(context));
                                });
                            } catch(e) {
                                // 打印失败，继续
                            }
                        }

                        iterator.keep();
                    } while ((instruction = iterator.next()) !== null);
                }
            });
        },
        onLeave: function(retval) {
            Stalker.unfollow(this.tid);
            console.log("[-] Thread " + this.tid + " left, trace stopped");
        }
    });
}

/**
 * 内部实现：完整的 Stalker 追踪（带调用链分析）
 */
function _stalker(so_name, start_addr, end_addr) {
    const module = Process.findModuleByName(so_name);
    if (!module) {
        console.log("[-] Module not found: " + so_name);
        return;
    }

    const base_addr = module.base;
    const func = base_addr.add(start_addr);
    const end_address = end_addr ? base_addr.add(end_addr) : null;

    // 参数验证
    if (end_address && end_address.compare(func) <= 0) {
        console.log("[-] 错误: end_addr 必须大于 start_addr!");
        console.log("    start_addr: 0x" + start_addr.toString(16));
        console.log("    end_addr: 0x" + end_addr.toString(16));
        console.log("\n提示: 如果要追踪单条指令，请使用:");
        console.log("  stalker('so_name', 0xXXXX, 0xXXXX + 4)");
        return;
    }

    console.log("[+] Stalker setup:");
    console.log("    Base: " + base_addr);
    console.log("    Func: " + func);
    console.log("    End:  " + end_address);

    // 警告：如果函数有完整性检测，在这里 attach 可能导致崩溃
    // 解决方案：找到调用这个函数的地方，在调用者处 hook
    Interceptor.attach(func, {
        onEnter: function(args) {
            this.tid = Process.getCurrentThreadId();

            Stalker.follow(this.tid, {
                events: {
                    call: true,      // 记录 CALL 指令
                    ret: false,      // 不记录 RET
                    exec: false,     // 不记录所有指令（太多）
                    block: false,    // 不记录基本块
                    compile: false   // 不记录编译事件
                },

                // 调用摘要：显示哪些函数被调用了
                onCallSummary: function(summary) {
                    for (let addr in summary) {
                        try {
                            const calleeModule = Process.getModuleByAddress(ptr(addr));
                            if (calleeModule.name.indexOf(so_name) != -1) {
                                console.log("[CallSummary]", addr, "offset:", ptr(addr).sub(calleeModule.base));
                            }
                        } catch(err) {
                            // 忽略不在模块内的地址
                        }
                    }
                },

                // 调用事件：显示调用链
                onReceive: function(events) {
                    console.log("[+] Received stalker events");
                    const eventsData = Stalker.parse(events, {
                        annotate: true,
                        stringify: true
                    });

                    for (let idx in eventsData) {
                        const event = eventsData[idx];
                        const [type, from, to, depth] = event;

                        if (type !== 'call') continue;

                        try {
                            const fromModule = Process.getModuleByAddress(ptr(from));
                            const toModule = Process.getModuleByAddress(ptr(to));

                            // 只显示目标 SO 内的调用
                            if (fromModule.name.indexOf(so_name) != -1) {
                                const fromOffset = ptr(from).sub(fromModule.base);
                                const toOffset = toModule.name.indexOf(so_name) != -1
                                    ? ptr(to).sub(toModule.base)
                                    : ptr(to);

                                console.log(`[Call] ${fromModule.name}!${fromOffset} -> ${toModule.name}!${toOffset}`);
                            }
                        } catch(err) {
                            console.log("[Call Error]", type, from, to);
                        }
                    }
                },

                // Transform：修改/监控指令执行
                transform: function(iterator) {
                    let instruction = iterator.next();

                    // 安全检查：确保第一条指令有效
                    if (!instruction) {
                        return;
                    }

                    do {
                        // 安全检查：确保指令对象有效
                        if (!instruction || !instruction.address) {
                            iterator.keep();
                            continue;
                        }

                        // 在循环内重新检查每条指令是否在范围内
                        let isInRange;
                        try {
                            if (end_address) {
                                isInRange = instruction.address.compare(base_addr.add(start_addr)) >= 0 &&
                                           instruction.address.compare(end_address) < 0;
                            } else {
                                isInRange = instruction.address.compare(base_addr.add(start_addr)) >= 0;
                            }
                        } catch(e) {
                            // 地址比较失败，跳过
                            iterator.keep();
                            continue;
                        }

                        if (isInRange) {
                            try {
                                const offset = instruction.address.sub(base_addr);
                                console.log(offset + "\t:\t" + instruction);

                                // 示例：在特定地址添加回调
                                // if (offset.toInt32() == 0xC7E18) {
                                //     iterator.putCallout((context) => {
                                //         console.log("[0xC7E18] X10:", context.x10, "X11:", context.x11);
                                //     });
                                // }
                            } catch(e) {
                                // 打印失败，继续
                            }
                        }

                        iterator.keep();
                    } while ((instruction = iterator.next()) !== null);
                }
            });
        },

        onLeave: function(retval) {
            Stalker.unfollow(this.tid);
        }
    });
}

/**
 * 替代方案：在调用者处 hook，避免完整性检测
 *
 * 使用方法：
 * 1. 先找到谁调用了目标函数
 * 2. Hook 调用者，在调用前启动 Stalker
 * 3. 这样可以避免修改目标函数本身
 */
export function stalker_at_caller(so_name, caller_addr, target_start, target_end) {
    hook_dlopen(so_name, () => {
        const module = Process.findModuleByName(so_name);
        if (!module) {
            console.log("[-] Module not found: " + so_name);
            return;
        }

        const base_addr = module.base;
        const caller = base_addr.add(caller_addr);
        const target_start_addr = base_addr.add(target_start);
        const target_end_addr = target_end ? base_addr.add(target_end) : null;

        console.log("[+] Stalker at caller:");
        console.log("    Caller: " + caller);
        console.log("    Target: " + target_start_addr + " - " + target_end_addr);

        Interceptor.attach(caller, {
            onEnter: function(args) {
                this.tid = Process.getCurrentThreadId();
                console.log("[+] Caller entered, starting stalker for thread " + this.tid);

                Stalker.follow(this.tid, {
                    transform: function(iterator) {
                        let instruction = iterator.next();

                        // 安全检查：确保第一条指令有效
                        if (!instruction) {
                            return;
                        }

                        do {
                            // 安全检查：确保指令对象有效
                            if (!instruction || !instruction.address) {
                                iterator.keep();
                                continue;
                            }

                            // 只追踪目标范围内的指令
                            let isInRange;
                            try {
                                if (target_end_addr) {
                                    isInRange = instruction.address.compare(target_start_addr) >= 0 &&
                                               instruction.address.compare(target_end_addr) < 0;
                                } else {
                                    isInRange = instruction.address.compare(target_start_addr) >= 0;
                                }
                            } catch(e) {
                                iterator.keep();
                                continue;
                            }

                            if (isInRange) {
                                try {
                                    const offset = instruction.address.sub(base_addr);
                                    console.log(offset + "\t:\t" + instruction);

                                    // 监控特定指令
                                    if (offset.toInt32() == 0xC7E18) {
                                        iterator.putCallout((context) => {
                                            console.log("\n========== 0xC7E18: SUB X10, X10, X11 ==========");
                                            console.log("X10 (加密地址):", context.x10);
                                            console.log("X11 (密钥):     ", context.x11);
                                            console.log("X10 - X11 =     ", context.x10.sub(context.x11));
                                            console.log("===============================================\n");
                                        });
                                    }

                                    if (offset.toInt32() == 0xC7E44) {
                                        iterator.putCallout((context) => {
                                            console.log("\n[BR X10] 跳转目标:", context.x10, "偏移:", context.x10.sub(base_addr));
                                        });
                                    }
                                } catch(e) {
                                    // 打印失败，继续
                                }
                            }

                            iterator.keep();
                        } while ((instruction = iterator.next()) !== null);
                    }
                });
            },

            onLeave: function(retval) {
                Stalker.unfollow(this.tid);
                console.log("[-] Caller left, stalker stopped");
            }
        });
    });
}
