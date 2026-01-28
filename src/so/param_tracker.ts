//@ts-nocheck
import { native_hook } from "./hook_func.js";
import { hexdumpAdvanced } from "./BufferUtils.js";

/**
 * 参数变化追踪器 - 通用化工具
 *
 * 用于验证函数调用前后，参数指向的数据是否发生变化
 * 特别适合验证 shared_ptr 拷贝、引用传递等场景
 *
 * @author Claude Code
 * @version 1.0.0
 */

// ==================== 智能参数打印函数 ====================

/**
 * 智能参数打印器 - 自动识别参数类型并选择合适的打印方式
 * （从 utils.ts 迁移而来，统一参数追踪相关功能）
 *
 * @param {NativePointer} value - 要打印的参数值
 * @param {Object} options - 打印选项
 * @returns {string} 格式化的输出
 */
export function smartPrintArg(value, options = {}) {
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
 * （从 utils.ts 迁移而来，统一参数追踪相关功能）
 *
 * @param {Array} args - 参数数组
 * @param {Object|Array} config - 配置对象或配置数组
 *
 * 配置示例:
 * - ['hexdump:1'] - args[0] 以 hexdump 打印，长度从 args[1] 获取
 * - ['string', 'u32', 'hexdump:100'] - args[0]字符串, args[1]整数, args[2] hexdump(长度100)
 * - {0: {type: 'hexdump', lengthFrom: 'args[1]'}, 2: {type: 'string'}}
 */
export function smartPrintArgs(args, config) {
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

// ==================== 辅助函数 ====================

/**
 * 安全读取指针
 * @param {NativePointer} ptr - 要读取的指针
 * @returns {NativePointer|null} 指针值或 null
 */
function safeReadPointer(ptr) {
    try {
        if (!ptr || ptr.isNull() || ptr.compare(0x1000) <= 0) {
            return null;
        }
        const result = ptr.readPointer();
        if (!result || result.isNull() || result.compare(0x1000) <= 0) {
            return null;
        }
        return result;
    } catch (e) {
        return null;
    }
}

/**
 * 安全读取字符串（自动截断到 \0）
 * @param {NativePointer} ptr - 要读取的指针
 * @param {number} maxLen - 最大长度
 * @returns {string|null} 字符串或 null
 */
function safeReadString(ptr, maxLen = 300) {
    try {
        if (!ptr || ptr.isNull() || ptr.compare(0x1000) <= 0) {
            return null;
        }
        const str = ptr.readCString(maxLen);
        if (!str || str === "!notset!") {
            return null;
        }

        // 只返回第一个 \0 之前的内容
        const cleanStr = str.split('\0')[0];

        // 验证是否是有效字符串（60% 以上可打印字符）
        let printableCount = 0;
        for (let i = 0; i < cleanStr.length; i++) {
            const c = cleanStr.charCodeAt(i);
            if ((c >= 32 && c <= 126) || c === 9 || c === 10 || c === 13) {
                printableCount++;
            }
        }

        if (printableCount >= cleanStr.length * 0.6 && cleanStr.length > 0) {
            return cleanStr;
        }

        return null;
    } catch (e) {
        return null;
    }
}

/**
 * 安全读取内存字节数组
 * @param {NativePointer} ptr - 要读取的指针
 * @param {number} length - 读取长度
 * @returns {string|null} 十六进制字符串或 null
 */
function safeReadMemory(ptr, length = 32) {
    try {
        if (!ptr || ptr.isNull() || ptr.compare(0x1000) <= 0) {
            return null;
        }
        const hexBytes = [];
        for (let i = 0; i < length; i++) {
            hexBytes.push(ptr.add(i).readU8().toString(16).padStart(2, '0'));
        }
        return hexBytes.join(' ');
    } catch (e) {
        return null;
    }
}

/**
 * 读取指针链（支持多层指针解引用）
 * @param {NativePointer} basePtr - 基础指针
 * @param {Array<number>} chain - 偏移链，例如 [0, 24] 表示 (*base)[24]
 * @returns {NativePointer|null} 最终指针或 null
 */
function followPointerChain(basePtr, chain) {
    let current = basePtr;

    for (let offset of chain) {
        current = safeReadPointer(current);
        if (!current) return null;

        if (offset !== 0) {
            current = current.add(offset);
        }
    }

    return current;
}

/**
 * 创建数据快照
 * @param {NativePointer} dataPtr - 数据指针
 * @param {Array<Object>} fieldConfigs - 字段配置数组
 * @returns {Object} 快照数据
 */
function createSnapshot(dataPtr, fieldConfigs) {
    if (!dataPtr) return {};

    const snapshot = {};

    fieldConfigs.forEach(({ offset, name, type = 'string', length = 100 }) => {
        try {
            const fieldPtr = safeReadPointer(dataPtr.add(offset));
            if (!fieldPtr) return;

            let value;
            switch (type) {
                case 'string':
                    value = safeReadString(fieldPtr, length);
                    break;
                case 'memory':
                    value = safeReadMemory(fieldPtr, length);
                    break;
                case 'u32':
                    value = fieldPtr.readU32();
                    break;
                case 'u64':
                    value = `0x${fieldPtr.readU64().toString(16)}`;
                    break;
                case 'double':
                    value = fieldPtr.readDouble();
                    break;
                default:
                    value = safeReadString(fieldPtr, length);
            }

            if (value !== null && value !== undefined) {
                snapshot[name] = {
                    offset,
                    type,
                    value
                };
            }
        } catch (e) {}
    });

    return snapshot;
}

/**
 * 比较两个快照
 * @param {Object} before - 调用前快照
 * @param {Object} after - 调用后快照
 * @returns {Object} 变化详情
 */
function compareSnapshots(before, after) {
    const changes = {};

    // 检查所有字段
    const allKeys = new Set([...Object.keys(before), ...Object.keys(after)]);

    allKeys.forEach(key => {
        const beforeValue = before[key]?.value;
        const afterValue = after[key]?.value;

        if (beforeValue !== afterValue) {
            changes[key] = {
                changed: true,
                before: beforeValue,
                after: afterValue,
                offset: before[key]?.offset || after[key]?.offset,
                type: before[key]?.type || after[key]?.type
            };
        }
    });

    return changes;
}

// ==================== 主要导出函数 ====================

/**
 * 追踪函数参数的变化（支持 shared_ptr 等场景）
 *
 * 使用场景：
 * 1. 验证 shared_ptr 拷贝后是否指向同一对象
 * 2. 追踪函数调用前后参数指向的数据是否变化
 * 3. 调试复杂的指针传递逻辑
 *
 * @param {string} soName - SO 库名称（如 "libmetasec_ml.so"）
 * @param {number} funcOffset - 函数偏移地址（如 0xED7B0）
 * @param {Object} config - 配置对象
 *
 * 配置对象说明：
 * {
 *   paramIndex: 1,                    // 要追踪的参数索引（0=x0, 1=x1, ...）
 *   pointerChain: [0, 24],            // 指针链：[0] = *param, [0, 24] = (*param)[24]
 *   snapshotFields: [                 // 要快照的字段配置
 *     { offset: 200, name: "field1", type: "string", length: 100 },
 *     { offset: 304, name: "field2", type: "string" },
 *     { offset: 0, name: "memory", type: "memory", length: 32 }
 *   ],
 *   verifySharedPtr: true,            // 是否验证 shared_ptr（检查 param[0] 指针）
 *   targetFunc: 0xEF920,              // 目标函数偏移（用于验证指针相同）
 *   targetParamIndex: 1,              // 目标函数的参数索引
 *   showDetails: true,                // 是否显示详细信息
 *   onlyShowChanges: false            // 是否仅显示有变化的数据
 * }
 *
 * @example
 * // 示例1：验证 sub_ED7B0 的 a2 参数变化
 * track_param_changes("libmetasec_ml.so", 0xED7B0, {
 *   paramIndex: 1,
 *   pointerChain: [0, 24],
 *   snapshotFields: [
 *     { offset: 200, name: "MediaDrmId", type: "string" },
 *     { offset: 304, name: "NetworkConfig", type: "string" }
 *   ],
 *   verifySharedPtr: true,
 *   targetFunc: 0xEF920,
 *   targetParamIndex: 1
 * });
 *
 * @example
 * // 示例2：简单追踪单个参数
 * track_param_changes("libtest.so", 0x1234, {
 *   paramIndex: 0,
 *   snapshotFields: [
 *     { offset: 0, name: "value", type: "u32" }
 *   ]
 * });
 */
export function track_param_changes(soName, funcOffset, config = {}) {
    const {
        paramIndex = 1,
        pointerChain = [0, 24],
        snapshotFields = [],
        verifySharedPtr = false,
        targetFunc = null,
        targetParamIndex = 1,
        showDetails = true,
        onlyShowChanges = false,
        customLabel = null
    } = config;

    const label = customLabel || `0x${funcOffset.toString(16)}`;
    let savedState = null;
    let targetFuncState = null;

    console.log(`\n${"=".repeat(80)}`);
    console.log(`[参数追踪器] 初始化`);
    console.log(`  SO: ${soName}`);
    console.log(`  函数: ${label}`);
    console.log(`  参数索引: ${paramIndex}`);
    console.log(`  指针链: ${pointerChain.join(' -> ')}`);
    console.log(`  快照字段: ${snapshotFields.length} 个`);
    if (verifySharedPtr) {
        console.log(`  验证 shared_ptr: 是 (目标函数: 0x${targetFunc.toString(16)})`);
    }
    console.log(`${"=".repeat(80)}\n`);

    // Hook 主函数
    native_hook(soName, funcOffset, {
        logEnter: false,
        logLeave: false,

        customEnter: function(args, context, retval, base_addr, hook_addr, tid) {
            const param = context[`x${paramIndex}`];

            if (!showDetails && onlyShowChanges) {
                // 静默模式，只在 leave 时输出
                this.param = param;
                return;
            }

            console.log(`\n${"▼".repeat(80)}`);
            console.log(`[${label}] 调用进入`);
            console.log(`  参数 x${paramIndex}:`, param);

            try {
                // 读取 shared_ptr 结构（如果启用）
                if (verifySharedPtr) {
                    const obj_ptr = safeReadPointer(ptr(param));
                    const ref_ptr = safeReadPointer(ptr(param).add(8));

                    console.log(`\n  shared_ptr 结构：`);
                    console.log(`    [0] 对象指针:`, obj_ptr);
                    console.log(`    [8] 引用计数指针:`, ref_ptr);

                    if (ref_ptr) {
                        try {
                            const refCount = ref_ptr.readU32();
                            console.log(`    *[8] 引用计数:`, refCount);
                        } catch (e) {}
                    }

                    savedState = {
                        param_addr: param.toString(),
                        obj_ptr: obj_ptr ? obj_ptr.toString() : null,
                        ref_ptr: ref_ptr ? ref_ptr.toString() : null
                    };
                } else {
                    savedState = {
                        param_addr: param.toString()
                    };
                }

                // 跟随指针链
                const dataPtr = followPointerChain(ptr(param), pointerChain);

                if (dataPtr) {
                    console.log(`\n  数据指针（指针链 ${pointerChain.join(' -> ')}）:`, dataPtr);
                    savedState.dataPtr = dataPtr.toString();

                    // 创建快照
                    if (snapshotFields.length > 0) {
                        const snapshot = createSnapshot(dataPtr, snapshotFields);
                        savedState.snapshot = snapshot;

                        if (showDetails && Object.keys(snapshot).length > 0) {
                            console.log(`\n  【调用前快照】`);
                            Object.entries(snapshot).forEach(([name, data]) => {
                                let displayValue = data.value;
                                if (typeof displayValue === 'string' && displayValue.length > 60) {
                                    displayValue = displayValue.substring(0, 60) + '...';
                                }
                                console.log(`    ${name} (+${data.offset}): ${displayValue}`);
                            });
                        }
                    }
                } else {
                    console.log(`\n  [!] 无法跟随指针链`);
                }

            } catch (e) {
                console.log(`  [!] 读取参数失败: ${e.message}`);
            }

            console.log(`${"▼".repeat(80)}\n`);
            this.param = param;
        },

        customLeave: function(thisContext, retval, context, args, base_addr, hook_addr) {
            const param = ptr(thisContext.param);

            console.log(`\n${"▲".repeat(80)}`);
            console.log(`[${label}] 调用返回`);
            console.log(`  返回值:`, retval);

            try {
                // 验证 shared_ptr 指针是否变化
                if (verifySharedPtr && savedState) {
                    const obj_ptr = safeReadPointer(param);
                    const ref_ptr = safeReadPointer(param.add(8));

                    console.log(`\n  shared_ptr 结构（返回后）：`);
                    console.log(`    [0] 对象指针:`, obj_ptr);
                    console.log(`    [8] 引用计数指针:`, ref_ptr);

                    if (ref_ptr) {
                        try {
                            const refCount = ref_ptr.readU32();
                            console.log(`    *[8] 引用计数:`, refCount);
                        } catch (e) {}
                    }

                    const ptrChanged = (obj_ptr && savedState.obj_ptr && obj_ptr.toString() !== savedState.obj_ptr);
                    console.log(`\n  ✓ 对象指针是否变化:`, ptrChanged ? "是" : "否");

                    if (!ptrChanged && obj_ptr) {
                        console.log(`    ✓ 确认：指针始终指向同一对象`);
                    }
                }

                // 读取调用后的数据
                const dataPtr = followPointerChain(param, pointerChain);

                if (dataPtr && savedState && savedState.snapshot) {
                    const newSnapshot = createSnapshot(dataPtr, snapshotFields);
                    const changes = compareSnapshots(savedState.snapshot, newSnapshot);

                    const changedCount = Object.keys(changes).length;

                    console.log(`\n  【调用后对比】`);
                    console.log(`    变化字段数: ${changedCount} / ${snapshotFields.length}`);

                    if (changedCount > 0) {
                        console.log(`\n    详细变化：`);
                        Object.entries(changes).forEach(([name, change]) => {
                            console.log(`      ${name} (+${change.offset}): ✅ 已变化`);
                            if (showDetails) {
                                let beforeVal = change.before;
                                let afterVal = change.after;

                                if (typeof beforeVal === 'string' && beforeVal.length > 50) {
                                    beforeVal = beforeVal.substring(0, 50) + '...';
                                }
                                if (typeof afterVal === 'string' && afterVal.length > 50) {
                                    afterVal = afterVal.substring(0, 50) + '...';
                                }

                                console.log(`        调用前: ${beforeVal || '(空)'}`);
                                console.log(`        调用后: ${afterVal || '(空)'}`);
                            }
                        });
                    } else if (!onlyShowChanges) {
                        console.log(`    ⚪ 所有字段均未变化`);
                    }

                    // 最终结论
                    console.log(`\n  ${"═".repeat(70)}`);
                    if (changedCount > 0) {
                        console.log(`  【结论】✅ 参数指向的数据已被修改`);
                        if (verifySharedPtr && targetFuncState) {
                            console.log(`  这证明了：参数拷贝后共享同一个对象`);
                        }
                    } else {
                        console.log(`  【结论】⚪ 参数指向的数据未发生变化`);
                    }
                    console.log(`  ${"═".repeat(70)}`);
                }

            } catch (e) {
                console.log(`  [!] 读取返回后参数失败: ${e.message}`);
            }

            console.log(`${"▲".repeat(80)}\n`);
        }
    });

    // 如果需要验证 shared_ptr，hook 目标函数
    if (verifySharedPtr && targetFunc) {
        native_hook(soName, targetFunc, {
            logEnter: false,
            logLeave: false,

            customEnter: function(args, context, retval, base_addr, hook_addr, tid) {
                const targetParam = context[`x${targetParamIndex}`];

                console.log(`\n${"→".repeat(80)}`);
                console.log(`[0x${targetFunc.toString(16)}] 目标函数调用`);
                console.log(`  参数 x${targetParamIndex}:`, targetParam);

                try {
                    const obj_ptr = safeReadPointer(ptr(targetParam));
                    const ref_ptr = safeReadPointer(ptr(targetParam).add(8));

                    console.log(`\n  shared_ptr 结构：`);
                    console.log(`    [0] 对象指针:`, obj_ptr);
                    console.log(`    [8] 引用计数指针:`, ref_ptr);

                    if (ref_ptr) {
                        try {
                            const refCount = ref_ptr.readU32();
                            console.log(`    *[8] 引用计数:`, refCount);
                        } catch (e) {}
                    }

                    // 验证是否指向同一对象
                    if (savedState && savedState.obj_ptr) {
                        const isSame = (obj_ptr && obj_ptr.toString() === savedState.obj_ptr);

                        console.log(`\n  ${"═".repeat(70)}`);
                        console.log(`  【关键验证】是否指向同一对象？`);
                        console.log(`    源参数 [0]:`, savedState.obj_ptr);
                        console.log(`    目标参数 [0]:`, obj_ptr ? obj_ptr.toString() : null);
                        console.log(`    结果:`, isSame ? "✅ 是同一个对象！" : "❌ 不同对象");

                        if (isSame) {
                            console.log(`\n    ✓ 这证明参数拷贝是浅拷贝（指针拷贝）`);
                            console.log(`    ✓ 两个参数共享底层数据`);
                            console.log(`    ✓ 对目标参数的修改会直接影响源参数`);
                        }
                        console.log(`  ${"═".repeat(70)}`);

                        targetFuncState = {
                            isSameObject: isSame
                        };
                    }

                } catch (e) {
                    console.log(`  [!] 读取目标参数失败: ${e.message}`);
                }

                console.log(`${"→".repeat(80)}\n`);
            },

            customLeave: function(thisContext, retval, context, args, base_addr, hook_addr) {
                console.log(`\n${"←".repeat(80)}`);
                console.log(`[0x${targetFunc.toString(16)}] 目标函数返回`);
                console.log(`  返回值:`, retval);
                console.log(`  ✓ 数据修改已完成`);
                console.log(`${"←".repeat(80)}\n`);
            }
        });
    }

    console.log(`[参数追踪器] Hook 已安装，等待调用...\n`);
}

/**
 * 快捷函数：追踪 shared_ptr 参数变化
 *
 * @param {string} soName - SO 库名称
 * @param {number} callerFunc - 上层调用函数偏移
 * @param {number} targetFunc - 目标处理函数偏移
 * @param {Object} config - 其他配置
 *
 * @example
 * track_shared_ptr_changes("libmetasec_ml.so", 0xED7B0, 0xEF920, {
 *   paramIndex: 1,
 *   pointerChain: [0, 24],
 *   snapshotFields: [
 *     { offset: 200, name: "field1", type: "string" }
 *   ]
 * });
 */
export function track_shared_ptr_changes(soName, callerFunc, targetFunc, config = {}) {
    return track_param_changes(soName, callerFunc, {
        ...config,
        verifySharedPtr: true,
        targetFunc: targetFunc,
        targetParamIndex: config.targetParamIndex || 1
    });
}