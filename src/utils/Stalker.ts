// @ts-nocheck

// Import can be uncommented if using external logger module
// import { LogColor } from './logger';

/**
 * Advanced instruction tracing with register state comparison
 * 
 * @param {string} moduleName - Name of the module to trace
 * @param {number} [offset=0] - Offset within the module to start tracing from
 * @param {number} [size=0] - Size of memory to trace (0 means the entire module)
 * @param {boolean} [excludeOthers=true] - Whether to exclude other modules from tracing
 * @param {Object} [options] - Additional options
 * @param {boolean} [options.showRegisters=true] - Whether to show register changes
 * @param {boolean} [options.trackStrings=true] - Whether to attempt reading strings from registers
 */
export function traceFunctions(moduleName, offset = 0, size = 0, excludeOthers = true, options = {}) {
    const defaults = {
        showRegisters: true,
        trackStrings: true
    };
    
    const config = { ...defaults, ...options };
    
    // Find the target module
    let targetModule = Process.findModuleByName(moduleName);
    if (!targetModule) {
        console.error(`Module ${moduleName} not found. Consider using hook_dlopen to wait for it to load.`);
        return;
    }
    
    const moduleBase = targetModule.base;
    console.log(`Tracing module: ${moduleName} at ${moduleBase}`);
    
    // Exclude other modules if requested
    if (excludeOthers) {
        const modules = Process.enumerateModules();
        modules.forEach(module => {
            if (module.name !== moduleName) {
                console.log(`Excluding ${module.name}`);
                Stalker.exclude({
                    "base": module.base,
                    "size": module.size
                });
            }
        });
    }
    
    // Variables for tracking state between executions
    let isFirstIn = true;
    let prevRegs = null;
    let infoMap = new Map();
    let detailInsMap = new Map();
    let lastAddr = undefined;
    let currentIndex = 0;
    
    // Attach to the specified offset in the module
    Interceptor.attach(moduleBase.add(offset), {
        onEnter: function(args) {
            this.pid = Process.getCurrentThreadId();
            console.log(`Following thread: ${this.pid}`);
            
            Stalker.follow(this.pid, {
                transform: function(iterator) {
                    const instruction = iterator.next();
                    let startAddress = instruction.address;
                    
                    // Calculate size for tracing if not specified
                    if (size === 0) {
                        size = targetModule.size;
                    }
                    
                    // Check if instruction is within our target range
                    const isModuleCode = startAddress.compare(moduleBase.add(offset)) >= 0 &&
                        startAddress.compare(moduleBase.add(offset).add(size)) < 0;
                    
                    do {
                        if (isModuleCode) {
                            let offsetHex = getOffsetHex(instruction);
                            let address = instruction.address;
                            let offset = address - moduleBase;
                            let lastInfo = offsetHex + "\t\t" + instruction;
                            
                            // Store instruction information for later use
                            detailInsMap.set(offset, JSON.stringify(instruction));
                            infoMap.set(offset, lastInfo);
                            
                            // Add callout to analyze register state when instruction executes
                            iterator.putCallout(function(context) {
                                if (isFirstIn) {
                                    isFirstIn = false;
                                    // Save registers on first execution
                                    prevRegs = formatRegisters(context);
                                } else if (config.showRegisters) {
                                    // Compare current registers with previous state
                                    let pcReg = getPcRegister(prevRegs);
                                    let offset = Number(pcReg) - moduleBase;
                                    let logInfo = infoMap.get(offset);
                                    let detailIns = detailInsMap.get(offset);
                                    
                                    // Get register changes
                                    let entity = compareRegisters(context, detailIns, config.trackStrings);
                                    logWithColor(logInfo + " ; " + entity.info, entity.color);
                                }
                            });
                        }
                        iterator.keep();
                    } while (iterator.next() != null);
                },
            });
        },
        onLeave: function(ret) {
            console.log(`Leaving function, return: ${ret}`);
            Stalker.unfollow(this.pid);
        }
    });
}

/**
 * Gets the hex representation of the offset for an instruction
 */
function getOffsetHex(instruction) {
    let address = instruction.address;
    return address.toString(16);
}

/**
 * Formats ARM64 registers into an array
 */
function formatRegisters(context) {
    let regs = [];
    // Extract x0-x28 registers
    for (let i = 0; i <= 28; i++) {
        regs.push(context['x' + i]);
    }
    // Add special registers
    regs.push(context.fp);
    regs.push(context.lr);
    regs.push(context.sp);
    regs.push(context.pc);
    return regs;
}

/**
 * Gets the PC register value from the register array
 */
function getPcRegister(regs) {
    return regs[32]; // PC is at index 32 in our array
}

/**
 * Compare current register state with previous state and return changes
 */
function compareRegisters(context, instructionDetails, trackStrings = true) {
    let currentRegs = formatRegisters(context);
    let logInfo = "";
    let parsedInstruction = null;
    
    try {
        parsedInstruction = JSON.parse(instructionDetails);
    } catch (e) {
        console.error("Failed to parse instruction details:", e);
    }
    
    // Check for register changes
    for (let i = 0; i < 32; i++) {
        if (i === 30) continue; // Skip the 30th register (lr)
        
        let prevReg = prevRegs[i];
        let currentReg = currentRegs[i];
        
        if (Number(prevReg) !== Number(currentReg)) {
            if (logInfo === "" && trackStrings) {
                // Try to read string from register
                let changeString = "";
                try {
                    let nativePointer = new NativePointer(currentReg);
                    changeString = nativePointer.readCString();
                } catch (e) {
                    changeString = "";
                }
                
                if (changeString !== "") {
                    currentReg = currentReg + "   (" + changeString + ")";
                }
                
                logInfo = "\t " + getRegisterName(i) + " = " + prevReg + " --> " + currentReg;
            } else {
                logInfo = logInfo + "\t " + getRegisterName(i) + " = " + prevReg + " --> " + currentReg;
            }
        }
    }
    
    // Add instruction-specific info
    if (parsedInstruction) {
        const mnemonic = parsedInstruction.mnemonic;
        
        // Handle specific instructions
        if (mnemonic === "str") {
            let strParams = getStrParams(parsedInstruction, currentRegs);
            if (strParams) logInfo += strParams;
        } else if (mnemonic === "cmp") {
            let cmpParams = getCmpParams(parsedInstruction, currentRegs);
            if (cmpParams) logInfo += cmpParams;
        } else if (["b.gt", "b.le", "b.eq", "b.ne", "b"].includes(mnemonic)) {
            let branchAddr = getBranchAddr(parsedInstruction);
            if (branchAddr) logInfo += branchAddr;
        }
    }
    
    // Store current registers for next comparison
    prevRegs = currentRegs;
    
    // Rotate colors for better visibility
    let color = getNextColor();
    
    return {
        info: logInfo,
        color: color
    };
}

/**
 * Gets the register name for a given index
 */
function getRegisterName(index) {
    if (index === 31) {
        return "sp";
    } else {
        return "x" + index;
    }
}

/**
 * Gets branch target address for branch instructions
 */
function getBranchAddr(instruction) {
    if (!instruction || !instruction.operands) return "";
    
    let branchAddr = "";
    for (let operand of instruction.operands) {
        if (operand.type === "imm") {
            let value = operand.value;
            branchAddr = "\t branch target: 0x" + value.toString(16);
            break;
        }
    }
    return branchAddr;
}

/**
 * Gets store instruction information
 */
function getStrParams(instruction, currentRegs) {
    if (!instruction || !instruction.operands) return "";
    
    for (let operand of instruction.operands) {
        if (operand.type === "reg") {
            let value = operand.value;
            if (value === "wzr") {
                return "\t str = 0";
            } else {
                let regIndex = value.replace(/[wx]/g, "");
                let regValue = currentRegs[regIndex];
                
                // Try to read string from register
                let strValue = "";
                try {
                    let nativePointer = new NativePointer(regValue);
                    strValue = nativePointer.readCString();
                    if (strValue) {
                        regValue = regValue + "   (" + strValue + ")";
                    }
                } catch (e) { }
                
                return "\t str = " + regValue;
            }
        }
    }
    return "";
}

/**
 * Gets compare instruction information
 */
function getCmpParams(instruction, currentRegs) {
    if (!instruction || !instruction.operands) return "";
    
    let cmpInfo = "";
    for (let operand of instruction.operands) {
        if (operand.type === "reg") {
            let value = operand.value;
            let regIndex = value.replace(/[wx]/g, "");
            let regValue = currentRegs[regIndex];
            
            // Try to read string from register
            let strValue = "";
            try {
                let nativePointer = new NativePointer(regValue);
                strValue = nativePointer.readCString();
                if (strValue) {
                    regValue = regValue + "   (" + strValue + ")";
                }
            } catch (e) { }
            
            cmpInfo += "\t " + value + " = " + regValue;
        }
    }
    return cmpInfo;
}

// Color rotation system
let colorIndex = 0;
const colors = [
    LogColor.C35,  // Purple
    LogColor.C36,  // Cyan
    LogColor.C32,  // Green
    LogColor.C33,  // Yellow
    LogColor.C34   // Blue
];

/**
 * Get the next color in rotation
 */
function getNextColor() {
    let color = colors[colorIndex];
    colorIndex = (colorIndex + 1) % colors.length;
    return color;
}

/**
 * Log with color
 */
function logWithColor(message, color) {
    if (typeof console.logColor === 'function') {
        console.logColor(message, color);
    } else {
        // Fallback if logColor isn't available
        console.log(message);
    }
}

// Logger utility - can be imported from external module
export const LogColor = {
    WHITE: 0,
    RED: 1,
    YELLOW: 3,
    C31: 31,
    C32: 32,
    C33: 33,
    C34: 34,
    C35: 35,
    C36: 36,
    C41: 41,
    C42: 42,
    C43: 43,
    C44: 44,
    C45: 45,
    C46: 46,
    C90: 90,
    C91: 91,
    C92: 92,
    C93: 93,
    C94: 94,
    C95: 95,
    C96: 96,
    C97: 97,
    C100: 100,
    C101: 101,
    C102: 102,
    C103: 103,
    C104: 104,
    C105: 105,
    C106: 106,
    C107: 107
};

/**
 * Hook dynamic library loading to detect when a specific library is loaded
 * 
 * @param {string} so_name - Name of the shared object to look for
 * @param {Function} hook_func - Function to call when the library is loaded
 * @param {number} so_addr - Optional address parameter to pass to hook_func
 */
export function hook_dlopen(so_name = null, hook_func = null, so_addr = null) {
    console.log('hook_dlopen for ' + so_name);
    
    // Hook android_dlopen_ext (Android specific)
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    if (android_dlopen_ext != null) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function (args) {
                var soName = args[0].readCString();
                // console.log('soName:' + soName);
                if (so_name && soName.indexOf(so_name) != -1) {
                    console.log('Found ' + so_name + ' in android_dlopen_ext');
                    this.hook = true;
                }
            },
            onLeave: function (retval) {
                if (this.hook && hook_func) {
                    hook_func(so_addr); // Pass the so_addr parameter
                }
            }
        });
    }
    
    // Hook dlopen (more universal)
    var dlopen = Module.findExportByName(null, "dlopen");
    if (dlopen != null) {
        Interceptor.attach(dlopen, {
            onEnter: function (args) {
                var soName = args[0].readCString();
                // console.log('soName:' + soName);
                if (so_name && soName.indexOf(so_name) != -1) {
                    console.log('Found ' + so_name + ' in dlopen');
                    this.hook = true;
                }
            },
            onLeave: function (retval) {
                if (this.hook && hook_func) {
                    hook_func(so_addr); // Pass the so_addr parameter
                }
            }
        });
    }
}

// Example usage:
// traceFunctions("libexample.so", 0x1234, 0x1000, true, { showRegisters: true, trackStrings: true });
// 
// To hook a library that might be loaded later:
// hook_dlopen("libexample.so", function(addr) {
//     traceFunctions("libexample.so", addr || 0x1234, 0x1000);
// }, 0x5678);