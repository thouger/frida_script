//@ts-nocheck
import {native_hook} from "./so/hook_func.js"
import {hexdumpAdvanced} from "./so/BufferUtils.js"

// Java.perform(function() {
//     const env = Java.vm.getEnv();
//     const jniEnvPtr = env.handle.readPointer();

//     const GetStringUTFCharsPtr = jniEnvPtr.add(Process.pointerSize * 169).readPointer();
//     GetStringUTFCharsFunc = new NativeFunction(GetStringUTFCharsPtr, 'pointer', ['pointer', 'pointer', 'pointer']);

//     const ReleaseStringUTFCharsPtr = jniEnvPtr.add(Process.pointerSize * 170).readPointer();
//     ReleaseStringUTFCharsFunc = new NativeFunction(ReleaseStringUTFCharsPtr, 'void', ['pointer', 'pointer', 'pointer']);

//     console.log("[+] JNI 函数指针已初始化");
// });

// 辅助函数：读取 jstring
// function readJString(env, jstring) {
//     if (!jstring || jstring.isNull() || ptr(jstring).compare(0x1000) < 0) {
//         return null;
//     }
//     try {
//         const chars = GetStringUTFCharsFunc(env, jstring, NULL);
//         if (chars.isNull()) {
//             return null;
//         }
//         const result = chars.readCString();
//         ReleaseStringUTFCharsFunc(env, jstring, chars);
//         return result;
//     } catch(e) {
//         return null;
//     }
// }

let callCount_1B1990 = 0;
let callCount_19643C = 0;

// Hook 1: sub_19643C - Protobuf serialization (before encryption)
native_hook("libmetasec_ml.so", 0x19643C, {
    logEnter: false,
    logLeave: false,
    customEnter: function(args, context, retval, base_addr, hook_addr, tid) {
        this.outputBuf = context.x1;
    },
    customLeave: function(thisContext, retval, context, args, base_addr, hook_addr) {
        let actualLength = retval.toInt32();

        // Only log large serializations (> 500 bytes)
        if (actualLength > 500 && actualLength < 100000) {
            callCount_19643C++;
            console.log("\n========== [PROTOBUF SERIALIZATION #" + callCount_19643C + "] ==========");
            console.log("Function: sub_19643C (Protobuf serializer)");
            console.log("Output length:", actualLength, "bytes");

            try {
                let outputBuf = thisContext.outputBuf;
                if (outputBuf && !outputBuf.isNull()) {
                    console.log("\n[Unencrypted Protobuf - First 256 bytes]:");
                    console.log(hexdumpAdvanced(outputBuf, Math.min(actualLength, 256)));

                    // Check if it starts with valid protobuf markers
                    let firstBytes = [];
                    for (let i = 0; i < Math.min(16, actualLength); i++) {
                        firstBytes.push(outputBuf.add(i).readU8().toString(16).padStart(2, '0'));
                    }
                    console.log("\nFirst 16 bytes:", firstBytes.join(' '));
                }
            } catch(e) {
                console.log("Error:", e.message);
            }
            console.log("===================\n");
        }
    }
});

// Hook 2: sub_1B1990 - JNI NewByteArray (after encryption)
native_hook("libmetasec_ml.so", 0x1B1990, {
    logEnter: false,
    logLeave: false,
    customEnter: function(args, context, retval, base_addr, hook_addr, tid) {
        let dataPtr = context.x1;
        let dataLen = context.x2.toInt32();

        // Only process large data (> 1000 bytes)
        if (dataLen > 1000 && dataLen < 100000) {
            callCount_1B1990++;

            console.log("\n========== [FINAL DATA PACKET #" + callCount_1B1990 + "] ==========");
            console.log("Function: sub_1B1990 (JNI NewByteArray)");
            console.log("Data length:", dataLen, "bytes");

            try {
                console.log("\n[Encrypted Data - First 512 bytes]:");
                console.log(hexdumpAdvanced(dataPtr, Math.min(dataLen, 512)));

                // Check first bytes
                let firstBytes = [];
                for (let i = 0; i < 16; i++) {
                    firstBytes.push(dataPtr.add(i).readU8().toString(16).padStart(2, '0'));
                }
                console.log("\nFirst 16 bytes:", firstBytes.join(' '));

                // Extract FULL hex data
                console.log("\n[EXTRACTING FULL " + dataLen + " BYTES...]");
                let hexBytes = [];
                for (let i = 0; i < dataLen; i++) {
                    hexBytes.push(dataPtr.add(i).readU8().toString(16).padStart(2, '0'));
                }

                // Output in chunks
                console.log("\n[HEX FORMAT - FULL DATA]:");
                let chunkSize = 1000;
                for (let i = 0; i < hexBytes.length; i += chunkSize) {
                    let chunk = hexBytes.slice(i, Math.min(i + chunkSize, hexBytes.length));
                    console.log(chunk.join(' '));
                }
                console.log("\n[END OF HEX DATA]");

            } catch(e) {
                console.log("Error:", e.message);
            }
            console.log("===================\n");
        } else if (dataLen > 0) {
            console.log("\n[sub_1B1990] Small data: " + dataLen + " bytes (skipped)\n");
        }
    }
});


// Hook protobuf_serialize 函数
// 函数原型: __int64 __usercall sub_1A86EC@<X0>(__int64 a1@<X1>, _QWORD *a2@<X8>)
let saved_x8 = null;
let saved_context = null;
native_hook("libmetasec_ml.so", 0x1A86EC, {
    logEnter: false,
    logLeave: false,
    customEnter: function(args, context, retval, base_addr, hook_addr, tid) {
        // 保存 x8 和 context，以便在 customLeave 中使用
        saved_x8 = ptr(context.x8);
        saved_context = context;

        // 打印输入的 protobuf message 对象
        const a1 = ptr(context.x1);
        console.log("\n========== protobuf_serialize 调用 - 输入数据 ==========");
        console.log("【输入对象地址 (x1)】:", a1);

        if (!a1.isNull()) {
            try {
                // 打印前 256 字节的内存数据
                console.log("\n【输入对象内存 (前256字节)】:");
                console.log(hexdump(a1, {
                    offset: 0,
                    length: 256,
                    header: true,
                    ansi: false
                }));

                // 尝试递归读取结构体字段，寻找字符串和数据
                console.log("\n【尝试解析对象字段】:");

                // 遍历前 64 个指针大小的偏移
                for (let i = 0; i < 64; i++) {
                    try {
                        const offset = i * 8;
                        const value = a1.add(offset).readPointer();

                        // 尝试判断是否是字符串指针
                        if (!value.isNull() && value.compare(0x1000) > 0) {
                            try {
                                const str = value.readCString(100);
                                if (str && str.length > 0 && str.length < 100) {
                                    // 检查是否是可打印字符串
                                    const isPrintable = /^[\x20-\x7E\s]+$/.test(str);
                                    if (isPrintable) {
                                        console.log(`  偏移 0x${offset.toString(16).padStart(2, '0')}: "${str}"`);
                                    }
                                }
                            } catch(e) {
                                // 不是字符串，忽略
                            }

                            // 也尝试读取整数值
                            try {
                                const int_val = a1.add(offset).readU32();
                                if (int_val > 0 && int_val < 0x7fffffff) {
                                    console.log(`  偏移 0x${offset.toString(16).padStart(2, '0')}: ${int_val} (0x${int_val.toString(16)})`);
                                }
                            } catch(e) {
                                // 忽略
                            }
                        }
                    } catch(e) {
                        // 忽略读取失败
                    }
                }
            } catch(e) {
                console.log("[!] 解析输入对象失败:", e.message);
            }
        }
    },

    customLeave: function(thisContext, retval, context, args, base_addr, hook_addr) {
        try {
            // 使用保存的 x8 值
            if (saved_x8 && !saved_x8.isNull()) {
                // x8 是指向输出缓冲区指针的地址，需要解引用
                const output_buffer_ptr = saved_x8.readPointer();

                if (!output_buffer_ptr.isNull()) {
                    // 尝试读取序列化数据的大小和指针
                    try {
                        const size = output_buffer_ptr.add(0xC).readU32();
                        const data_ptr = output_buffer_ptr.add(0x10).readPointer();

                        if (!data_ptr.isNull() && size > 0 && size < 100000) {
                            // 打印完整的 hexdump
                            console.log("\n【序列化后的 protobuf 数据 (完整hexdump)】:");
                            const hexdump_output = hexdump(data_ptr, {
                                offset: 0,
                                length: size,
                                header: true,
                                ansi: false
                            });
                            console.log(hexdump_output);

                            // 读取数据并转换为十六进制字符串，方便复制到在线工具
                            const protobuf_bytes = data_ptr.readByteArray(size);
                            const hex_string = Array.from(new Uint8Array(protobuf_bytes))
                                .map(b => b.toString(16).padStart(2, '0'))
                                .join('');

                            console.log("\n【Protobuf 十六进制字符串（可复制到在线解析工具）】:");
                            console.log(`长度: ${hex_string.length} 字符 (${size} 字节)`);
                            console.log(hex_string);

                            // 当十六进制字符串长度大于20000 时，打印调用栈
                            if (hex_string.length >= 20000) {
                                console.log("\n========== 检测到长度大于20000 的 Protobuf 数据，打印调用栈 ==========");
                                console.log(Thread.backtrace(saved_context, Backtracer.ACCURATE)
                                    .map(DebugSymbol.fromAddress).join('\n') + '\n');
                            }
                        }
                    } catch(e) {
                        console.log("[!] 读取序列化数据失败:", e.message);
                    }
                }
            }
        } catch(e) {
            console.log("[!] 读取输出失败:", e.message);
        }
    }
});
