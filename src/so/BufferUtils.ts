// @ts-nocheck
// src/utils/buffer.ts
import { log } from "../utils/log.js";

interface HexdumpOptions {
    showTotal?: boolean;
    showAscii?: boolean;
    bytesPerLine?: number;
}

export function hexdumpAdvanced(buffer: any, length: number=500, options: HexdumpOptions = {}) {
    const {
        showTotal = true,
        showAscii = true,
        bytesPerLine = 16
    } = options;
    
    let output = '';
    
    if (showTotal) {
        output += `Total length: ${length} (0x${length.toString(16)})\n`;
    }

    // 判断buffer是否为空
    if (!buffer) {
        log('Buffer is null');
        return;
    }
    
    output += 'Offset    | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F';
    if (showAscii) output += ' | ASCII';
    output += '\n' + '-'.repeat(showAscii ? 75 : 58) + '\n';
    
    for (let i = 0; i < length; i += bytesPerLine) {
        output += `${i.toString(16).padStart(8, '0')}  | `;
        
        let hexPart = '';
        let asciiPart = '';
        
        for (let j = 0; j < bytesPerLine; j++) {
            if (i + j < length) {
                const byte = buffer.add(i + j).readU8();
                hexPart += `${byte.toString(16).padStart(2, '0')} `;
                
                if (showAscii) {
                    const char = (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
                    asciiPart += char;
                }
                
                if (j === 7) hexPart += ' ';
            } else {
                hexPart += '   ';
                if (j === 7) hexPart += ' ';
                if (showAscii) asciiPart += ' ';
            }
        }
        
        log(output + hexPart + (showAscii ? `| ${asciiPart}` : ''));
        output = '';
    }
}

export function hexdumpAsciiOnly(buffer: any, length: number = 500) {
    try{
        let result = '';

        for (let i = 0; i < length; i++) {
            const byte = buffer.add(i).readU8();
            // 只获取可打印的 ASCII 字符
            if (byte >= 32 && byte <= 126) {
                result += String.fromCharCode(byte);
            }
        }

        // 输出结果
        log(result);
        return result;

    }catch(e){
        return "";
    }

    // 如果你需要返回结果而不是直接打印
}

/**
 * 将字节数组转换为十六进制字符串
 * @param bytes - 字节数组
 * @returns 十六进制字符串
 */
export function toHex(bytes: any) {
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        let byte = bytes[i] & 0xff;
        hex += ('0' + byte.toString(16)).slice(-2)