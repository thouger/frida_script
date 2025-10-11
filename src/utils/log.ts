// @ts-nocheck
import {hexdumpAdvanced} from "../so/BufferUtils.js"

export function log(message: string) {
  let colorCode;
  switch (Math.floor(Math.random() * 6)) {
    case 0:
      colorCode = '\x1b[31m'; // 红色
      break;
    case 1:
      colorCode = '\x1b[32m'; // 绿色
      break;
    case 2:
      colorCode = '\x1b[33m'; // 黄色
      break;
    case 3:
      colorCode = '\x1b[35m'; // 紫色
      break;
    case 4:
      colorCode = '\x1b[36m'; // 青色
      break;
    case 5:
      colorCode = '\x1b[37m'; // 白色
      break;
    default:
      colorCode = '';
      break;
  }
  console.log(`${colorCode}${message}\x1b[0m`);
}


export function stacktrace_java(){
  return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new())
}

export function stacktrace_so(context){
return 'stacktrace_so called from:\n' +Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n';
}

export function print_byte(byte){
  var str = Java.use("java.lang.String").$new(byte);
  return str;
}

export function print_hashmap(map) {
  var result = "";
  var HashMapNode = Java.use("java.util.HashMap$Node");
  var iterator = map.entrySet().iterator();
  while (iterator.hasNext()) {
      console.log("entry", iterator.next());
      var entry = Java.cast(iterator.next(), HashMapNode);
      console.log(entry.getKey());
      console.log(entry.getValue());
      result += entry.getValue();
  }
  
  console.log("result is :", result);

  return result
}



/**
 * 打印ARM64寄存器的值
 * @param {Array<string>|null} regs - 要打印的寄存器数组，不传或null则打印全部
 * @param {number} length - hexdump的长度参数，默认为5000
 */
export function printRegisters(context,regs = null, length = 5000) {
    // 定义ARM64架构中的所有通用寄存器
    const allRegisters = [
      "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
      "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
      "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
      "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp", "pc"
    ];
    
    // 如果没有指定寄存器，则使用所有寄存器
    const registersToPrint = regs || allRegisters;
    
  // 遍历并打印每个寄存器的值
  for (let i = 0; i < registersToPrint.length; i++) {
    const reg = registersToPrint[i];
    try {
      // 根据是否提供length参数，决定调用hexdump的方式
      if (length !== null) {
        log(reg + ":" + hexdump(context[reg], {length: length}));
      } else {
        log(reg + ":" + hexdump(context[reg]));
      }
    } catch (error) {
      log("无法打印寄存器 " + reg + ": " + error.message);
    }
  }
}

  // 使用示例:
  
  // 1. 打印所有寄存器(默认长度5000)
  // printRegisters();
  
  // 2. 只打印特定寄存器
  // printRegisters(["x0", "x1", "x2"]);
  
  // 3. 使用自定义长度打印特定寄存器
  // printRegisters(["x2", "x8"], 1000);
  
  // 4. 使用默认寄存器列表，但自定义长度
  // printRegisters(null, 2000);
  // 或者
  // printRegisters(undefined, 2000);
