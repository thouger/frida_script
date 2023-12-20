// @ts-nocheck
import { hook_dlopen } from "../so/utils.js"

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


export function stacktrace(){
    return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new())
}

export function print_hashmap(hashmap) {
  if (!hashmap) {
    console.log('Invalid hashmap');
    return;
  }

  var output = "";

  var HashMapNode = Java.use('java.util.HashMap$Node');
  var iterator = hashmap.entrySet().iterator();
  while (iterator.hasNext()) {
    var entry = Java.cast(iterator.next(), HashMapNode);
    var key = entry.getKey();
    var value = entry.getValue();

    if(!key)
    key='null'
    if(!value)
    value='null'
    output += key.toString() + " => " + value.toString() + "\n";
  }

  // console.log(output); // 输出到 Frida 控制台
  return output; // 返回输出结果
}


export function native_print(so_name,so_addr){
  function hexdumpMem(addr){
    if(Process.findRangeByAddress(addr)){
        return hexdump(ptr(addr),{length:0x40})+"\r\n"
    }else{
        return ptr(addr)+"\r\n";
    }
}
//比较通用的hook地址并且打印5个参数。如果参数是地址就打印下内存信息
function nativeHookFunction(addr){
    var base_addr=Module.getBaseAddress(so_name);
    var hook_addr=base_addr.add(addr);
    console.log("hook_addr:",hook_addr);
    Interceptor.attach(hook_addr,{
        onEnter:function(args){
            this.logs=[];
            this.logs.push("call",addr);
            this.arg0=args[0];
            this.arg1=args[1];
            this.arg2=args[2];
            this.arg3=args[3];
            this.arg4=args[4];
            this.arg5=args[5];
            this.logs.push("arg0:",hexdumpMem(this.arg0));
            this.logs.push("arg1:",hexdumpMem(this.arg1));
            this.logs.push("arg2:",hexdumpMem(this.arg2));
            this.logs.push("arg3:",hexdumpMem(this.arg3));
            this.logs.push("arg4:",hexdumpMem(this.arg4));
            this.logs.push("arg5:",hexdumpMem(this.arg5));
        },onLeave:function(retval){
            this.logs.push("arg0 leave:",hexdumpMem(this.arg0));
            this.logs.push("arg1 leave:",hexdumpMem(this.arg1));
            this.logs.push("arg2 leave:",hexdumpMem(this.arg2));
            this.logs.push("arg3 leave:",hexdumpMem(this.arg3));
            this.logs.push("arg4 leave:",hexdumpMem(this.arg4));
            this.logs.push("arg5 leave:",hexdumpMem(this.arg5));
            this.logs.push("retval leave:",hexdumpMem(retval));
            console.log(this.logs);
        }
    })
}
  hook_dlopen(so_name,nativeHookFunction,so_addr);
}