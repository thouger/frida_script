// @ts-nocheck
export function log(message: string) {
  let colorCode;
  switch (Math.floor(Math.random() * 7)) {
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
      colorCode = '\x1b[34m'; // 蓝色
      break;
    case 4:
      colorCode = '\x1b[35m'; // 紫色
      break;
    case 5:
      colorCode = '\x1b[36m'; // 青色
      break;
    case 6:
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

export function print_hashmap(hashmap){
  var output = "";

  var HashMapNode = Java.use('java.util.HashMap$Node');
  var hashmap = Java.cast(hashmap, Java.use('java.util.HashMap'));
    var iterator = hashmap.entrySet().iterator();
    while (iterator.hasNext()) {
      var entry = Java.cast(iterator.next(), HashMapNode);
        output = output.concat(entry.getKey() + " => " + entry.getValue()+"\r");
    }
    return output;
}