// @ts-nocheck
export function log(message:string) {
    let colorCode;
    switch (Math.floor(Math.random() * 8)) {
      case 0:
        colorCode = '\x1b[30m';
        break;
      case 1:
        colorCode = '\x1b[31m';
        break;
      case 2:
        colorCode = '\x1b[32m';
        break;
      case 3:
        colorCode = '\x1b[33m';
        break;
      case 4:
        colorCode = '\x1b[34m';
        break;
      case 5:
        colorCode = '\x1b[35m';
        break;
      case 6:
        colorCode = '\x1b[36m';
        break;
      case 7:
        colorCode = '\x1b[45m';
        break;
        break;
      case 8:
        colorCode = '\x1b[1m';
        break;
      case 9:
        colorCode = '\x1b[4m';
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