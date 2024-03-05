// @ts-nocheck
import { stacktrace,log } from "../utils/log.js";

export function hook_string(){

//   var targetClass = Java.use("java.lang.StringBuilder");
  // targetClass.append.overload('java.lang.String').implementation = function (str) {
  //   var output = '';
  //   output = output.concat("=================String.append====================");
  //   output = output.concat("str: " + str + " => " + JSON.stringify(str));
  //   output = output.concat("\r\n")
  //   output = output.concat(stacktrace());
  //   output = output.concat("=================String.append====================");
  //   if (output.indexOf("AFa1wSDK") != -1)

  //       log(output);
  //   var retval = this.append(str);
  //   return retval;
  // };

    const StringBuilder = Java.use('java.lang.StringBuilder');
     StringBuilder.toString.implementation = function () {
    		var res = this.toString();
    		var tmp = "";
    		if (res !== null){
    		    tmp = res.toString().replace("/n", "");
    		    console.log(tmp);
    		}
    		return res;
    };
}

// export function hook_stringBuilder() {



//     StringBuilder.$init.overload('java.lang.String').implementation = function (str) {
//         var output = str.toString() + '\n'
//         output=output.concat(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
//         output=output.concat("\r\n");
//         log(output);
//         return this.$init(str);
//     };
// }