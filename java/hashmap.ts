// @ts-nocheck
import { stacktrace,log } from "../utils/log";

export function hook_hashmap(){
    var _HashMap=Java.use('java.util.HashMap');
    // _HashMap.put.implementation = function(arg1,arg2){
    //     var data=this.put(arg1,arg2);
    //     var output = '';
    //     output = output.concat("=================_HashMap.put====================");
    //     output = output.concat("arg1: " + arg1 + " => " + JSON.stringify(arg1));
    //     output = output.concat("\r\n")
    //     output = output.concat("arg2: " + arg2 + " => " + JSON.stringify(arg2));
    //     output = output.concat("\r\n")
    //     output = output.concat(stacktrace());
    //     output = output.concat("=================_HashMap.put====================");
    //     log(output);
    //     return data;
    // }   

    //会直接崩溃
    _HashMap.get.implementation = function(arg1){
        var data=this.get(arg1);
        var output = '';
        output = output.concat("=================_HashMap.get====================");
        output = output.concat("arg1: " + arg1 + " => " + JSON.stringify(arg1));
        output = output.concat("\r\n")
        output = output.concat("data: " + data + " => " + JSON.stringify(data));
        output = output.concat("\r\n")
        output = output.concat(stacktrace());
        output = output.concat("=================_HashMap.get====================");
        if (output.indexOf("AFa1wSDK") != -1)
            log(output);
        
        return data;
    }
}