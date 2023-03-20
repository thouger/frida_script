//@ts-nocheck
import { log } from "../utils/log";

export function invoke_hook(){
    Java.use("java.lang.reflect.Method").invoke.overload("java.lang.Object", "[Ljava.lang.Object;").implementation = function (param0,param1) {
        output = "";
        log("invoke() called with: param0 = [" + param0 + "], param1 = [" + param1 + "]"+'\n');
        return this.invoke(param0,param1);
    };
}