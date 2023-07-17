
//@ts-nocheck
import { log } from "../utils/log.js";
import {hook_dlopen} from "./utils.js";


export function so_method(so_name:string){
    hook_dlopen(so_name,function(){
        var output = ''
        const export_method = Module.enumerateExports(so_name)
        export_method.forEach((element: { name: string }) => {
            output += `export method:${element.name}\n`;
        }); 

        const symbols_method = Module.enumerateSymbols(so_name)
        symbols_method.forEach((element: { name: string }) => {
            output += `export method:${element.name}\n`;
        });

        const improt_method = Module.enumerateImports('libencryptlib.so')
        improt_method.forEach((element: { name: string }) => {
            output += `export method:${element.name}\n`;
        });
        log(output)
    })
}