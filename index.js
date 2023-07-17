📦
226 /src/index.js.map
91 /src/index.js
11 /src/index.d.ts
58 /src/so/so_method.d.ts
1143 /src/so/so_method.js.map
985 /src/so/so_method.js
73 /src/so/utils.d.ts
760 /src/so/utils.js.map
685 /src/so/utils.js
168 /src/utils/log.d.ts
1653 /src/utils/log.js.map
1533 /src/utils/log.js
✄
{"version":3,"file":"index.js","sourceRoot":"/Users/thouger/Documents/code/frida_script/","sources":["src/index.ts"],"names":[],"mappings":"AAAA,aAAa;AACb,OAAO,EAAE,SAAS,EAAE,MAAM,mBAAmB,CAAC;AAC9C,SAAS,CAAC,kBAAkB,CAAC,CAAA"}
✄
//@ts-nocheck
import { so_method } from "./so/so_method.js";
so_method('libnative-lib.so');
✄
export {};

✄
export declare function so_method(so_name: string): void;

✄
{"version":3,"file":"so_method.js","sourceRoot":"/Users/thouger/Documents/code/frida_script/","sources":["src/so/so_method.ts"],"names":[],"mappings":"AACA,aAAa;AACb,OAAO,EAAE,GAAG,EAAE,MAAM,iBAAiB,CAAC;AACtC,OAAO,EAAC,WAAW,EAAC,MAAM,YAAY,CAAC;AAGvC,MAAM,UAAU,SAAS,CAAC,OAAc;IACpC,WAAW,CAAC,OAAO,EAAC;QAChB,IAAI,MAAM,GAAG,EAAE,CAAA;QACf,MAAM,aAAa,GAAG,MAAM,CAAC,gBAAgB,CAAC,OAAO,CAAC,CAAA;QACtD,aAAa,CAAC,OAAO,CAAC,CAAC,OAAyB,EAAE,EAAE;YAChD,IAAI,OAAO,CAAC,IAAI,CAAC,OAAO,CAAC,MAAM,CAAC,KAAK,CAAC,CAAC,EAAE;gBACrC,MAAM,IAAI,iBAAiB,OAAO,CAAC,IAAI,IAAI,CAAC;aAC/C;QACL,CAAC,CAAC,CAAC;QAEH,MAAM,cAAc,GAAG,MAAM,CAAC,gBAAgB,CAAC,OAAO,CAAC,CAAA;QACvD,cAAc,CAAC,OAAO,CAAC,CAAC,OAAyB,EAAE,EAAE;YACjD,IAAI,OAAO,CAAC,IAAI,CAAC,OAAO,CAAC,MAAM,CAAC,KAAK,CAAC,CAAC,EAAE;gBACrC,MAAM,IAAI,UAAU,OAAO,CAAC,IAAI,IAAI,CAAC;aACxC;QACL,CAAC,CAAC,CAAC;QAEH,MAAM,aAAa,GAAG,MAAM,CAAC,gBAAgB,CAAC,kBAAkB,CAAC,CAAA;QACjE,aAAa,CAAC,OAAO,CAAC,CAAC,OAAyB,EAAE,EAAE;YAChD,IAAI,OAAO,CAAC,IAAI,CAAC,OAAO,CAAC,MAAM,CAAC,KAAK,CAAC,CAAC,EAAE;gBACrC,MAAM,IAAI,iBAAiB,OAAO,CAAC,IAAI,IAAI,CAAC;aAC/C;QACL,CAAC,CAAC,CAAC;QACH,GAAG,CAAC,MAAM,CAAC,CAAA;IACf,CAAC,CAAC,CAAA;AACN,CAAC"}
✄
//@ts-nocheck
import { log } from "../utils/log.js";
import { hook_dlopen } from "./utils.js";
export function so_method(so_name) {
    hook_dlopen(so_name, function () {
        var output = '';
        const export_method = Module.enumerateExports(so_name);
        export_method.forEach((element) => {
            if (element.name.indexOf(method) !== -1) {
                output += `export method:${element.name}\n`;
            }
        });
        const symbols_method = Module.enumerateSymbols(so_name);
        symbols_method.forEach((element) => {
            if (element.name.indexOf(method) !== -1) {
                output += `symbol:${element.name}\n`;
            }
        });
        const improt_method = Module.enumerateImports('libencryptlib.so');
        improt_method.forEach((element) => {
            if (element.name.indexOf(method) !== -1) {
                output += `import method:${element.name}\n`;
            }
        });
        log(output);
    });
}
✄
export declare function hook_dlopen(so_name: any, hook_func: any): void;

✄
{"version":3,"file":"utils.js","sourceRoot":"/Users/thouger/Documents/code/frida_script/","sources":["src/so/utils.ts"],"names":[],"mappings":"AAAA,aAAa;AACb,OAAO,EAAE,GAAG,EAAE,MAAM,iBAAiB,CAAC;AACtC,MAAM,UAAU,WAAW,CAAC,OAAO,EAAC,SAAS;IACzC,GAAG,CAAC,aAAa,CAAC,CAAA;IAClB,IAAI,kBAAkB,GAAG,MAAM,CAAC,gBAAgB,CAAC,IAAI,EAAE,oBAAoB,CAAC,CAAC;IAC7E,IAAI,kBAAkB,IAAI,IAAI,EAAE;QAC5B,WAAW,CAAC,MAAM,CAAC,kBAAkB,EAAE;YACnC,OAAO,EAAE,UAAU,IAAI;gBACnB,IAAI,MAAM,GAAG,IAAI,CAAC,CAAC,CAAC,CAAC,WAAW,EAAE,CAAC;gBACnC,IAAI,MAAM,CAAC,OAAO,CAAC,OAAO,CAAC,IAAI,CAAC,CAAC,EAAE;oBAC/B,GAAG,CAAC,SAAS,CAAC,CAAA;oBACd,IAAI,CAAC,IAAI,GAAG,IAAI,CAAC;iBACpB;YACL,CAAC;YACD,OAAO,EAAE,UAAU,MAAM;gBACrB,IAAI,IAAI,CAAC,IAAI;oBACT,SAAS,EAAE,CAAE;YACrB,CAAC;SACJ,CAAC,CAAC;KACN;AACL,CAAC"}
✄
//@ts-nocheck
import { log } from "../utils/log.js";
export function hook_dlopen(so_name, hook_func) {
    log('hook_dlopen');
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    if (android_dlopen_ext != null) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function (args) {
                var soName = args[0].readCString();
                if (soName.indexOf(so_name) != -1) {
                    log('find so');
                    this.hook = true;
                }
            },
            onLeave: function (retval) {
                if (this.hook)
                    hook_func();
            }
        });
    }
}
✄
export declare function log(message: string): void;
export declare function stacktrace(): any;
export declare function print_hashmap(hashmap: any): string | undefined;

✄
{"version":3,"file":"log.js","sourceRoot":"/Users/thouger/Documents/code/frida_script/","sources":["src/utils/log.ts"],"names":[],"mappings":"AAAA,cAAc;AACd,MAAM,UAAU,GAAG,CAAC,OAAe;IACjC,IAAI,SAAS,CAAC;IACd,QAAQ,IAAI,CAAC,KAAK,CAAC,IAAI,CAAC,MAAM,EAAE,GAAG,CAAC,CAAC,EAAE;QACrC,KAAK,CAAC;YACJ,SAAS,GAAG,UAAU,CAAC,CAAC,KAAK;YAC7B,MAAM;QACR,KAAK,CAAC;YACJ,SAAS,GAAG,UAAU,CAAC,CAAC,KAAK;YAC7B,MAAM;QACR,KAAK,CAAC;YACJ,SAAS,GAAG,UAAU,CAAC,CAAC,KAAK;YAC7B,MAAM;QACR,KAAK,CAAC;YACJ,SAAS,GAAG,UAAU,CAAC,CAAC,KAAK;YAC7B,MAAM;QACR,KAAK,CAAC;YACJ,SAAS,GAAG,UAAU,CAAC,CAAC,KAAK;YAC7B,MAAM;QACR,KAAK,CAAC;YACJ,SAAS,GAAG,UAAU,CAAC,CAAC,KAAK;YAC7B,MAAM;QACR;YACE,SAAS,GAAG,EAAE,CAAC;YACf,MAAM;KACT;IACD,OAAO,CAAC,GAAG,CAAC,GAAG,SAAS,GAAG,OAAO,SAAS,CAAC,CAAC;AAC/C,CAAC;AAGD,MAAM,UAAU,UAAU;IACtB,OAAO,IAAI,CAAC,GAAG,CAAC,kBAAkB,CAAC,CAAC,mBAAmB,CAAC,IAAI,CAAC,GAAG,CAAC,qBAAqB,CAAC,CAAC,IAAI,EAAE,CAAC,CAAA;AACnG,CAAC;AAED,MAAM,UAAU,aAAa,CAAC,OAAO;IACnC,IAAI,CAAC,OAAO,EAAE;QACZ,OAAO,CAAC,GAAG,CAAC,iBAAiB,CAAC,CAAC;QAC/B,OAAO;KACR;IAED,IAAI,MAAM,GAAG,EAAE,CAAC;IAEhB,IAAI,WAAW,GAAG,IAAI,CAAC,GAAG,CAAC,wBAAwB,CAAC,CAAC;IACrD,IAAI,QAAQ,GAAG,OAAO,CAAC,QAAQ,EAAE,CAAC,QAAQ,EAAE,CAAC;IAC7C,OAAO,QAAQ,CAAC,OAAO,EAAE,EAAE;QACzB,IAAI,KAAK,GAAG,IAAI,CAAC,IAAI,CAAC,QAAQ,CAAC,IAAI,EAAE,EAAE,WAAW,CAAC,CAAC;QACpD,IAAI,GAAG,GAAG,KAAK,CAAC,MAAM,EAAE,CAAC;QACzB,IAAI,KAAK,GAAG,KAAK,CAAC,QAAQ,EAAE,CAAC;QAE7B,IAAG,CAAC,GAAG;YACP,GAAG,GAAC,MAAM,CAAA;QACV,IAAG,CAAC,KAAK;YACT,KAAK,GAAC,MAAM,CAAA;QACZ,MAAM,IAAI,GAAG,CAAC,QAAQ,EAAE,GAAG,MAAM,GAAG,KAAK,CAAC,QAAQ,EAAE,GAAG,IAAI,CAAC;KAC7D;IAED,OAAO,CAAC,GAAG,CAAC,MAAM,CAAC,CAAC,CAAC,gBAAgB;IACrC,OAAO,MAAM,CAAC,CAAC,SAAS;AAC1B,CAAC"}
✄
// @ts-nocheck
export function log(message) {
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
export function stacktrace() {
    return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
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
        if (!key)
            key = 'null';
        if (!value)
            value = 'null';
        output += key.toString() + " => " + value.toString() + "\n";
    }
    console.log(output); // 输出到 Frida 控制台
    return output; // 返回输出结果
}