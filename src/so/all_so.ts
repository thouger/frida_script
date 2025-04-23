//@ts-nocheck
// import {log} from "../utils/log.js";

export function all_so(system: boolean = false) {
    {
        Process.enumerateModules({
            onMatch: function (module) {

                if (system) {
                    if (!module.path.includes('/data/app'))
                        console.log('Module name: ' + module.name + " - " + "Base Address: " + module.base.toString() + " - " + "path: " + module.path);
                } else {
                    console.log('Module name: ' + module.name + " - " + "Base Address: " + module.base.toString() + " - " + "path: " + module.path);
                }
            },
            onComplete: function () {
            }
        });
    }
}
