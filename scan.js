// 获取所有模块(so文件)信息
const modules = Process.enumerateModules();

// 根据地址查找所属模块
function findModuleByAddress(addr) {
    for(let mod of modules) {
        if(addr >= mod.base && addr < mod.base.add(mod.size)) {
            return mod;
        }
    }
    return null;
}

Process.enumerateRanges('r--').forEach(function(range) {
    Memory.scan(range.base, range.size, "62 35 39 66 65 61 66 36 37 39 63 63 34 34 39 39 63 62 31 31 30 39 32 30 38 61 64 34 61 36 35 61", {
        onMatch: function(address, size){
            const mod = findModuleByAddress(address);
            if(mod) {
                console.log('[+] Pattern found at: ' + address.toString());
                console.log('   Module: ' + mod.name);
                console.log('   Base: ' + mod.base);
                console.log('   Offset: ' + address.sub(mod.base));
            } else {
                console.log('[+] Pattern found at: ' + address.toString() + ' (Not in any module)');
            }
        },
        onError: function(reason){
            console.log('[!] Error scanning memory: ' + reason);
        },
        onComplete: function(){
            console.log('[*] Memory scan completed');
        }
    });
});


// var _m = Process.enumerateModules();// enumerate loaded modules and take the first on_m
// for (var module of _m) {

//     var pattern = '62 35 39 66 65 61 66 36 37 39 63 63 34 34 39 39 63 62 31 31 30 39 32 30 38 61 64 34 61 36 35 61'

//     Memory.scan(/*NativePointer*/ module.base, /*number*/ module.size, /*string*/ pattern, {
//         onMatch: function (address, size) {// called when pattern matches
//             console.log("Memory.scan() found at " + address +'Module name: ' + module.name + " - " + "Base Address: " + module.base.toString() + " - " + "path: " + module.path);
//         },
//         onError: function(reason){
//             //搜索失败
//             // console.log('搜索失败');
//         },
//         onComplete: function () {
//             // console.log("搜索完毕")
//         }
//     });
// }