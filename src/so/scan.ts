//@ts-nocheck
// var _m = Process.enumerateModules();// enumerate loaded modules and take the first on_m
// for (var module of _m) {

//     var pattern = 'C7 C7 65 47 65 74 44 65  78 44 61 74 61 00 35 30'

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

//     // var results = Memory.scanSync(m.base, m.size, pattern);
//     // console.log("Memory.scanSync() result = \n" + JSON.stringify(results));