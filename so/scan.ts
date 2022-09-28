//@ts-nocheck
var _m = Process.enumerateModules();// enumerate loaded modules and take the first on_m
for (var m of _m) {

    var pattern = 'c9 0f da a2'

    Memory.scan(/*NativePointer*/ m.base, /*number*/ m.size, /*string*/ pattern, {
        onMatch: function (address, size) {// called when pattern matches
            console.log("Memory.scan() found at " + address + " so address:" + m.base + " so path:" + m.path);
            // return 'stop';// optional, stop scanning early
        },
        onComplete: function () {
        }
    });
}

    // var results = Memory.scanSync(m.base, m.size, pattern);
    // console.log("Memory.scanSync() result = \n" + JSON.stringify(results));