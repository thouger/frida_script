function hook_libc(){
    let fgets_ptr = Module.findExportByName("libc.so", "fgets");
    let fgets = new NativeFunction(fgets_ptr, "pointer", ["pointer", "int", "pointer"]);
    let popen_addr = Module.findExportByName("libc.so", "popen");
    console.log(`popen_addr => ${popen_addr}`);
    Interceptor.attach(popen_addr, {
        onEnter: function(args){
            let command = args[0].readUtf8String();
            let mode = args[1].readUtf8String();
            console.log(`[popen] [onEnter] command=${command} mode=${mode}`)
        },
        onLeave: function(fp){
            let output = "";
            let buffer = Memory.alloc(1024);
            while (fgets(buffer, 1024, fp) > 0) {
                output += buffer.readUtf8String();
            }
            console.log(`[popen] [onLeave] fp=${fp} output =>${output}<=`);
        }
    })
}
// hook_libc();
