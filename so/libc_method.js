// Hook libc.so
Java.perform(function () {
  var mkdirat_addr = null;

  var symbols = Process.findModuleByName("libc.so").enumerateSymbols();
  for (var i = 0; i < symbols.length; i++) {
    if (symbols[i].name === "mkdirat") {
      mkdirat_addr = symbols[i].address;
      break;
    }
  }

  if (mkdirat_addr) {
    var output = "";

  Interceptor.attach(mkdirat_addr, {
    onEnter: function (args) {
      var dirfd = args[0];
      var pathname = Memory.readUtf8String(args[1]);
      var mode = args[2];
      output = "mkdirat() called with dirfd: " + dirfd + ", pathname: " + pathname + ", mode: " + mode;
      output += "\nStack trace:\n" +
        Thread.backtrace(this.context, Backtracer.ACCURATE)
          .map(DebugSymbol.fromAddress).join('\n');
    },
    onLeave: function (retval) {
      console.log(output+"\nReturn value: "+retval+"\n\n\n");
      // You can add additional code here if needed
    }
  });
} else {
  console.log("Failed to find the address of mkdirat");
}
