var class_loader = 'anet.channel.session.HttpConnector';
var target_method = 'c';
// var className = class_loader.split('.')[class_loader.split('.').length - 1]
// setTimeout(main, 10000)
main();
function main() {
    console.log("start");
    Java.perform(function () {
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    if (loader.findClass(class_loader)) {
                        console.log("Successfully found loader")
                        Java.classFactory.loader = loader;
                        console.log("Switch Classloader Successfully ! ")
                    }
                } catch (e) { }
            },
            onComplete: function () {
            }
        });
        Java.enumerateLoadedClasses({
            onMatch: function (class_name) {
                //输出所有类
                // console.log(className)
                if (class_name.toString().toLowerCase() === class_loader.toLowerCase()) {
                    try {
                        var hook = Java.use(class_loader);
                        var overloads = hook[target_method].overloads;
                        for (var i = 0; i < overloads.length; i++) {
                            overloads[i].implementation = function () {
                                var retval = this[target_method].apply(this, arguments);
                                // var retval = null;

                                //输出函数参数
                                for (var j = 0; j < arguments.length; j++) {
                                    console.log(arguments[j])
                                    // print_hashmap(arguments[1])
                                }
                                console.log(retval);
                                console.log(arguments[0].j().toString())
                                return retval;
                            }

                        }
                    } catch (e) { }
                }
            }, onComplete: function () { }
        })

    })
}

function print_hashmap(hashmap) {
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
  
      if(!key)
      key='null'
      if(!value)
      value='null'
      output += key.toString() + " => " + value.toString() + "\n";
    }
  
    console.log(output); // 输出到 Frida 控制台
    return output; // 返回输出结果
  }

// function antiAntiFrida() {
//     var strstr = Module.findExportByName(null, "strstr");
//     if (null !== strstr) {
//         Interceptor.attach(strstr, {
//             onEnter: function (args) {
//                 this.frida = Boolean(0);

//                 this.haystack = args[0];
//                 this.needle = args[1];

//                 if (this.haystack.readCString() !== null && this.needle.readCString() !== null) {
//                     if (this.haystack.readCString().indexOf("frida") !== -1 ||
//                         this.needle.readCString().indexOf("frida") !== -1 ||
//                         this.haystack.readCString().indexOf("gum-js-loop") !== -1 ||
//                         this.needle.readCString().indexOf("gum-js-loop") !== -1 ||
//                         this.haystack.readCString().indexOf("gmain") !== -1 ||
//                         this.needle.readCString().indexOf("gmain") !== -1 ||
//                         this.haystack.readCString().indexOf("linjector") !== -1 ||
//                         this.needle.readCString().indexOf("linjector") !== -1) {
//                         this.frida = Boolean(1);
//                     }
//                 }
//             },
//             onLeave: function (retval) {
//                 if (this.frida) {
//                     retval.replace(ptr("0x0"));
//                 }

//             }
//         })
//         // console.log("anti anti-frida");
//     }
// }
// setImmediate(antiAntiFrida)

// var isLite = false;
// var ByPassTracerPid = function () {
//     var fgetsPtr = Module.findExportByName("libc.so", "fgets");
//     var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
//     Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
//         var retval = fgets(buffer, size, fp);
//         var bufstr = Memory.readUtf8String(buffer);
//         if (bufstr.indexOf("TracerPid:") > -1) {
//             Memory.writeUtf8String(buffer, "TracerPid:\t0");
//             // console.log("tracerpid replaced: " + Memory.readUtf8String(buffer));
//         }
//         return retval;
//     }, 'pointer', ['pointer', 'int', 'pointer']));
// };
// setImmediate(ByPassTracerPid);