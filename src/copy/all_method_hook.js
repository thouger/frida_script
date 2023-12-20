var class_loader = "b21";
var className = class_loader
// var className = class_loader.split('.')[class_loader.split('.').length - 1]
// setTimeout(main, 10000)
function main() {
    console.Blue("start");
    Java.perform(function () {
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    if (loader.findClass(class_loader)) {
                        console.Blue("Successfully found loader")
                        Java.classFactory.loader = loader;
                        console.Blue("Switch Classloader Successfully ! ")


                        console.Blue("Begin Search Class...")
                        var targetClasses = new Array();
                        Java.enumerateLoadedClasses({
                            onMatch: function (class_name) {
                                //输出所有类
                                // console.log(className)
                                if (class_name.toString().toLowerCase().includes(className.toLowerCase())) {
                                    console.Purple("Found Class and hook => " + class_name)
                                    targetClasses.push(class_name);
                                    hook_all_method(class_name)
                                }
                            }, onComplete: function () { }
                        })
                        var output = "On Total Tracing :" + String(targetClasses.length) + " classes :\r\n";
                        targetClasses.forEach(function (target) {
                            output = output.concat(target);
                            output = output.concat("\r\n")
                        })
                        console.Green(output + "Start Tracing ...")
                    }
                } catch (e) { }
            },
            onComplete: function () {
            }
        });
    });
}

function hook_all_method(className) {
    var output = "hook method start:\r\n";
    var hook = Java.use(className);

    //1.利用反射的方式，拿到当前类的所有方法    
    var methods = hook.class.getDeclaredMethods();
    var Targets = methods.map(function (method) {
        output = output.concat(method.toString())
        output = output.concat("\r\n")
        return method.toString().replace(className + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1];
    })

    //2. 构造函数
    var constructors = hook.class.getDeclaredConstructors();
    if (constructors.length > 0) {
        constructors.forEach(function (constructor) {
            output = output.concat("Tracing ", constructor.toString())
            output = output.concat("\r\n")
        })
        Targets = Targets.concat("$init")
    }
    Targets = uniqBy(Targets, JSON.stringify);
    //对数组中所有的方法进行hook，
    Targets.forEach(function (targetMethod) {
        trace_method(hook, className, targetMethod);
    });

    //画个横线
    output.concat('hook method done\r\n');
    output += "========================================================================================================================================================================================================";
    console.Green(output);
}

// trace单个类的所有静态和实例方法包括构造方法 trace a specific Java Method
function trace_method(hook, targetClass, targetMethod) {
    var targetClassMethod = targetClass + "." + targetMethod;
    var overloads = hook[targetMethod].overloads;

    for (var i = 0; i < overloads.length; i++) {
        overloads[i].implementation = function () {
            var retval = this[targetMethod].apply(this, arguments);

            //初始化输出
            var output = "========================================================================================================================================================================================================\r\n";
            //域值
            output = inspectObject(this, output);
            //进入函数
            output = output.concat("\n*** entered " + targetClassMethod);
            output = output.concat("\r\n")
            // if (arguments.length) console.Black();
            //参数
            for (var j = 0; j < arguments.length; j++) {
                output = output.concat("arg[" + j + "]: " + arguments[j] + " => " + JSON.stringify(arguments[j]));
                output = output.concat("\r\n")
            }
            //调用栈
            output = output.concat(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
            //返回值
            output = output.concat("\nretval: " + retval + " => " + JSON.stringify(retval));
            // inspectObject(this)
            //离开函数
            output = output.concat("\n*** exiting " + targetClassMethod);
            //最终输出
            // console.Black(output);
            var r = parseInt((Math.random() * 7).toFixed(0));
            var i = r;
            var printOutput = null;
            switch (i) {
                case 1:
                    printOutput = console.Red;
                    break;
                case 2:
                    printOutput = console.Yellow;
                    break;
                case 3:
                    printOutput = console.Green;
                    break;
                case 4:
                    printOutput = console.Cyan;
                    break;
                case 5:
                    printOutput = console.Blue;
                    break;
                case 6:
                    printOutput = console.Gray;
                    break;
                default:
                    printOutput = console.Purple;
            }
            printOutput(output);
            return retval;
        }
    }
}

function hasOwnProperty(obj, name) {
    try {
        return obj.hasOwnProperty(name) || name in obj;
    } catch (e) {
        return obj.hasOwnProperty(name);
    }
}
function getHandle(object) {
    if (hasOwnProperty(object, '$handle')) {
        if (object.$handle != undefined) {
            return object.$handle;
        }
    }
    if (hasOwnProperty(object, '$h')) {
        if (object.$h != undefined) {
            return object.$h;
        }
    }
    return null;
}

function printHashMap(object, output) {
    var HashMapNode = Java.use('java.util.HashMap$HashMapEntry');
    var iterator = object.entrySet().iterator();
    while (iterator.hasNext()) {
        var entry = Java.cast(iterator.next(), HashMapNode);
        output = output.concat("\nHashMap retval: " + entry.getKey() + " => " + entry.getValue());
        //嵌套map
        //   if (entry.getKey().$className=='java.util.HashMap'){
        //       printHashMap(entry);
        //   }else{
        //   output = output.concat("\nHashMap retval: " + entry.getKey() + " => " + entry.getValue());
        //   }
    }
    return output;
}

function uniqBy(array, key) {
    var seen = {};
    return array.filter(function (item) {
        var k = key(item);
        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
    });
}
//查看域值
function inspectObject(obj, input) {
    var isInstance = false;
    var obj_class = null;
    if (getHandle(obj) === null) {
        obj_class = obj.class;
    } else {
        var Class = Java.use("java.lang.Class");
        obj_class = Java.cast(obj.getClass(), Class);
        isInstance = true;
    }
    input = input.concat("Inspecting Fields: => ", isInstance, " => ", obj_class.toString());
    input = input.concat("\r\n")
    var fields = obj_class.getDeclaredFields();
    for (var i in fields) {
        if (isInstance || Boolean(fields[i].toString().indexOf("static ") >= 0)) {
            // output = output.concat("\t\t static static static " + fields[i].toString());
            var className = obj_class.toString().trim().split(" ")[1];
            // console.Red("className is => ",className);
            var fieldName = fields[i].toString().split(className.concat(".")).pop();
            var fieldType = fields[i].toString().split(" ").slice(-2)[0];
            var fieldValue = undefined;
            if (!(obj[fieldName] === undefined))
                fieldValue = obj[fieldName].value;
            input = input.concat(fieldType + " \t" + fieldName + " => ", fieldValue + " => ", JSON.stringify(fieldValue));
            input = input.concat("\r\n")
        }
    }
    return input;
}

(function () {
    let Color = { RESET: "\x1b[39;49;00m", Black: "0;01", Blue: "4;01", Cyan: "6;01", Gray: "7;11", "Green": "2;01", Purple: "5;01", Red: "1;01", Yellow: "3;01" };
    let LightColor = { RESET: "\x1b[39;49;00m", Black: "0;11", Blue: "4;11", Cyan: "6;11", Gray: "7;01", "Green": "2;11", Purple: "5;11", Red: "1;11", Yellow: "3;11" };
    var colorPrefix = '\x1b[3', colorSuffix = 'm'
    for (let c in Color) {
        if (c == "RESET") continue;
        console[c] = function (message) {
            console.log(colorPrefix + Color[c] + colorSuffix + message + Color.RESET);
        }
        console["Light" + c] = function (message) {
            console.log(colorPrefix + LightColor[c] + colorSuffix + message + Color.RESET);
        }
    }
})();

function antiAntiFrida() {
    var strstr = Module.findExportByName(null, "strstr");
    if (null !== strstr) {
        Interceptor.attach(strstr, {
            onEnter: function (args) {
                this.frida = Boolean(0);

                this.haystack = args[0];
                this.needle = args[1];

                if (this.haystack.readCString() !== null && this.needle.readCString() !== null) {
                    if (this.haystack.readCString().indexOf("frida") !== -1 ||
                        this.needle.readCString().indexOf("frida") !== -1 ||
                        this.haystack.readCString().indexOf("gum-js-loop") !== -1 ||
                        this.needle.readCString().indexOf("gum-js-loop") !== -1 ||
                        this.haystack.readCString().indexOf("gmain") !== -1 ||
                        this.needle.readCString().indexOf("gmain") !== -1 ||
                        this.haystack.readCString().indexOf("linjector") !== -1 ||
                        this.needle.readCString().indexOf("linjector") !== -1) {
                        this.frida = Boolean(1);
                    }
                }
            },
            onLeave: function (retval) {
                if (this.frida) {
                    retval.replace(ptr("0x0"));
                }

            }
        })
        // console.log("anti anti-frida");
    }
}
setImmediate(antiAntiFrida)

var isLite = false;
var ByPassTracerPid = function () {
    var fgetsPtr = Module.findExportByName("libc.so", "fgets");
    var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
    Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
        var retval = fgets(buffer, size, fp);
        var bufstr = Memory.readUtf8String(buffer);
        if (bufstr.indexOf("TracerPid:") > -1) {
            Memory.writeUtf8String(buffer, "TracerPid:\t0");
            // console.log("tracerpid replaced: " + Memory.readUtf8String(buffer));
        }
        return retval;
    }, 'pointer', ['pointer', 'int', 'pointer']));
};
setImmediate(ByPassTracerPid);