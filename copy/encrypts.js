function main() {
    Java.perform(function () {
        //Base64
        var base64 = Java.use('android.util.Base64');
        var string = Java.use('java.lang.String');
        base64.encode.overload('[B', 'int', 'int', 'int').implementation = function () {
            console.Purple("\r\n=================base64 encode====================");
            printStack()
            console.Yellow(arguments[0]);
            console.Yellow(arguments[1]);
            console.Yellow(arguments[2]);
            console.Yellow(arguments[3]);
            var data = this.encode(arguments[0], arguments[1], arguments[2], arguments[3])
            console.Yellow("base64:" + string.$new(data));
            return data;
        }

        base64.decode.overload('[B', 'int', 'int', 'int').implementation = function () {
            console.Purple("\r\n=================base64 decode====================");
            printStack()
            console.Yellow(arguments[0]);
            console.Yellow(arguments[1]);
            console.Yellow(arguments[2]);
            console.Yellow(arguments[3]);
            var data = this.decode(arguments[0], arguments[1], arguments[2], arguments[3])
            console.Yellow("base64:" + string.$new(data));
            return data;
        }


        // MD SHA 
        var messageDigest = Java.use('java.security.MessageDigest');
        // update
        for (var i = 0; i < messageDigest.update.overloads.length; i++) {
            messageDigest.update.overloads[i].implementation = function () {
                var name = this.getAlgorithm()
                console.Purple("\r\n=================" + name + "====================");
                printStack()
                if (arguments.length == 1) {
                    console.Yellow(arguments[0]);
                    this.update(arguments[0]);
                } else if (arguments.length == 3) {
                    console.Yellow(arguments[0]);
                    console.Yellow(arguments[1]);
                    console.Yellow(arguments[2]);
                    this.update(arguments[0], arguments[1], arguments[2]);
                }
            }
        }
        // digest
        for (var i = 0; i < messageDigest.digest.overloads.length; i++) {
            messageDigest.digest.overloads[i].implementation = function () {
                var name = this.getAlgorithm()
                console.Purple("\r\n=================" + name + "====================");
                printStack()
                if (arguments.length == 0) {
                    var data = this.digest();
                    console.Yellow(data);
                    return data;
                } else if (arguments.length == 1) {
                    console.Yellow(arguments[0]);
                    var data = this.digest(arguments[0]);
                    console.Yellow(data);
                    return data;
                } else if (arguments.length == 3) {
                    console.Yellow(arguments[0]);
                    console.Yellow(arguments[1]);
                    console.Yellow(arguments[2]);
                    var data = this.digest(arguments[0], arguments[1], arguments[2]);
                    console.Yellow(data);
                    return data;
                }
            }
        }

        //MAC
        var mac = Java.use('javax.crypto.Mac');
        for (var i = 0; i < mac.doFinal.overloads.length; i++) {
            mac.doFinal.overloads[i].implementation = function () {
                var name = this.getAlgorithm()
                console.Purple("\r\n=================" + name + "====================");
                printStack()
                if (arguments.length == 0) {
                    var data = this.doFinal();
                    console.Yellow(data);
                    return data;
                } else if (arguments.length == 1) {
                    console.Yellow(arguments[0]);
                    var data = this.doFinal(arguments[0]);
                    console.Yellow(data);
                    return data;
                } else if (arguments.length == 2) {
                    console.Yellow(arguments[0]);
                    console.Yellow(arguments[1]);
                    var data = this.doFinal(arguments[0], arguments[1]);
                    console.Yellow(data);
                    return data;
                }
            }
        }

        // DES DESede AES PBE RSA
        var cipher = Java.use('javax.crypto.Cipher');
        for (var i = 0; i < cipher.doFinal.overloads.length; i++) {
            cipher.doFinal.overloads[i].implementation = function () {
                var name = this.getAlgorithm()
                console.Yellow("=================" + name + "====================");
                printStack()
                if (arguments.length == 0) {
                    var data = this.doFinal();
                    console.Yellow(data);
                    return data;
                } else if (arguments.length == 1) {
                    console.Yellow(arguments[0]);
                    var data = this.doFinal(arguments[0]);
                    console.Yellow(data);
                    return data;
                } else if (arguments.length == 2) {
                    console.Yellow(arguments[0]);
                    console.Yellow(arguments[1]);
                    var data = this.doFinal(arguments[0], arguments[1]);
                    console.Yellow(data);
                    return data;
                } else if (arguments.length == 3) {
                    console.Yellow(arguments[0]);
                    console.Yellow(arguments[1]);
                    console.Yellow(arguments[2]);
                    var data = this.doFinal(arguments[0], arguments[1], arguments[2]);
                    console.Yellow(data);
                    return data;
                } else if (arguments.length == 5) {
                    console.Yellow(arguments[0]);
                    console.Yellow(arguments[1]);
                    console.Yellow(arguments[2]);
                    console.Yellow(arguments[3]);
                    console.Yellow(arguments[4]);
                    var data = this.doFinal(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4]);
                    console.Yellow(data);
                    return data;
                } else {
                    console.Yellow(arguments[0]);
                    console.Yellow(arguments[1]);
                    console.Yellow(arguments[2]);
                    console.Yellow(arguments[3]);
                    var data = this.doFinal(arguments[0], arguments[1], arguments[2], arguments[3]);
                    console.Yellow(data);
                    return data;
                }
            }
        }

        //KEY
        var secretKey = Java.use('javax.crypto.spec.SecretKeySpec');
        for (var i = 0; i < secretKey.$init.overloads.length; i++) {
            secretKey.$init.overloads[i].implementation = function () {
                var name = this.getAlgorithm()
                console.Purple("\r\n=================KEY====================");
                printStack()
                //console.Yellow(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
                if (arguments.length == 2) {
                    console.Yellow(arguments[0]);
                    console.Yellow(arguments[1]);
                    this.$init(arguments[0], arguments[1]);
                } else if (arguments.length == 4) {
                    console.Yellow(arguments[0]);
                    console.Yellow(arguments[1]);
                    console.Yellow(arguments[2]);
                    console.Yellow(arguments[3]);
                    this.$init(arguments[0], arguments[1], arguments[2], arguments[3]);
                }
            }
        }
        //IV
        //DES KEY  
        //DESede KEY
        //PBE KEY salt
    });

}

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
        }
        return retval;
    }, 'pointer', ['pointer', 'int', 'pointer']));
};
setImmediate(ByPassTracerPid);

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

function printStack() {
    Java.perform(function () {
        var Exception = Java.use("java.lang.Exception");
        var ins = Exception.$new("Exception");
        var straces = ins.getStackTrace();
        if (straces != undefined && straces != null) {
            var strace = straces.toString();
            var replaceStr = strace.replace(/,/g, "\r\n");
            console.Green(
                "============================= Stack start ======================="
            );
            console.Blue(replaceStr);
            console.Green(
                "============================= Stack end ======================="
            );
            Exception.$dispose();
        }
    });
}