// var className = class_loader.split('.')[class_loader.split('.').length - 1]
// setTimeout(main, 10000)
function main() {
	console.Blue("start");
	Java.perform(function () {
		Java.enumerateClassLoaders({
			onMatch: function (loader) {
				try {
					Java.classFactory.loader = loader;
					Java.enumerateLoadedClasses({
						onMatch: function (class_name) {
							//输出所有类
							console.log(class_name)
						}, onComplete: function () { }
					})
				} catch (e) { }
			},
			onComplete: function () {
			}
		});
	})
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