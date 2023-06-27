(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
});

const a = require("./java/trace_change");

(0, a.trace_change)("com.lazada.android.cpx.task.a", "c"), (0, a.trace_change)("com.lazada.android.cpx.o", "a");

},{"./java/trace_change":2}],2:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.trace_change = exports._trace = void 0;

const a = require("../utils/log");

function e(a) {
  var e = a.lastIndexOf("/"), t = a.indexOf("/", e + 1);
  return -1 !== e && -1 !== t ? a.substring(e + 1, t) : "com.lazada.android";
}

function t(e, t) {
  var n = e.lastIndexOf("."), r = e.slice(0, n), o = (e = e.slice(n + 1, e.length), 
  Java.use(r));
  if (o[e]) for (var c = o[e].overloads.length, s = 0; s < c; s++) o[e].overloads[s].implementation = function() {
    for (var n = "", r = 0; r < arguments.length; r++) n = (n = n.concat("arg[" + r + "]: " + arguments[r] + " => " + JSON.stringify(arguments[r]))).concat("\n");
    var o = this[e].apply(this, arguments);
    n = (n = n.concat("\n retval: " + o + " => " + JSON.stringify(o))).concat("*********entered " + t + "********* \n"), 
    (0, a.log)("*********entered " + t + "********* \n"), n = n.concat("\n----------------------------------------\n");
    var c = (0, a.stacktrace)();
    if ("getDataDir" == e && -1 != c.indexOf("com.lazada.android")) {
      var s = Java.use("java.io.File"), i = o.getPath();
      if (-1 == i.indexOf("ratel")) {
        var l = i + "/app_ratel_env_mock/default_0/data/";
        n = n.concat("replace path is => ", l, "\n");
        var d = s.$new(l);
        return (0, a.log)(n), d;
      }
    }
    return n = (n = n.concat("----------------------------------------\n")).concat("\n ********* exiting " + e + "*********\n"), 
    (0, a.log)(n), o;
  }; else (0, a.log)("Class not found: " + r);
}

function n(a, e) {
  var n = Java.use(a), r = n.class.getDeclaredMethods();
  n.$dispose();
  var o = {};
  r.forEach((t => {
    var n = (t = t.toString()).replace(a + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1];
    e && e.toLowerCase() !== n.toLowerCase() || (o[n] = t);
  }));
  var c = n.class.getDeclaredConstructors();
  for (var s in c.length, o) {
    var i = o[s];
    t(a + "." + s, i);
  }
}

function r(a, e) {
  Java.perform((function() {
    try {
      Java.use(a);
    } catch (a) {}
    Java.enumerateClassLoaders({
      onMatch: function(e) {
        try {
          e.findClass(a) && (Java.classFactory.loader = e);
        } catch (a) {}
      },
      onComplete: function() {}
    });
    var t = new Array;
    Java.enumerateLoadedClasses({
      onMatch: function(r) {
        r.toLowerCase().indexOf(a.toLowerCase()) > -1 && (t.push(r), n(r, e));
      },
      onComplete: function() {}
    });
  }));
}

exports._trace = n, exports.trace_change = r;

},{"../utils/log":3}],3:[function(require,module,exports){
"use strict";

function a(a) {
  let e;
  switch (Math.floor(6 * Math.random())) {
   case 0:
    e = "[31m";
    break;

   case 1:
    e = "[32m";
    break;

   case 2:
    e = "[33m";
    break;

   case 3:
    e = "[35m";
    break;

   case 4:
    e = "[36m";
    break;

   case 5:
    e = "[37m";
    break;

   default:
    e = "";
  }
  console.log(`${e}${a}[0m`);
}

function e() {
  return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
}

function t(a) {
  for (var e = "", t = Java.use("java.util.HashMap$Node"), r = (a = Java.cast(a, Java.use("java.util.HashMap"))).entrySet().iterator(); r.hasNext(); ) {
    var s = Java.cast(r.next(), t);
    e = e.concat(s.getKey() + " => " + s.getValue() + "\r");
  }
  return e;
}

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.print_hashmap = exports.stacktrace = exports.log = void 0, exports.log = a, 
exports.stacktrace = e, exports.print_hashmap = t;

},{}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC50cyIsImphdmEvdHJhY2VfY2hhbmdlLnRzIiwidXRpbHMvbG9nLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7Ozs7O0FDR0EsTUFBQSxJQUFBLFFBQUE7O0NBcUJBLEdBQUEsRUFBQSxjQUFhLGlDQUFnQyxPQUM3QyxHQUFBLEVBQUEsY0FBYSw0QkFBMkI7Ozs7Ozs7OztBQ3ZCeEMsTUFBQSxJQUFBLFFBQUE7O0FBRUEsU0FBUyxFQUFtQjtFQUN4QixJQUFJLElBQWEsRUFBSyxZQUFZLE1BQzlCLElBQVcsRUFBSyxRQUFRLEtBQUssSUFBYTtFQUM5QyxRQUFvQixNQUFoQixNQUFtQyxNQUFkLElBQ2QsRUFBSyxVQUFVLElBQWEsR0FBRyxLQUUvQjtBQUVmOztBQUVBLFNBQVMsRUFBWSxHQUFjO0VBRS9CLElBQUksSUFBUSxFQUFhLFlBQVksTUFDakMsSUFBYyxFQUFhLE1BQU0sR0FBRyxJQUVwQyxLQURBLElBQWUsRUFBYSxNQUFNLElBQVEsR0FBRyxFQUFhO0VBQ25ELEtBQUssSUFBSTtFQUNwQixJQUFLLEVBQUssSUFNVixLQUZBLElBQUksSUFBZ0IsRUFBSyxHQUFjLFVBQVUsUUFFeEMsSUFBSSxHQUFHLElBQUksR0FBZSxLQUMvQixFQUFLLEdBQWMsVUFBVSxHQUFHLGlCQUFpQjtJQUc3QyxLQUZBLElBQUksSUFBUyxJQUVKLElBQUksR0FBRyxJQUFJLFVBQVUsUUFBUSxLQUVsQyxLQURBLElBQVMsRUFBTyxPQUFPLFNBQVMsSUFBSSxRQUFRLFVBQVUsS0FBSyxTQUFTLEtBQUssVUFBVSxVQUFVLE1BQzdFLE9BQU87SUFHM0IsSUFBSSxJQUFTLEtBQUssR0FBYyxNQUFNLE1BQU07SUFLNUMsS0FIQSxJQUFTLEVBQU8sT0FBTyxnQkFBZ0IsSUFBUyxTQUFTLEtBQUssVUFBVSxLQUd4RCxPQUFPLHNCQUFzQixJQUFnQjtLQUM3RCxHQUFBLEVBQUEsS0FB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
