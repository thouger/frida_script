📦
161 /src/index.js.map
68 /src/index.js
11 /src/index.d.ts
43 /src/java/file.d.ts
714 /src/java/file.js.map
522 /src/java/file.js
132 /src/java/trace.d.ts
4163 /src/java/trace.js.map
2752 /src/java/trace.js
139 /src/java/trace_change.d.ts
2693 /src/java/trace_change.js.map
1737 /src/java/trace_change.js
56 /src/so/all_so.d.ts
537 /src/so/all_so.js.map
318 /src/so/all_so.js
138 /src/so/hook_func.d.ts
1157 /src/so/hook_func.js.map
780 /src/so/hook_func.js
44 /src/so/init_array.d.ts
1550 /src/so/init_array.js.map
987 /src/so/init_array.js
137 /src/so/inlinehook.d.ts
1147 /src/so/inlinehook.js.map
766 /src/so/inlinehook.js
11 /src/so/scan.d.ts
117 /src/so/scan.js.map
9 /src/so/scan.js
53 /src/so/so_info.d.ts
568 /src/so/so_info.js.map
258 /src/so/so_info.js
58 /src/so/so_method.d.ts
573 /src/so/so_method.js.map
380 /src/so/so_method.js
73 /src/so/utils.d.ts
568 /src/so/utils.js.map
298 /src/so/utils.js
168 /src/utils/log.d.ts
1074 /src/utils/log.js.map
678 /src/utils/log.js
✄
{"version":3,"file":"index.js","names":["so_method"],"sourceRoot":"C:/data/code/frida_script/src/","sources":["index.ts"],"mappings":"oBAGSA,MAAiB,oBAe1BA,EAAU"}
✄
import{so_method as o}from"./so/so_method.js";o("libnative-lib.so");
✄
export {};

✄
export declare function hook_file(): void;

✄
{"version":3,"file":"file.js","names":["hook_file","Java","perform","File","use","$init","overload","implementation","path","console","log","file_name","this","getName","call","e","dirPath","fileName"],"sourceRoot":"C:/data/code/frida_script/src/java/","sources":["file.ts"],"mappings":"OAGM,SAAUA,YACZC,KAAKC,SAAQ,WACT,IAAIC,EAAOF,KAAKG,IAAI,gBAGpBD,EAAKE,MAAMC,SAAS,oBAAoBC,eAAiB,SAAUC,GAC/DC,QAAQC,IAAI,kCAAoCF,GAEhD,IACI,IAAIG,EAAaC,KAAKC,QAAQC,KAAKF,MAEnCH,QAAQC,IAAI,cAAeC,E,CAC9B,MAAMI,G,CAIP,OAAOH,KAAKP,MAAMS,KAAKF,KAAMJ,EACjC,EAGAL,EAAKE,MAAMC,SAAS,mBAAoB,oBAAoBC,eAAiB,SAAUS,EAASC,GAM5F,OALAR,QAAQC,IAAI,qCAAuCM,EAAU,eAAiBC,GAG9ER,QAAQC,IAAI,cAAgBO,GAErBL,KAAKP,MAAMS,KAAKF,KAAMI,EAASC,EAC1C,CACJ,GACJ"}
✄
export function hook_file(){Java.perform((function(){var o=Java.use("java.io.File");o.$init.overload("java.lang.String").implementation=function(o){console.log("File constructor hooked, path: "+o);try{var i=this.getName.call(this);console.log("File name: "+i)}catch(o){}return this.$init.call(this,o)},o.$init.overload("java.lang.String","java.lang.String").implementation=function(o,i){return console.log("File constructor hooked, dirPath: "+o+", fileName: "+i),console.log("File name: "+i),this.$init.call(this,o,i)}}))}
✄
export declare function _trace(targetClass: any, method: any): void;
export declare function trace(target: any, method: any): void;

✄
{"version":3,"file":"trace.js","names":["log","print_hashmap","stacktrace","hasOwnProperty","obj","name","e","inspectObject","input","object","isInstance","obj_class","undefined","$handle","$h","class","Class","Java","use","cast","getClass","concat","toString","fields","getDeclaredFields","i","Boolean","indexOf","className","trim","split","fieldName","pop","fieldType","slice","fieldValue","value","JSON","stringify","traceMethod","targetMethod","unparseMethod","delim","lastIndexOf","targetClass","hook","length","overloadCount","overloads","implementation","output","p","this","j","arguments","stacktraceLog","retval","apply","_trace","method","methods","getDeclaredMethods","$dispose","methodsDict","forEach","_method","parsedMethod","replace","match","toLowerCase","constructors","getDeclaredConstructors","constructor","trace","target","perform","error","enumerateClassLoaders","onMatch","loader","findClass","classFactory","onComplete","targetClasses","Array","enumerateLoadedClasses","clazz","push","String"],"sourceRoot":"C:/data/code/frida_script/src/java/","sources":["trace.ts"],"mappings":"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"}
✄
import{log as a,print_hashmap as n,stacktrace as t}from"../utils/log.js";function e(a,n){try{return a.hasOwnProperty(n)||n in a}catch(t){return a.hasOwnProperty(n)}}function r(a,n){var t,r=!1,o=null;if(null===(e(t=a,"$handle")&&null!=t.$handle?t.$handle:e(t,"$h")&&null!=t.$h?t.$h:null))o=a.class;else{var c=Java.use("java.lang.Class");o=Java.cast(a.getClass(),c),r=!0}n=(n=n.concat("Inspecting Fields: => ",r," => ",o.toString())).concat("\n");var s=o.getDeclaredFields();for(var l in s)if(r||Boolean(s[l].toString().indexOf("static ")>=0)){var i=o.toString().trim().split(" ")[1],u=s[l].toString().split(i.concat(".")).pop(),f=s[l].toString().split(" ").slice(-2)[0],v=void 0;void 0!==a[u]&&(v=a[u].value),n=(n=n.concat(f+" \t"+u+" => ",v+" => ",JSON.stringify(v))).concat("\n")}return n}function o(e,o){var c=e.lastIndexOf("."),s=e.slice(0,c),l=(e=e.slice(c+1,e.length),Java.use(s));if(l[e])for(var i=l[e].overloads.length,u=0;u<i;u++)l[e].overloads[u].implementation=function(){for(var c="",s=0;s<100;s++)c=c.concat("==");c=(c=(c=(c=r(this,c=c.concat("\n"))).concat("*********entered "+o+"********* \n")).concat("\n----------------------------------------\n")).concat("----------------------------------------\n");for(var l=0;l<arguments.length;l++)c=(c=c.concat("arg["+l+"]: "+arguments[l]+" => "+JSON.stringify(arguments[l]))).concat("\n");var i=t();c=c.concat(i);var u=this[e].apply(this,arguments);c=(c=c.concat("\n retval: "+u+" => "+JSON.stringify(u))).concat("\n ********* exiting "+e+"*********\n");for(s=0;s<100;s++)c=c.concat("==");return n(u),a(c),u};else a("Class not found: "+s)}export function _trace(n,t){var e="Tracing Class: "+n+"\n",r=Java.use(n),c=r.class.getDeclaredMethods();r.$dispose();var s={};e+="\t\nSpec: => \n",c.forEach((a=>{a=a.toString(),e+=a+"\n";var r=a.replace(n+".","TOKEN").match(/\sTOKEN(.*)\(/)[1];t&&t.toLowerCase()!==r.toLowerCase()||(s[r]=a)}));var l=r.class.getDeclaredConstructors();for(var i in l.length>0&&(l.forEach((function(a){e+="Tracing "+a.toString()+"\n"})),s.$init="$init"),a(e),s){var u=s[i];o(n+"."+i,u)}}export function trace(n,t){Java.perform((function(){try{Java.use(n)}catch(a){}Java.enumerateClassLoaders({onMatch:function(t){try{a(t),t.findClass(n)&&(a("Successfully found loader"),a(t),Java.classFactory.loader=t,a("Switch Classloader Successfully ! "))}catch(a){}},onComplete:function(){a("EnumerateClassloader END")}}),a("Begin enumerateClasses ...");var e=new Array;Java.enumerateLoadedClasses({onMatch:function(r){r.toLowerCase()==n.toLowerCase()&&(e.push(r),a("find target class: "+r),_trace(r,t))},onComplete:function(){a("Search Class Completed!")}});var r="On Total Tracing :"+String(e.length)+" classes :\r\n";e.forEach((function(a){r=(r=r.concat(a)).concat("\r\n")})),a(r)}))}
✄
export declare function _trace(targetClass: any, method: any): void;
export declare function trace_change(target: any, method: any): void;

✄
{"version":3,"file":"trace_change.js","names":["log","stacktrace","traceMethod","targetMethod","unparseMethod","delim","lastIndexOf","targetClass","slice","hook","length","Java","use","overloadCount","overloads","i","implementation","output","j","arguments","concat","JSON","stringify","retval","this","apply","stacktraceLog","indexOf","File","path","getPath","replacedPath","file","$new","_trace","method","methods","class","getDeclaredMethods","$dispose","methodsDict","forEach","_method","parsedMethod","toString","replace","match","toLowerCase","constructors","getDeclaredConstructors","trace_change","target","perform","error","enumerateClassLoaders","onMatch","loader","findClass","classFactory","onComplete","targetClasses","Array","enumerateLoadedClasses","clazz","push"],"sourceRoot":"C:/data/code/frida_script/src/java/","sources":["trace_change.ts"],"mappings":"cAESA,gBAAoBC,MAAkB,kBAY/C,SAASC,EAAYC,EAAcC,GAE/B,IAAIC,EAAQF,EAAaG,YAAY,KACjCC,EAAcJ,EAAaK,MAAM,EAAGH,GAEpCI,GADAN,EAAeA,EAAaK,MAAMH,EAAQ,EAAGF,EAAaO,QACnDC,KAAKC,IAAIL,IACpB,GAAKE,EAAKN,GAMV,IAFA,IAAIU,EAAgBJ,EAAKN,GAAcW,UAAUJ,OAExCK,EAAI,EAAGA,EAAIF,EAAeE,IAC/BN,EAAKN,GAAcW,UAAUC,GAAGC,eAAiB,WAG7C,IAFA,IAAIC,EAAS,GAEJC,EAAI,EAAGA,EAAIC,UAAUT,OAAQQ,IAElCD,GADAA,EAASA,EAAOG,OAAO,OAASF,EAAI,MAAQC,UAAUD,GAAK,OAASG,KAAKC,UAAUH,UAAUD,MAC7EE,OAAO,MAG3B,IAAIG,EAASC,KAAKrB,GAAcsB,MAAMD,KAAML,WAK5CF,GAHAA,EAASA,EAAOG,OAAO,cAAgBG,EAAS,OAASF,KAAKC,UAAUC,KAGxDH,OAAO,oBAAsBhB,EAAgB,gBAC7DJ,EAAI,oBAAsBI,EAAgB,gBAE1Ca,EAASA,EAAOG,OAAO,gDACvB,IAAIM,EAAgBzB,IACpB,GAAoB,cAAhBE,IAAgF,GAAhDuB,EAAcC,QAAQ,sBAA6B,CACnF,IAAIC,EAAOjB,KAAKC,IAAI,gBAChBiB,EAAON,EAAOO,UAClB,IAA6B,GAA1BD,EAAKF,QAAQ,SAAe,CAC3B,IAAII,EAAeF,EAAO,sCAC1BZ,EAASA,EAAOG,OAAO,sBAAuBW,EAAc,MAC5D,IAAIC,EAAOJ,EAAKK,KAAKF,GAErB,OADA/B,EAAIiB,GACGe,C,EA8Bf,OAHAf,GAHAA,EAASA,EAAOG,OAAO,+CAGPA,OAAO,wBAA0BjB,EAAe,eAEhEH,EAAIiB,GACGM,CACX,OA/DAvB,EAAI,oBAAsBO,EAiElC,QAEM,SAAU2B,OAAO3B,EAAa4B,GAChC,IACI1B,EAAOE,KAAKC,IAAIL,GAChB6B,EAAU3B,EAAK4B,MAAMC,qBACzB7B,EAAK8B,WACL,IAAIC,EAAc,GAElBJ,EAAQK,SAAQC,IAGZ,IAAIC,GAFJD,EAAUA,EAAQE,YAESC,QAAQtC,EAAc,IAAK,SAASuC,MAAM,iBAAiB,GAClFX,GAAUA,EAAOY,gBAAkBJ,EAAaI,gBAEpDP,EAAYG,GAAgBD,EAAO,IAGvC,IAEIM,EAAevC,EAAK4B,MAAMY,0BAO9B,IAAK,IAAIN,KANLK,EAAatC,OAMQ8B,EAAa,CAClC,IAAIpC,EAAgBoC,EAAYG,GAChCzC,EAAYK,EAAc,IAAMoC,EAAcvC,E,CAEtD,QAEM,SAAU8C,aAAaC,EAAQhB,GACjCxB,KAAKyC,SAAQ,WAET,IACIzC,KAAKC,IAAIuC,E,CACX,MAAOE,G,CAMT1C,KAAK2C,sBAAsB,CACvBC,QAAS,SAAUC,GACf,IACQA,EAAOC,UAAUN,KACjBxC,KAAK+C,aAAaF,OAASA,E,CAEjC,MAAOH,G,CAGb,EACAM,WAAY,WACZ,IAGJ,IAAIC,EAAgB,IAAIC,MACxBlD,KAAKmD,uBAAuB,CACxBP,QAAS,SAAUQ,GACXA,EAAMhB,cAAcpB,QAAQwB,EAAOJ,gBAAkB,IAErDa,EAAcI,KAAKD,GACnB7B,OAAO6B,EAAO5B,GAEtB,EACAwB,WAAY,WACZ,GAER,GACJ"}
✄
import{log as a,stacktrace as e}from"../utils/log.js";function t(t,n){var r=t.lastIndexOf("."),o=t.slice(0,r),c=(t=t.slice(r+1,t.length),Java.use(o));if(c[t])for(var s=c[t].overloads.length,i=0;i<s;i++)c[t].overloads[i].implementation=function(){for(var r="",o=0;o<arguments.length;o++)r=(r=r.concat("arg["+o+"]: "+arguments[o]+" => "+JSON.stringify(arguments[o]))).concat("\n");var c=this[t].apply(this,arguments);r=(r=r.concat("\n retval: "+c+" => "+JSON.stringify(c))).concat("*********entered "+n+"********* \n"),a("*********entered "+n+"********* \n"),r=r.concat("\n----------------------------------------\n");var s=e();if("getDataDir"==t&&-1!=s.indexOf("com.lazada.android")){var i=Java.use("java.io.File"),l=c.getPath();if(-1==l.indexOf("ratel")){var v=l+"/app_ratel_env_mock/default_0/data/";r=r.concat("replace path is => ",v,"\n");var f=i.$new(v);return a(r),f}}return r=(r=r.concat("----------------------------------------\n")).concat("\n ********* exiting "+t+"*********\n"),a(r),c};else a("Class not found: "+o)}export function _trace(a,e){var n=Java.use(a),r=n.class.getDeclaredMethods();n.$dispose();var o={};r.forEach((t=>{var n=(t=t.toString()).replace(a+".","TOKEN").match(/\sTOKEN(.*)\(/)[1];e&&e.toLowerCase()!==n.toLowerCase()||(o[n]=t)}));var c=n.class.getDeclaredConstructors();for(var s in c.length,o){var i=o[s];t(a+"."+s,i)}}export function trace_change(a,e){Java.perform((function(){try{Java.use(a)}catch(a){}Java.enumerateClassLoaders({onMatch:function(e){try{e.findClass(a)&&(Java.classFactory.loader=e)}catch(a){}},onComplete:function(){}});var t=new Array;Java.enumerateLoadedClasses({onMatch:function(n){n.toLowerCase().indexOf(a.toLowerCase())>-1&&(t.push(n),_trace(n,e))},onComplete:function(){}})}))}
✄
export declare function all_so(system?: boolean): void;

✄
{"version":3,"file":"all_so.js","names":["all_so","system","Process","enumerateModules","onMatch","module","console","log","name","base","toString","path","includes","onComplete"],"sourceRoot":"C:/data/code/frida_script/src/so/","sources":["all_so.ts"],"mappings":"OAGM,SAAUA,OAAOC,GAAkB,GAEjCC,QAAQC,iBAAiB,CACrBC,QAAS,SAAUC,GAEXJ,EAEAK,QAAQC,IAAI,gBAAkBF,EAAOG,KAAzB,oBAA2DH,EAAOI,KAAKC,WAAvE,YAAuGL,EAAOM,MAErHN,EAAOM,KAAKC,SAAS,YAC1BN,QAAQC,IAAI,gBAAkBF,EAAOG,KAAzB,oBAA2DH,EAAOI,KAAKC,WAAvE,YAAuGL,EAAOM,KAElI,EACAE,WAAY,WACZ,GAGZ"}
✄
export function all_so(e=!1){Process.enumerateModules({onMatch:function(o){e?console.log("Module name: "+o.name+" - Base Address: "+o.base.toString()+" - path: "+o.path):o.path.includes("/system")||console.log("Module name: "+o.name+" - Base Address: "+o.base.toString()+" - path: "+o.path)},onComplete:function(){}})}
✄
export declare function hook_func(so_name: any, addr: any): void;
export declare function _hook_func(so_name: any, func_name: any): void;

✄
{"version":3,"file":"hook_func.js","names":["hook_func","so_name","addr","android_dlopen_ext","Module","findExportByName","Interceptor","attach","onEnter","args","readCString","indexOf","this","hook","onLeave","retval","_hook_func","func_name","console","log","so_addr","findBaseAddress","func","Java","perform","Thread","backtrace","context","Backtracer","ACCURATE","map","DebugSymbol","fromAddress","join","hexdump"],"sourceRoot":"C:/data/code/frida_script/src/so/","sources":["hook_func.ts"],"mappings":"OACM,SAAUA,UAAUC,EAASC,GAC/B,IAAIC,EAAqBC,OAAOC,iBAAiB,KAAM,sBAC7B,MAAtBF,GACAG,YAAYC,OAAOJ,EAAoB,CACnCK,QAAS,SAAUC,IAEiB,GADnBA,EAAK,GAAGC,cACVC,QAAQV,KACfW,KAAKC,MAAO,EAEpB,EACAC,QAAS,SAAUC,GACXH,KAAKC,MACLG,WAAWf,EAASC,EAC5B,GAGZ,QACM,SAAUc,WAAWf,EAASgB,GAChCC,QAAQC,IAAI,WACZ,IAAIC,EAAUhB,OAAOiB,gBAAgBpB,GACrCiB,QAAQC,IAAI,YAAcC,GAC1B,IAAIE,EAAOlB,OAAOC,iBAAiBJ,EAASgB,GAC5CC,QAAQC,IAAI,yBAA2BG,GAEvCC,KAAKC,SAAQ,WACTlB,YAAYC,OAAOe,EAAM,CACrBd,QAAS,SAAUC,GACfS,QAAQC,IAAI,SAeZD,QAAQC,IAAI,6EAA+EM,OAAOC,UAAUd,KAAKe,QAASC,WAAWC,UAAUC,IAAIC,YAAYC,aAAaC,KAAK,MAAQ,KAC7L,EACAnB,QAAS,SAAUC,GAGf,OAFAG,QAAQC,IAAI,iBAAmBe,QAAQnB,IAEhCA,CACX,GAER,GACJ"}
✄
export function hook_func(o,n){var e=Module.findExportByName(null,"android_dlopen_ext");null!=e&&Interceptor.attach(e,{onEnter:function(n){-1!=n[0].readCString().indexOf(o)&&(this.hook=!0)},onLeave:function(e){this.hook&&_hook_func(o,n)}})}export function _hook_func(o,n){console.log("find so");var e=Module.findBaseAddress(o);console.log("so_addr: "+e);var t=Module.findExportByName(o,n);console.log("[+] Hooking function: "+t),Java.perform((function(){Interceptor.attach(t,{onEnter:function(o){console.log("enter"),console.log("*********************\nCCCryptorCreate called from:\n*********************"+Thread.backtrace(this.context,Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n")+"\n")},onLeave:function(o){return console.log("[+] Returned: "+hexdump(o)),o}})}))}
✄
export declare function init_array(): void;

✄
{"version":3,"file":"init_array.js","names":["init_array","Process","pointerSize","linker","findModuleByName","addr_g_ld_debug_verbosity","addr_async_safe_format_log","symbols","enumerateSymbols","i","length","name","indexOf","address","ptr","writeInt","Interceptor","attach","onEnter","args","this","log_level","tag","readCString","fmt","function_type","so_path","strs","Array","split","so_name","pop","func_offset","sub","Module","findBaseAddress","console","log","onLeave","retval"],"sourceRoot":"C:/data/code/frida_script/src/so/","sources":["init_array.ts"],"mappings":"OACM,SAAUA,aACZ,GAA2B,GAAvBC,QAAQC,YACR,IAAIC,EAASF,QAAQG,iBAAiB,eAElCD,EAASF,QAAQG,iBAAiB,YAG1C,IACIC,EAA4B,KAC5BC,EAA6B,KACjC,GAAIH,EAGA,IADA,IAAII,EAAUJ,EAAOK,mBACZC,EAAI,EAAGA,EAAIF,EAAQG,OAAQD,IAAK,CACrC,IAAIE,EAAOJ,EAAQE,GAAGE,KAClBA,EAAKC,QAAQ,kBAAoB,EACZL,EAAQE,GAAGI,QAG5BF,EAAKC,QAAQ,yBAA0B,GAC3CP,EAA4BE,EAAQE,GAAGI,QAEvCC,IAAIT,GAA2BU,SAAS,IAElCJ,EAAKC,QAAQ,0BAA2B,GAAKD,EAAKC,QAAQ,WAAa,IAE7EN,EAA6BC,EAAQE,GAAGI,Q,CAMjDP,GACCU,YAAYC,OAAOX,EAA2B,CAC1CY,QAAS,SAASC,GAId,GAHAC,KAAKC,UAAaF,EAAK,GACvBC,KAAKE,IAAMR,IAAIK,EAAK,IAAII,cACxBH,KAAKI,IAAMV,IAAIK,EAAK,IAAII,cACrBH,KAAKI,IAAIZ,QAAQ,UAAY,GAAKQ,KAAKI,IAAIZ,QAAQ,QAAU,EAAE,CAC9DQ,KAAKK,cAAgBX,IAAIK,EAAK,IAAII,cAClCH,KAAKM,QAAUZ,IAAIK,EAAK,IAAII,cAC5B,IAAII,EAAO,IAAIC,MACfD,EAAOP,KAAKM,QAAQG,MAAM,KAC1BT,KAAKU,QAAUH,EAAKI,MACpBX,KAAKY,YAAelB,IAAIK,EAAK,IAAIc,IAAIC,OAAOC,gBAAgBf,KAAKU,UAChEM,QAAQC,IAAI,aAAcjB,KAAKK,cAC5B,aAAaL,KAAKU,QAClB,aAAaV,KAAKM,QAClB,iBAAiBN,KAAKY,Y,CAIlC,EACAM,QAAS,SAASC,GAClB,GAKZ"}
✄
export function init_array(){if(4==Process.pointerSize)var t=Process.findModuleByName("linker");else t=Process.findModuleByName("linker64");var e=null,n=null;if(t)for(var s=t.enumerateSymbols(),i=0;i<s.length;i++){var r=s[i].name;r.indexOf("call_function")>=0?s[i].address:r.indexOf("g_ld_debug_verbosity")>=0?(e=s[i].address,ptr(e).writeInt(2)):r.indexOf("async_safe_format_log")>=0&&r.indexOf("va_list")<0&&(n=s[i].address)}n&&Interceptor.attach(n,{onEnter:function(t){if(this.log_level=t[0],this.tag=ptr(t[1]).readCString(),this.fmt=ptr(t[2]).readCString(),this.fmt.indexOf("c-tor")>=0&&this.fmt.indexOf("Done")<0){this.function_type=ptr(t[3]).readCString(),this.so_path=ptr(t[5]).readCString();var e=new Array;e=this.so_path.split("/"),this.so_name=e.pop(),this.func_offset=ptr(t[4]).sub(Module.findBaseAddress(this.so_name)),console.log("func_type:",this.function_type,"\nso_name:",this.so_name,"\nso_path:",this.so_path,"\nfunc_offset:",this.func_offset)}},onLeave:function(t){}})}
✄
export declare function inline_hook(so_name: any, addr: any): void;
export declare function _inline_hook(so_name: any, addr: any): void;

✄
{"version":3,"file":"inlinehook.js","names":["inline_hook","so_name","addr","android_dlopen_ext","Module","findExportByName","Interceptor","attach","onEnter","args","readCString","indexOf","this","hook","onLeave","retval","_inline_hook","console","log","so_addr","findBaseAddress","func","add","Java","perform","Thread","backtrace","context","Backtracer","ACCURATE","map","DebugSymbol","fromAddress","join","hexdump"],"sourceRoot":"C:/data/code/frida_script/src/so/","sources":["inlinehook.ts"],"mappings":"OACM,SAAUA,YAAYC,EAASC,GACjC,IAAIC,EAAqBC,OAAOC,iBAAiB,KAAM,sBAC7B,MAAtBF,GACAG,YAAYC,OAAOJ,EAAoB,CACnCK,QAAS,SAAUC,IAEiB,GADnBA,EAAK,GAAGC,cACVC,QAAQV,KACfW,KAAKC,MAAO,EAEpB,EACAC,QAAS,SAAUC,GACXH,KAAKC,MACLG,aAAaf,EAASC,EAC9B,GAGZ,QACM,SAAUc,aAAaf,EAASC,GAClCe,QAAQC,IAAI,WACZ,IAAIC,EAAUf,OAAOgB,gBAAgBnB,GACrCgB,QAAQC,IAAI,YAAcC,GAC1B,IAAIE,EAAOF,EAAQG,IAAIpB,GACvBe,QAAQC,IAAI,yBAA2BG,GAEvCE,KAAKC,SAAQ,WACTlB,YAAYC,OAAOc,EAAM,CACrBb,QAAS,SAAUC,GACfQ,QAAQC,IAAI,SAeZD,QAAQC,IAAI,6EAA+EO,OAAOC,UAAUd,KAAKe,QAASC,WAAWC,UAAUC,IAAIC,YAAYC,aAAaC,KAAK,MAAQ,KAC7L,EACAnB,QAAS,SAAUC,GAGf,OAFAE,QAAQC,IAAI,iBAAmBgB,QAAQnB,IAEhCA,CACX,GAER,GACJ"}
✄
export function inline_hook(o,n){var e=Module.findExportByName(null,"android_dlopen_ext");null!=e&&Interceptor.attach(e,{onEnter:function(n){-1!=n[0].readCString().indexOf(o)&&(this.hook=!0)},onLeave:function(e){this.hook&&_inline_hook(o,n)}})}export function _inline_hook(o,n){console.log("find so");var e=Module.findBaseAddress(o);console.log("so_addr: "+e);var t=e.add(n);console.log("[+] Hooking function: "+t),Java.perform((function(){Interceptor.attach(t,{onEnter:function(o){console.log("enter"),console.log("*********************\nCCCryptorCreate called from:\n*********************"+Thread.backtrace(this.context,Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n")+"\n")},onLeave:function(o){return console.log("[+] Returned: "+hexdump(o)),o}})}))}
✄
export {};

✄
{"version":3,"file":"scan.js","names":[],"sourceRoot":"C:/data/code/frida_script/src/so/","sources":[],"mappings":""}
✄
export{};
✄
export declare function so_info(so_name: any): void;

✄
{"version":3,"file":"so_info.js","names":["so_info","so_name","imports","Module","enumerateImportsSync","i","length","console","log","name","address","exports","enumerateExportsSync"],"sourceRoot":"C:/data/code/frida_script/src/so/","sources":["so_info.ts"],"mappings":"OAEM,SAAUA,QAAQC,GAGpB,IADA,IAAIC,EAAUC,OAAOC,qBAAqBH,GACjCI,EAAI,EAAGA,EAAIH,EAAQI,OAAQD,IAChCE,QAAQC,IAAI,UAAUN,EAAQG,GAAGI,KAAO,KAAOP,EAAQG,GAAGK,QAAQ,MAItE,IAAIC,EAAUR,OAAOS,qBAAqBX,GAC1C,IAASI,EAAI,EAAGA,EAAIM,EAAQL,OAAQD,IAChCE,QAAQC,IAAI,SAASG,EAAQN,GAAGI,KAAO,KAAOE,EAAQN,GAAGK,QAAQ,KAEzE"}
✄
export function so_info(e){for(var o=Module.enumerateImportsSync(e),n=0;n<o.length;n++)console.log("import:"+o[n].name+": "+o[n].address+"\n");var r=Module.enumerateExportsSync(e);for(n=0;n<r.length;n++)console.log("export"+r[n].name+": "+r[n].address+"\n")}
✄
export declare function so_method(so_name: string): void;

✄
{"version":3,"file":"so_method.js","names":["log","hook_dlopen","so_method","so_name","output","Module","enumerateExports","forEach","element","name","enumerateSymbols","enumerateImports"],"sourceRoot":"C:/data/code/frida_script/src/so/","sources":["so_method.ts"],"mappings":"cAESA,MAAW,wCACZC,MAAkB,oBAGpB,SAAUC,UAAUC,GACtBF,EAAYE,GAAQ,WAChB,IAAIC,EAAS,GACSC,OAAOC,iBAAiBH,GAChCI,SAASC,IACnBJ,GAAU,iBAAiBI,EAAQC,QAAQ,IAGxBJ,OAAOK,iBAAiBP,GAChCI,SAASC,IACpBJ,GAAU,iBAAiBI,EAAQC,QAAQ,IAGzBJ,OAAOM,iBAAiB,oBAChCJ,SAASC,IACnBJ,GAAU,iBAAiBI,EAAQC,QAAQ,IAE/CT,EAAII,EACR,GACJ"}
✄
import{log as o}from"../utils/log.js";import{hook_dlopen as e}from"./utils.js";export function so_method(t){e(t,(function(){var e="";Module.enumerateExports(t).forEach((o=>{e+=`export method:${o.name}\n`}));Module.enumerateSymbols(t).forEach((o=>{e+=`export method:${o.name}\n`}));Module.enumerateImports("libencryptlib.so").forEach((o=>{e+=`export method:${o.name}\n`})),o(e)}))}
✄
export declare function hook_dlopen(so_name: any, hook_func: any): void;

✄
{"version":3,"file":"utils.js","names":["log","hook_dlopen","so_name","hook_func","android_dlopen_ext","Module","findExportByName","Interceptor","attach","onEnter","args","readCString","indexOf","this","hook","onLeave","retval"],"sourceRoot":"C:/data/code/frida_script/src/so/","sources":["utils.ts"],"mappings":"cACSA,MAAW,yBACd,SAAUC,YAAYC,EAAQC,GAChCH,EAAI,eACJ,IAAII,EAAqBC,OAAOC,iBAAiB,KAAM,sBAC7B,MAAtBF,GACAG,YAAYC,OAAOJ,EAAoB,CACnCK,QAAS,SAAUC,IAEiB,GADnBA,EAAK,GAAGC,cACVC,QAAQV,KACfF,EAAI,WACJa,KAAKC,MAAO,EAEpB,EACAC,QAAS,SAAUC,GACXH,KAAKC,MACLX,GACR,GAGZ"}
✄
import{log as o}from"../utils/log.js";export function hook_dlopen(n,t){o("hook_dlopen");var e=Module.findExportByName(null,"android_dlopen_ext");null!=e&&Interceptor.attach(e,{onEnter:function(t){-1!=t[0].readCString().indexOf(n)&&(o("find so"),this.hook=!0)},onLeave:function(o){this.hook&&t()}})}
✄
export declare function log(message: string): void;
export declare function stacktrace(): any;
export declare function print_hashmap(hashmap: any): string | undefined;

✄
{"version":3,"file":"log.js","names":["log","message","colorCode","Math","floor","random","console","stacktrace","Java","use","getStackTraceString","$new","print_hashmap","hashmap","output","HashMapNode","iterator","entrySet","hasNext","entry","cast","next","key","getKey","value","getValue","toString"],"sourceRoot":"C:/data/code/frida_script/src/utils/","sources":["log.ts"],"mappings":"OACM,SAAUA,IAAIC,GAClB,IAAIC,EACJ,OAAQC,KAAKC,MAAsB,EAAhBD,KAAKE,WACtB,KAAK,EACHH,EAAY,QACZ,MACF,KAAK,EACHA,EAAY,QACZ,MACF,KAAK,EACHA,EAAY,QACZ,MACF,KAAK,EACHA,EAAY,QACZ,MACF,KAAK,EACHA,EAAY,QACZ,MACF,KAAK,EACHA,EAAY,QACZ,MACF,QACEA,EAAY,GAGhBI,QAAQN,IAAI,GAAGE,IAAYD,QAC7B,QAGM,SAAUM,aACZ,OAAOC,KAAKC,IAAI,oBAAoBC,oBAAoBF,KAAKC,IAAI,uBAAuBE,OAC5F,QAEM,SAAUC,cAAcC,GAC5B,GAAKA,EAAL,CASA,IAJA,IAAIC,EAAS,GAETC,EAAcP,KAAKC,IAAI,0BACvBO,EAAWH,EAAQI,WAAWD,WAC3BA,EAASE,WAAW,CACzB,IAAIC,EAAQX,KAAKY,KAAKJ,EAASK,OAAQN,GACnCO,EAAMH,EAAMI,SACZC,EAAQL,EAAMM,WAEdH,IACJA,EAAI,QACAE,IACJA,EAAM,QACNV,GAAUQ,EAAII,WAAa,OAASF,EAAME,WAAa,I,CAIzD,OADApB,QAAQN,IAAIc,GACLA,C,CArBLR,QAAQN,IAAI,kBAsBhB"}
✄
export function log(a){let e;switch(Math.floor(6*Math.random())){case 0:e="[31m";break;case 1:e="[32m";break;case 2:e="[33m";break;case 3:e="[35m";break;case 4:e="[36m";break;case 5:e="[37m";break;default:e=""}console.log(`${e}${a}[0m`)}export function stacktrace(){return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new())}export function print_hashmap(a){if(a){for(var e="",t=Java.use("java.util.HashMap$Node"),r=a.entrySet().iterator();r.hasNext();){var o=Java.cast(r.next(),t),n=o.getKey(),l=o.getValue();n||(n="null"),l||(l="null"),e+=n.toString()+" => "+l.toString()+"\n"}return console.log(e),e}console.log("Invalid hashmap")}