"use strict";
//@ts-nocheck
const Class = Java.use("com.Awesome.App.MainActivity");
function inspectClass(obj) {
    const obj_class = Java.cast(obj.getClass(), Class);
    const fields = obj_class.getDeclaredFields();
    const methods = obj_class.getMethods();
    console.log("Inspect " + obj.getClass().toString());
    console.log("\tFields:");
    for (var i in fields)
        console.log("\t" + fields[i].toString());
    console.log("\tMethods:");
    for (var i in methods)
        console.log("\t" + methods[i].toString());
}
