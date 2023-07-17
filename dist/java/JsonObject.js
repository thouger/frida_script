export function main() {
    Java.perform(function () {
        var JSONObject = Java.use('org.json.JSONObject');
        JSONObject.toString.overload().implementation = function () {
            send("=================org.json.JSONObject.toString====================");
            send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
            var data = this.toString();
            send("org.json.JSONObject.toString result:" + data);
            return data;
        };
        for (var i = 0; i < JSONObject.put.overloads.length; i++) {
            JSONObject.put.overloads[i].implementation = function () {
                send("=================org.json.JSONObject.put====================");
                if (arguments.length == 2) {
                    send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
                    send("key:" + arguments[0]);
                    send("value:" + arguments[1]);
                    var retval = this.put(arguments[0], arguments[1]);
                    return retval;
                }
            };
        }
        for (var i = 0; i < JSONObject.$init.overloads.length; i++) {
            JSONObject.$init.overloads[i].implementation = function () {
                send("=================org.json.JSONObject.$init====================");
                send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
                if (arguments.length == 1) { //只有1个string参数
                    send("string:" + arguments[0]);
                }
                else if (arguments.length == 2) { //其他构造函数用到的时候可以继续添加
                }
            };
        }
    });
}
setTimeout(main, 0);
