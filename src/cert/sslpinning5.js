function hook_ssl() {
    Java.perform(function () {
        var ClassName = "com.android.org.conscrypt.Platform";
        var Platform = Java.use(ClassName);
        var targetMethod = "checkServerTrusted";
        var len = Platform[targetMethod].overloads.length;
        console.log(targetMethod, len);
        for (var i = 0; i < len; ++i) {
            Platform[targetMethod].overloads[i].implementation = function () {
                console.log("class:", ClassName, "target:", targetMethod, " i:", i, arguments);
            };
        }
        var ClassName = "com.android.org.conscrypt.TrustManagerImpl";
        var Platform = Java.use(ClassName);
        var targetMethod = "checkTrustedRecursive";
        var len = Platform[targetMethod].overloads.length;
        console.log(targetMethod, len);
        var ArrayList = Java.use("java.util.ArrayList")
        var X509Certificate = Java.use("java.security.cert.X509Certificate");
        for (var i = 0; i < len; ++i) {
            Platform[targetMethod].overloads[i].implementation = function () {
                console.log("class:", ClassName, "target:", targetMethod, " i:", i, arguments);
                return ArrayList.$new();
            };
        }
    });
}
hook_ssl();