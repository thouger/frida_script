/**
 * SSL Certificate Bypass Module
 * 用于绕过 SSL 证书验证
 */

/**
 * 监听动态库加载
 * @param {string} name - 要监听的库名称
 * @param {Function} callback - 加载完成后的回调
 */
function onLoad(name, callback) {
    const android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    if (android_dlopen_ext != null) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function (args) {
                if (Memory.readCString(args[0]).indexOf(name) !== -1) {
                    this.hook = true;
                }
            },
            onLeave: function (retval) {
                if (this.hook) {
                    callback();
                }
            }
        });
    }
}

/**
 * Hook Cronet Engine 创建
 * 禁用 Cronet Engine 的创建，强制应用回退到其他网络库
 */
export function hookCronetEngine() {
    console.log("[Cronet Hook] 开始 hook CronetClient...");

    Java.perform(function() {
        try {
            var targetClass = 'org.chromium.CronetClient';
            var methodName = 'tryCreateCronetEngine';

            var gclass = Java.use(targetClass);

            // Hook tryCreateCronetEngine 方法
            gclass[methodName].overload(
                'android.content.Context',
                'boolean',
                'boolean',
                'boolean',
                'boolean',
                'java.lang.String',
                'java.util.concurrent.Executor',
                'boolean'
            ).implementation = function(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) {
                console.log("[Cronet Hook] tryCreateCronetEngine 被调用，参数:");
                console.log("  Context: " + arg0);
                console.log("  enableQuic: " + arg1);
                console.log("  enableBrotli: " + arg2);
                console.log("  enableHttp2: " + arg3);
                console.log("  enableCache: " + arg4);
                console.log("  userAgent: " + arg5);
                console.log("  executor: " + arg6);
                console.log("  enablePublicKeyPinning: " + arg7);

                // 不创建 Cronet Engine，直接返回 null
                console.log("[Cronet Hook] 阻止 Cronet Engine 创建，返回 null");
                return null;
            };

            console.log("[Cronet Hook] 成功 hook CronetClient.tryCreateCronetEngine");
        } catch (e) {
            console.log("[Cronet Hook] Hook 失败: " + e);
        }
    });
}

/**
 * 绕过 SSL 证书验证
 * @param {string} soName - 要 hook 的 so 库名称，默认为 'libsscronet.so'
 */
export function dySslBypass(soName = 'libsscronet.so') {
    console.log(`[SSL Bypass] 开始监听 ${soName} 加载...`);

    onLoad(soName, () => {
        console.log(`[SSL Bypass] ${soName} 已加载`);

        let SSL_CTX_set_custom_verify = Module.getExportByName(soName, 'SSL_CTX_set_custom_verify');
        if (SSL_CTX_set_custom_verify != null) {
            console.log("[SSL Bypass] 找到 SSL_CTX_set_custom_verify");
            Interceptor.attach(SSL_CTX_set_custom_verify, {
                onEnter: function (args) {
                    Interceptor.attach(args[2], {
                        onLeave: function (retval) {
                            if (retval > 0x0) {
                                console.log("[SSL Bypass] 修改返回值为 0，绕过证书验证");
                                retval.replace(0x0);
                            }
                        }
                    });
                }
            });
            console.log("[SSL Bypass] SSL 证书验证已成功绕过");
        } else {
            console.log(`[SSL Bypass] 未找到 SSL_CTX_set_custom_verify 函数`);
        }
    });
}
