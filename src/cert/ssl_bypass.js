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
    const android_dlopen_ext = Module.findGlobalExportByName("android_dlopen_ext");
    if (android_dlopen_ext != null) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function (args) {
                if (args[0].readCString().indexOf(name) !== -1) {
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
 * 绕过 SSL 证书验证
 * @param {string} soName - 要 hook 的 so 库名称，默认为 'libsscronet.so'
 */
export function sslBypass(soName = 'libsscronet.so') {
    console.log(`[SSL Bypass] 开始监听 ${soName} 加载...`);

    onLoad(soName, () => {
        console.log(`[SSL Bypass] ${soName} 已加载`);

        let SSL_CTX_set_custom_verify = Process.getModuleByName(soName).getExportByName('SSL_CTX_set_custom_verify');
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
