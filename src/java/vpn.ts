//@ts-nocheck
/**
 * VPN 检测绕过模块
 * 用于绕过应用对 VPN 和代理的检测
 */
export function bypassVpnDetection() {
    Java.perform(function() {
        // --- Targeted bypass for this app ---
        // index.android.bundle calls `NativeModules.Toast.isProxy()/isVpn()` and then shows an Alert
        // if they resolve to true. The Android implementation we found is in:
        // - com.remobile.toast.Toast.isProxy(Promise)  -> System.getProperty("http.proxyHost/http.proxyPort")
        // - com.remobile.toast.Toast.isVpn(Promise)    -> isVpnUsed()
        // - com.remobile.toast.Toast.isVpnUsed()       -> NetworkInterface enum, checks tun0/ppp0
        //
        // The safest bypass is to force these methods to always return/resolve false.
        try {
            const ToastModule = Java.use("com.remobile.toast.Toast");
            const BooleanCls = Java.use("java.lang.Boolean");

            if (ToastModule.isVpnUsed) {
                ToastModule.isVpnUsed.implementation = function() {
                    console.log("[+] com.remobile.toast.Toast.isVpnUsed() -> false");
                    return false;
                };
            }

            if (ToastModule.isVpn) {
                ToastModule.isVpn.implementation = function(promise) {
                    console.log("[+] com.remobile.toast.Toast.isVpn(Promise) -> resolve(false)");
                    try {
                        promise.resolve(BooleanCls.valueOf(false));
                    } catch (e) {
                        // If Promise impl differs, fall back to raw JS boolean.
                        promise.resolve(false);
                    }
                };
            }

            if (ToastModule.isProxy) {
                ToastModule.isProxy.implementation = function(promise) {
                    console.log("[+] com.remobile.toast.Toast.isProxy(Promise) -> resolve(false)");
                    try {
                        promise.resolve(BooleanCls.valueOf(false));
                    } catch (e) {
                        promise.resolve(false);
                    }
                };
            }

            console.log("[+] Successfully hooked com.remobile.toast.Toast (VPN/proxy checks)");
        } catch (e) {
            console.log("[-] Failed to hook com.remobile.toast.Toast: " + e);
        }

        // Also bypass UMeng's collection fields (vpn_pxy) to reduce risk telemetry.
        try {
            const Umeng = Java.use("com.umeng.umzid.C6584d");
            if (Umeng.m20769i) {
                Umeng.m20769i.implementation = function(ctx) {
                    console.log("[+] com.umeng.umzid.C6584d.m20769i(Context) -> false");
                    return false;
                };
            }
            if (Umeng.m20770j) {
                Umeng.m20770j.implementation = function(ctx) {
                    console.log("[+] com.umeng.umzid.C6584d.m20770j(Context) -> false");
                    return false;
                };
            }
            console.log("[+] Successfully hooked com.umeng.umzid.C6584d (vpn/proxy flags)");
        } catch (e) {
            console.log("[-] Failed to hook com.umeng.umzid.C6584d: " + e);
        }

        // --- Generic/fallback hooks (fix recursion issues) ---
        // Hook NetworkInterface.isUp() to return false for VPN interfaces
        try {
            var NetworkInterface = Java.use("java.net.NetworkInterface");
            var niGetName = NetworkInterface.getName;
            var niIsUp = NetworkInterface.isUp;
            niIsUp.implementation = function() {
                var interfaceName = null;
                try {
                    interfaceName = niGetName.call(this);
                } catch (_) {}

                // If this is a VPN interface (tun0 or ppp0), return false
                if (interfaceName && (interfaceName === "tun0" || interfaceName === "ppp0")) {
                    console.log("[+] NetworkInterface.isUp() hooked for " + interfaceName + " - returning false");
                    return false;
                }

                return niIsUp.call(this);
            };
            console.log("[+] Successfully hooked NetworkInterface.isUp()");
        } catch (e) {
            console.log("[-] Failed to hook NetworkInterface.isUp(): " + e);
        }

        // Hook NetworkInterface.getInterfaceAddresses().size() to return 0 for VPN interfaces
        try {
            var NetworkInterface = Java.use("java.net.NetworkInterface");
            var niGetName = NetworkInterface.getName;
            var niGetIfAddrs = NetworkInterface.getInterfaceAddresses;
            niGetIfAddrs.implementation = function() {
                var interfaceName = null;
                try {
                    interfaceName = niGetName.call(this);
                } catch (_) {}

                // If this is a VPN interface, return empty list
                if (interfaceName && (interfaceName === "tun0" || interfaceName === "ppp0")) {
                    console.log("[+] NetworkInterface.getInterfaceAddresses() hooked for " + interfaceName + " - returning empty list");
                    var Collections = Java.use("java.util.Collections");
                    return Collections.emptyList();
                }

                return niGetIfAddrs.call(this);
            };
            console.log("[+] Successfully hooked NetworkInterface.getInterfaceAddresses()");
        } catch (e) {
            console.log("[-] Failed to hook NetworkInterface.getInterfaceAddresses(): " + e);
        }

        // Hook NetworkInterface.getName() to hide VPN interface names
        try {
            var NetworkInterface = Java.use("java.net.NetworkInterface");
            var niGetName = NetworkInterface.getName;
            niGetName.implementation = function() {
                var originalName = niGetName.call(this);

                // Replace VPN interface names with normal interface names
                if (originalName && originalName === "tun0") {
                    console.log("[+] NetworkInterface.getName() hooked - hiding tun0, returning rmnet_data0");
                    return "rmnet_data0";
                } else if (originalName && originalName === "ppp0") {
                    console.log("[+] NetworkInterface.getName() hooked - hiding ppp0, returning wlan0");
                    return "wlan0";
                }

                return originalName;
            };
            console.log("[+] Successfully hooked NetworkInterface.getName()");
        } catch (e) {
            console.log("[-] Failed to hook NetworkInterface.getName(): " + e);
        }

        // Hook System.getProperty() to hide proxy settings
        try {
            var System = Java.use("java.lang.System");
            var getProp1 = System.getProperty.overload('java.lang.String');
            var getProp2 = System.getProperty.overload('java.lang.String', 'java.lang.String');
            getProp1.implementation = function(key) {
                var originalValue = getProp1.call(this, key);

                // Hide proxy-related system properties
                if (key && (key === "http.proxyHost" || key === "https.proxyHost")) {
                    console.log("[+] System.getProperty() hooked for " + key + " - returning null");
                    return null;
                } else if (key && (key === "http.proxyPort" || key === "https.proxyPort")) {
                    console.log("[+] System.getProperty() hooked for " + key + " - returning null");
                    return null;
                }

                return originalValue;
            };

            getProp2.implementation = function(key, defaultValue) {
                var originalValue = getProp2.call(this, key, defaultValue);

                // Hide proxy-related system properties
                if (key && (key === "http.proxyHost" || key === "https.proxyHost")) {
                    console.log("[+] System.getProperty() hooked for " + key + " - returning null");
                    return null;
                } else if (key && (key === "http.proxyPort" || key === "https.proxyPort")) {
                    console.log("[+] System.getProperty() hooked for " + key + " - returning null");
                    return null;
                }

                return originalValue;
            };

            console.log("[+] Successfully hooked System.getProperty()");
        } catch (e) {
            console.log("[-] Failed to hook System.getProperty(): " + e);
        }

        // Additionally hook TextUtils.isEmpty() for extra protection
        try {
            var TextUtils = Java.use("android.text.TextUtils");
            var originalIsEmpty = TextUtils.isEmpty;
            TextUtils.isEmpty.implementation = function(str) {
                // For proxy-related checks, always return true (empty)
                if (str) {
                    var strValue = str.toString();
                    if (strValue.indexOf("proxy") !== -1 || strValue.indexOf("127.0.0.1") !== -1) {
                        console.log("[+] TextUtils.isEmpty() hooked for proxy-related string - returning true");
                        return true;
                    }
                }
                return originalIsEmpty.call(this, str);
            };
            console.log("[+] Successfully hooked TextUtils.isEmpty()");
        } catch (e) {
            console.log("[-] Failed to hook TextUtils.isEmpty(): " + e);
        }

        // NOTE: Avoid hooking ConnectivityManager.getNetworkCapabilities()/InetAddress etc.
        // Returning null or logging excessively here can break networking or crash some apps.
    });
}
