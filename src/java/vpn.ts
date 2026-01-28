//@ts-nocheck
/**
 * VPN 检测绕过模块
 * 用于绕过应用对 VPN 和代理的检测
 */
export function bypassVpnDetection() {
    Java.perform(function() {
        // Hook NetworkInterface.isUp() to return false for VPN interfaces
        try {
            var NetworkInterface = Java.use("java.net.NetworkInterface");
            NetworkInterface.isUp.implementation = function() {
                var originalResult = this.isUp();
                var interfaceName = this.getName();

                // If this is a VPN interface (tun0 or ppp0), return false
                if (interfaceName && (interfaceName === "tun0" || interfaceName === "ppp0")) {
                    console.log("[+] NetworkInterface.isUp() hooked for " + interfaceName + " - returning false");
                    return false;
                }

                return originalResult;
            };
            console.log("[+] Successfully hooked NetworkInterface.isUp()");
        } catch (e) {
            console.log("[-] Failed to hook NetworkInterface.isUp(): " + e);
        }

        // Hook NetworkInterface.getInterfaceAddresses().size() to return 0 for VPN interfaces
        try {
            var NetworkInterface = Java.use("java.net.NetworkInterface");
            NetworkInterface.getInterfaceAddresses.implementation = function() {
                var originalResult = this.getInterfaceAddresses();
                var interfaceName = this.getName();

                // If this is a VPN interface, return empty list
                if (interfaceName && (interfaceName === "tun0" || interfaceName === "ppp0")) {
                    console.log("[+] NetworkInterface.getInterfaceAddresses() hooked for " + interfaceName + " - returning empty list");
                    var ArrayList = Java.use("java.util.ArrayList");
                    return ArrayList.$new();
                }

                return originalResult;
            };
            console.log("[+] Successfully hooked NetworkInterface.getInterfaceAddresses()");
        } catch (e) {
            console.log("[-] Failed to hook NetworkInterface.getInterfaceAddresses(): " + e);
        }

        // Hook NetworkInterface.getName() to hide VPN interface names
        try {
            var NetworkInterface = Java.use("java.net.NetworkInterface");
            NetworkInterface.getName.implementation = function() {
                var originalName = this.getName();

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
            System.getProperty.overload('java.lang.String').implementation = function(key) {
                var originalValue = this.getProperty(key);

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

            System.getProperty.overload('java.lang.String', 'java.lang.String').implementation = function(key, defaultValue) {
                var originalValue = this.getProperty(key, defaultValue);

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
                if (str && typeof str === 'string') {
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

        // Hook InetAddress.isLoopbackAddress()
        try {
            Java.use("java.net.InetAddress").isLoopbackAddress.implementation = function() {
                var res = this.isLoopbackAddress();
                console.log("InetAddress.isLoopbackAddress() called, result: " + res);
                return res;
            }
            console.log("[+] Successfully hooked InetAddress.isLoopbackAddress()");
        } catch (e) {
            console.log("[-] Failed to hook InetAddress.isLoopbackAddress(): " + e);
        }

        // Hook NetworkInterface.getInetAddresses()
        try {
            Java.use("java.net.NetworkInterface").getInetAddresses.implementation = function() {
                var res = this.getInetAddresses();
                console.log("[+] NetworkInterface.getInetAddresses() called:", res);
                return res;
            }
            console.log("[+] Successfully hooked NetworkInterface.getInetAddresses()");
        } catch (e) {
            console.log("[-] Failed to hook NetworkInterface.getInetAddresses(): " + e);
        }

        // Hook ConnectivityManager.getNetworkCapabilities()
        try {
            Java.use("android.net.ConnectivityManager").getNetworkCapabilities.implementation = function(v) {
                console.log("[+] ConnectivityManager.getNetworkCapabilities() called with:", v);
                var res = this.getNetworkCapabilities(v);
                console.log("[+] Result:", res);
                return null;
            }
            console.log("[+] Successfully hooked ConnectivityManager.getNetworkCapabilities()");
        } catch (e) {
            console.log("[-] Failed to hook ConnectivityManager.getNetworkCapabilities(): " + e);
        }
    });
}
