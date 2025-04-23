function hook_dlopen(so_name = null, hook_func = null, so_addr = null) {
   console.log('hook_dlopen');
    
    // Flag to track if we already hooked the first non-system SO
    var hookedFirstNonSystemSo = false;
    
    // Function to check if a path belongs to a system library
    function isSystemLibrary(path) {
        return path.startsWith("/system/") || 
               path.startsWith("/apex/") || 
               path.startsWith("/vendor/");
    }
    
    // Function to check if a path is a shared object file
    function isSharedObject(path) {
        return path.endsWith(".so");
    }
    
    // Function to execute when first non-system SO is detected
    function onFirstNonSystemSo() {
        if (!hookedFirstNonSystemSo) {
           console.log('Hooking first non-system SO');
            hookedFirstNonSystemSo = true;
            hookStringFunctions();
        }
    }

    // Hook android_dlopen_ext
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    if (android_dlopen_ext != null) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function (args) {
                var soName = args[0].readCString();
                
                // Check if this is a non-system shared object library
                if (!isSystemLibrary(soName) && isSharedObject(soName) && !hookedFirstNonSystemSo) {
                   console.log('Found first non-system SO in android_dlopen_ext: ' + soName);
                    this.hookNonSystemSo = true;
                }
                
                // Also check for the specific SO name if provided
                if (so_name && soName.indexOf(so_name) != -1) {
                   console.log('Found specific SO in android_dlopen_ext: ' + soName);
                    this.hookSpecificSo = true;
                }
            },
            onLeave: function (retval) {
                // Hook the first non-system SO
                if (this.hookNonSystemSo) {
                    onFirstNonSystemSo();
                }
                
                // Also call the custom hook function if a specific SO was requested
                if (this.hookSpecificSo && hook_func) {
                    hook_func(so_addr);
                }
            }
        });
    }

    // Hook dlopen
    var dlopen = Module.findExportByName(null, "dlopen");
    if (dlopen != null) {
        Interceptor.attach(dlopen, {
            onEnter: function (args) {
                var soName = args[0].readCString();
                
                // Check if this is a non-system shared object library
                if (!isSystemLibrary(soName) && isSharedObject(soName) && !hookedFirstNonSystemSo) {
                   console.log('Found first non-system SO in dlopen: ' + soName);
                    this.hookNonSystemSo = true;
                }
                
                // Also check for the specific SO name if provided
                if (so_name && soName.indexOf(so_name) != -1) {
                   console.log('Found specific SO in dlopen: ' + soName);
                    this.hookSpecificSo = true;
                }
            },
            onLeave: function (retval) {
                // Hook the first non-system SO
                if (this.hookNonSystemSo) {
                    onFirstNonSystemSo();
                }
                
                // Also call the custom hook function if a specific SO was requested
                if (this.hookSpecificSo && hook_func) {
                    hook_func(so_addr);
                }
            }
        });
    }
}



hook_dlopen()