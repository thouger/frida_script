var m = 'libsystem_trace.dylib';
// bool os_log_type_enabled(os_log_t oslog, os_log_type_t type);
var isEnabledFunc = Module.findExportByName(m, 'os_log_type_enabled');
// _os_log_impl(void *dso, os_log_t log, os_log_type_t type, const char *format, uint8_t *buf, unsigned int size);
var logFunc = Module.findExportByName(m, '_os_log_impl');

// Enable all logs
Interceptor.attach(isEnabledFunc, {
  onLeave: function (ret) {
    ret.replace(0x1);
  }
});

Interceptor.attach(logFunc, {
  onEnter: function (a) {
/*
OS_ENUM(os_log_type, uint8_t,
	OS_LOG_TYPE_DEFAULT = 0x00,
	OS_LOG_TYPE_INFO    = 0x01,
	OS_LOG_TYPE_DEBUG   = 0x02,
	OS_LOG_TYPE_ERROR   = 0x10,
	OS_LOG_TYPE_FAULT   = 0x11);
*/
    var type = a[2]; 
    var format = a[3];
    if (type !== 0x2) {
      console.log(JSON.stringify({
        type: type,
        format: format.readCString(),
        //buf: a[4].readPointer().readCString() // TODO
      }, null, 2));
    }
  }
})