Java.perform(function() {
    // 获取 TelephonyManager 类
    var TelephonyManager = Java.use('android.telephony.TelephonyManager');
  
    // Hook getSimOperator 方法
    TelephonyManager.getSimOperator.overload() = function() {
      // 打印调用栈
      console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
  
      // 调用原始的 getSimOperator 方法
      return this.getSimOperator();
    };
  });