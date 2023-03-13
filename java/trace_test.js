Java.perform(function () {
    var hook = Java.use('com.appsflyer.internal.AFa1xSDK$AFa1wSDK');
    var methods = hook.class.getDeclaredMethods();    
    for (var i = 0; i < methods.length; i++) {
        console.log(methods[i].getName());
    }
});