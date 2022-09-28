Java.perform(function () {
   var linkerHashMap=Java.use('java.util.HashMap');
    linkerHashMap.put.implementation = function(arg1,arg2){
        send("=================linkerHashMap.put====================");
        var data=this.put(arg1,arg2);
        send(arg1+"-----"+arg2);
        send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        return data;
    }   
});