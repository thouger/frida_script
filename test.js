function main() {
    Java.perform(function () {
        Java.use("java.net.NetworkInterface").getName.implementation = function(){
            var string_class = Java.use("java.lang.String");
            var gname = this.getName();
            if(gname == string_class.$new("tun0")){
                console.log("find ===> ", gname);
                return string_class.$new("rmnet_data0")
            } else{
                console.log("gname ===> ", gname)
            }
            return gname;
        }
        // Java.use("android.net.ConnectivityManager").getNetworkCapabilities.implementation = function(v){
        //     console.log(v)
        //     var res = this.getNetworkCapabilities(v)
        //     console.log("res ==> ", res)
        //     return null;
        // }
        Java.use("android.net.NetworkCapabilities").hasTransport.implementation = function(v){
            console.log(v)
            var res = this.hasTransport(v)
            console.log("res ==> ", res)
            return false;
        }
    })
}
setImmediate(main);