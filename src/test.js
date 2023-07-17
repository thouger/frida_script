let address = Java.use("java.net.InetAddress")
address["getByName"].implementation = function (a) {
    console.log("params ->" + a);
    if (a === "api.gmtapp.net") {
        console.log("change host");
        return this["getByName"]("192.168.167.113");
    }
}
address["getAllByName"].implementation = function (a) {
    console.log("params ->" + a);
    if (a === "api.gmtapp.net") {
        console.log("change host");
        return this["getAllByName"]("192.168.167.113");
    } else {
        return this["getAllByName"](a);
    }
}