//@ts-nocheck
import {trace} from "./trace";

export function encryption(){
    //aes
    trace('javax.crypto.Cipher','doFinal')
    trace('javax.crypto.Cipher','getEncoded')

    //base64
    trace('android.util.Base64','encodeToString')

    //md5、sha1、sha256、sha512
    trace('java.security.MessageDigest','digest')
    //hmac
    trace('javax.crypto.Mac','doFinal')
    //rsa
    trace('java.security.interfaces.RSAPublicKey','getEncoded')
    
    // trace('java.io.OutputStream','write')
}


function hook_list(){
    var list = Java.use("java.util.ArrayList");
    list.add.implementation = function(value){
        var ret = this.add(value);
        console.log("add: " + ret);
        return ret;
    }
}
function hook_perform_click(){
    var click = Java.use("android.view.View");
    click.performClick.implementation = function(){
        var ret = this.performClick();
        console.log("performClick: " + ret);
        return ret;
    }
}
function hook_set_text(){
    var text = Java.use("android.widget.TextView");
    text.setText.implementation = function(text){
        var ret = this.setText(text);
        console.log("setText: " + ret);
        return ret;
    }
}
function hook_get_text(){
    var text = Java.use("android.widget.TextView"); 
    text.getText.implementation = function(){
        var ret = this.getText();
        console.log("getText: " + ret);
        return ret;
    }   
}
function hook_get_package_name(){
    var package_name = Java.use("android.content.Context");
    package_name.getPackageName.implementation = function(){
        var ret = this.getPackageName();
        console.log("getPackageName: " + ret);
        return ret;
    }
}
//frida byte to string 
function hook_byte_to_string(){
    var byte = Java.use("[B");
    byte.toString.implementation = function(){
        var ret = this.toString();
        console.log("toString: " + ret);
        return ret;
    }
}
//frida string to byte
function hook_string_to_byte(){
    var string = Java.use("java.lang.String");
    string.getBytes.implementation = function(){
        var ret = this.getBytes();
        console.log("getBytes: " + ret);
        return ret;
    }
}
function hook_response(){
    var response = Java.use("okhttp3.Response");
    response.body.implementation = function(){
        var ret = this.body();
        console.log("body: " + ret);
        return ret;
    }
}
function hook_request_url(){
    var request = Java.use("okhttp3.Request");
    request.url.implementation = function(){
        var ret = this.url();
        console.log("url: " + ret);
        return ret;
    }
}
function hook_url(){
    var url = Java.use("java.net.URL");
    url.toString.implementation = function(){
        var ret = this.toString();
        console.log("toString: " + ret);
        return ret;
    }
}
function hook_url_connection(){
    var url_connection = Java.use("java.net.URLConnection");
    url_connection.getInputStream.implementation = function(){
        var ret = this.getInputStream();
        console.log("getInputStream: " + ret);
        return ret;
    }
}