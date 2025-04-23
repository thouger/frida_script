//将数组转换成c++的byte[]。并且hexdump打印结果
function print_bytes(bytes) {
    var buf  = Memory.alloc(bytes.length);
    Memory.writeByteArray(buf, byte_to_ArrayBuffer(bytes));
    console.log(hexdump(buf, {offset: 0, length: bytes.length, header: false, ansi: true}));
}
//将java的数组转换成js的数组
function byte_to_ArrayBuffer(bytes) {
    var size=bytes.length;
    var tmparray = [];
    for (var i = 0; i < size; i++) {
        var val = bytes[i];
        if(val < 0){
            val += 256;
        }
        tmparray[i] = val
    }
    return tmparray;
}
// java.net.Socket$init(ip,port) 获取ip和端口
// socketWrite0(FileDescriptor fd, byte[] b, int off,int len) 获取发送的数据
// socketRead0(FileDescriptor fd,byte b[], int off, int len,int timeout) 获取接受的数据
function hook_tcp(){
    var socketClass= Java.use("java.net.Socket");
    socketClass.$init.overload('java.net.InetAddress', 'int').implementation=function(ip,port){
        console.log("socket$init ",ip,":",port);
        return this.$init(ip,port);
    };
    var outputClass=Java.use("java.net.SocketOutputStream");
    outputClass.socketWrite0.implementation=function(fd,buff,off,len){
        console.log("tcp write fd:",fd);
        print_bytes(buff);
        return this.socketWrite0(fd,buff,off,len);
    };
 
    var inputClass=Java.use("java.net.SocketInputStream");
    inputClass.socketRead0.implementation=function(fd,buff,off,len,timeout){
        var res=this.socketRead0(fd,buff,off,len,timeout);
        console.log("tcp read fd:",fd)
        print_bytes(buff);
        return res;
    };
}
//SSL_write(long sslNativePointer, FileDescriptor fd,
//             SSLHandshakeCallbacks shc, byte[] b, int off, int len, int writeTimeoutMillis)
//SSL_read(long sslNativePointer, FileDescriptor fd, SSLHandshakeCallbacks shc,
//             byte[] b, int off, int len, int readTimeoutMillis)
function getSocketData(fd){
    console.log("fd:",fd);
    var socketType=Socket.type(fd)
    if(socketType!=null){
        var res="type:"+socketType+",loadAddress:"+JSON.stringify(Socket.localAddress(fd))+",peerAddress"+JSON.stringify(Socket.peerAddress(fd));
        return res;
    }else{
        return "type:"+socketType;
    }
}
function getSocketData2(stream){
    var data0=stream.this$0.value;
    var sockdata=data0.socket.value;
    return sockdata;
}
function hook_ssl(){
    var NativeCryptoClass= Java.use("com.android.org.conscrypt.NativeCrypto");
    NativeCryptoClass.SSL_write.implementation=function(sslPtr,fd,shc,b,off,len,timeout){
        console.log("enter SSL_write");
        print_bytes(b);
        return this.SSL_write(sslPtr,fd,shc,b,off,len,timeout);
    };
    NativeCryptoClass.SSL_read.implementation=function(sslPtr,fd,shc,b,off,len,timeout){
        console.log("enter SSL_read");
        var res=this.SSL_read(sslPtr,fd,shc,b,off,len,timeout);
        print_bytes(b);
        return res;
    };
}
//SSLOutputStream  write(byte[] buf, int offset, int byteCount)
//SSLInputStream     read(byte[] buf, int offset, int byteCount)
function hook_ssl2(){
    var SSLOutputClass=Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream");
    SSLOutputClass.write.overload('[B', 'int', 'int').implementation=function(buf,off,cnt){
        console.log(getSocketData2(this));
        print_bytes(buf);
        return this.write(buf,off,cnt);
    };
    var SSLInputClass=Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream");
    SSLInputClass.read.overload('[B', 'int', 'int').implementation=function(buf,off,cnt){
        var res=this.read(buf,off,cnt);
        console.log(getSocketData2(this));
        print_bytes(buf);
        return res;
    }
}
//jni的ssl的加密数据hook
function hook_jni_ssl_enc(){
    var writePtr=Module.getExportByName("libc.so","write");
    var readPtr=Module.getExportByName("libc.so","read");
    console.log("write:",writePtr,",read:",readPtr);
    Interceptor.attach(writePtr,{
        onEnter:function(args){
            var fd=args[0];
            var buff=args[1];
            var size=args[2];
            var sockdata=getSocketData(fd.toInt32());
            if(sockdata.indexOf("tcp")){
                console.log(sockdata);
                console.log(hexdump(buff,{length:size.toInt32()}));
            }
        },
        onLeave:function(retval){
 
        }
    });
    Interceptor.attach(readPtr,{
        onEnter:function(args){
            this.fd=args[0];
            this.buff=args[1];
            this.size=args[2];
        },
        onLeave:function(retval){
            var sockdata=getSocketData(this.fd.toInt32());
            if(sockdata.indexOf("tcp")){
                console.log(sockdata);
                console.log(hexdump(this.buff,{length:this.size.toInt32()}));
            }
        }
    });
}
//jni的ssl明文数据hook
function hook_jni_ssl(){
    var sslWritePtr=Module.getExportByName("libssl.so","SSL_write");
    var sslReadPtr=Module.getExportByName("libssl.so","SSL_read");
    console.log("sslWrite:",sslWritePtr,",sslRead:",sslReadPtr);
    var sslGetFdPtr=Module.getExportByName("libssl.so","SSL_get_rfd");
    var sslGetFdFunc=new NativeFunction(sslGetFdPtr,'int',['pointer']);
 
    //int SSL_write(SSL *ssl, const void *buf, int num)
    Interceptor.attach(sslWritePtr,{
        onEnter:function(args){
            var sslPtr=args[0];
            var buff=args[1];
            var size=args[2];
            var fd=sslGetFdFunc(sslPtr);
            var sockdata=getSocketData(fd);
            console.log(sockdata);
            console.log(hexdump(buff,{length:size.toInt32()}));
 
        },
        onLeave:function(retval){
 
        }
    });
    //int SSL_read(SSL *ssl, void *buf, int num)
    Interceptor.attach(sslReadPtr,{
        onEnter:function(args){
            this.sslPtr=args[0];
            this.buff=args[1];
            this.size=args[2];
        },
        onLeave:function(retval){
            var fd=sslGetFdFunc(this.sslPtr);
            var sockdata=getSocketData(fd);
            console.log(sockdata);
            console.log(hexdump(this.buff,{length:this.size.toInt32()}));
        }
    });
}
 
function hook_jni_tcp(){
    var sendtoPtr=Module.getExportByName("libc.so","sendto");
    var recvfromPtr=Module.getExportByName("libc.so","recvfrom");
    console.log("sendto:",sendtoPtr,",recvfrom:",recvfromPtr);
    //sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t addr_len)
    Interceptor.attach(sendtoPtr,{
        onEnter:function(args){
            var fd=args[0];
            var buff=args[1];
            var size=args[2];
            var sockdata=getSocketData(fd.toInt32());
            console.log(sockdata);
            console.log(hexdump(buff,{length:size.toInt32()}));
        },
        onLeave:function(retval){
 
        }
    });
    //recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *addr, socklen_t *addr_len)
    Interceptor.attach(recvfromPtr,{
        onEnter:function(args){
            this.fd=args[0];
            this.buff=args[1];
            this.size=args[2];
        },
        onLeave:function(retval){
            var sockdata=getSocketData(this.fd.toInt32());
            console.log(sockdata);
            console.log(hexdump(this.buff,{length:this.size.toInt32()}));
        }
    });
}
 
function hook_java(){
    Java.perform(function(){
        // hook_tcp();
        // hook_ssl();
        // hook_ssl2();
        // hook_jni_tcp();
        // hook_jni_ssl_enc();
        hook_jni_ssl();
    })
}
function getFullName(name){
    Java.perform(function(){
        Java.enumerateLoadedClassesSync().forEach(function(className){
            if(className.indexOf(name)!=-1){
                console.log(className);
            }
        })
    });
}
 
function main(){
    hook_java();
    // getFullName("SSLOutputStream")
}
 
setImmediate(main);

