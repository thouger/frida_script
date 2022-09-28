// Convert a byte array to a hex string
function bytesToHex(pointer, len) {
    console.log("point: " + pointer + " len: " + len)
    if (len === 0 || pointer.toInt32() === 0) {
        return ""
    }
    pointer = new NativePointer(pointer)
    for (var hex = [], i = 0; i < len; i++) {
        // console.log("+++++++++" + pointer.add(i).readU8())
        var ch = pointer.add(i).readU8()
        hex.push((ch >>> 4).toString(16));
        hex.push((ch & 0xF).toString(16));
    }
    return hex.join("");
}


function HookOpensslEvp() {
    let FBSharedFramework = Module.getBaseAddress("FBSharedFramework")
    console.log(`FBSharedFramework : ${FBSharedFramework}`)
    var EVP_EncryptUpdate = FBSharedFramework.add(0xB3AC8);
    var EVP_EncryptFinal_ex = FBSharedFramework.add(0xB4104);
    var EVP_DecryptUpdate = FBSharedFramework.add(0xB1B54);
    var EVP_DecryptFinal_ex = FBSharedFramework.add(0xB25B0);

    //encode
    Interceptor.attach(EVP_EncryptUpdate, {
        onEnter: function (args) {
            // console.log("on EVP_EncryptUpdate")
            console.log("send: " + bytesToHex(args[3], args[4].toInt32()))
        },
        onLeave: function (ret) {
            // console.log("on EVP_EncryptUpdate exit")
            return 1
        }
    });

    Interceptor.attach(EVP_EncryptFinal_ex, {
        onEnter: function (args) {
            // console.log("on EVP_EncryptFinal_ex")
            console.log("send: " + bytesToHex(args[1], args[2].readInt()))
        },
        onLeave: function (ret) {
            // console.log("on EVP_EncryptFinal_ex exit")
            return 1
        }
    });

    //decode
    Interceptor.attach(EVP_DecryptUpdate, {
        onEnter: function (args) {
            // console.log("on EVP_DecryptUpdate")
            this.a1 = args[1]
            this.a2 = args[2]
        },
        onLeave: function (ret) {
            if (this.a1.toInt32() !== 0) {
                console.log("recv: " + bytesToHex(this.a1, this.a2.readInt()))
            }
            // console.log("on EVP_DecryptUpdate exit")
        }
    });

    Interceptor.attach(EVP_DecryptFinal_ex, {
        onEnter: function (args) {
            // console.log("on EVP_DecryptFinal_ex")
            this.a1 = args[1]
            this.a2 = args[2]
        },
        onLeave: function (ret) {
            console.log("recv: " + bytesToHex(this.a1, this.a2.readInt()))
            // console.log("on EVP_DecryptFinal_ex exit")
        }
    });
}

HookOpensslEvp()