
// setTimeout(main, 10000)
main();
function main() {
    mtop()
    igw()
}
function mtop() {
    var class_loader1 = "anet.channel.session.HttpConnector";
var target_method1 = 'c'
    Java.perform(function () {
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    if (loader.findClass(class_loader1)) {
                        Java.classFactory.loader = loader;
                    }
                } catch (e) { }
            },
            onComplete: function () {
            }
        });
        Java.enumerateLoadedClasses({
            onMatch: function (class_name) {
                //输出所有类
                // console.log(className)
                if (class_name.toString().toLowerCase() === class_loader1.toLowerCase()) {
                    try {
                        var hook = Java.use(class_loader1);
                        var overloads = hook[target_method1].overloads;
                        for (var i = 0; i < overloads.length; i++) {
                            overloads[i].implementation = function () {
                                var url = arguments[0].j().toString();
                                if(url.indexOf("us-ummt.alibaba.com")>-1){
                                    console.log("mtop:succuess")
                                }else{
                                    var retval = this[target_method1].apply(this, arguments);
                                }
                                return retval;
                            }
                        }
                    } catch (e) { }
                }
            }, onComplete: function () { } 
        })

    })
}

function igw(){
    var class_loader2 = "com.alipay.a.a.a.a.l";
    var target_method2 = 'call'
    Java.perform(function () {
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    if (loader.findClass(class_loader2)) {
                        Java.classFactory.loader = loader;
                    }
                } catch (e) { }
            },
            onComplete: function () {
            }
        });
        Java.enumerateLoadedClasses({
            onMatch: function (class_name) {
                //输出所有类
                // console.log(className)
                if (class_name.toString().toLowerCase() === class_loader2.toLowerCase()) {
                    try {
                        var hook = Java.use(class_loader2);
                        var overloads = hook[target_method2].overloads;
                        for (var i = 0; i < overloads.length; i++) {
                            overloads[i].implementation = function () {
                                console.log("igw:succuess")
                                return null;
                            }

                        }
                    } catch (e) { }
                }
            }, onComplete: function () { }
        })

    })
}