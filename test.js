function main() {
    Java.perform(function () {
        var find =false;

        while(!find){
            Java.enumerateClassLoadersSync().forEach(function (loader) {
                try{
                    if(loader.findClass('com.appsflyer.internal.AFa1ySDK')){
                        find=true;
                    }
                }catch(e){}
            });
        }
        console.log(22)
    })
}

// setImmediate(main);
setTimeout(() => {
    main()
}, 2000);