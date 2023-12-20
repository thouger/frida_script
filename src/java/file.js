export function hook_file() {
    Java.perform(function () {
        var File = Java.use('java.io.File');
        // Hook File构造函数
        File.$init.overload('java.lang.String').implementation = function (path) {
            console.log('File constructor hooked, path: ' + path);
            try {
                var file_name = this.getName.call(this);
                // 输出文件名
                console.log('File name: ' + file_name);
            }
            catch (e) {
                // console.log(e)
            }
            return this.$init.call(this, path);
        };
        // Hook File构造函数
        File.$init.overload('java.lang.String', 'java.lang.String').implementation = function (dirPath, fileName) {
            console.log('File constructor hooked, dirPath: ' + dirPath + ', fileName: ' + fileName);
            // 输出文件名
            console.log('File name: ' + fileName);
            return this.$init.call(this, dirPath, fileName);
        };
    });
}
