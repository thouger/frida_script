//@ts-nocheck

export function so_info(so_name) {
    // 导入
    var imports = Module.enumerateImportsSync(so_name);
    for (var i = 0; i < imports.length; i++) {
        console.log('import:'+imports[i].name + ": " + imports[i].address+'\n')
    }

    // 导出
    var exports = Module.enumerateExportsSync(so_name);
    for (var i = 0; i < exports.length; i++) {
        console.log('export'+exports[i].name + ": " + exports[i].address+'\n');
    }
}