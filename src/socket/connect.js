"use strict";
//@ts-nocheck
Process
    .getModuleByName({ linux: 'libc.so', darwin: 'libSystem.B.dylib', windows: 'ws2_32.dll' }[Process.platform])
    .enumerateExports().filter(ex => ex.type === 'function' && ['connect', 'recv', 'send', 'read', 'write'].some(prefix => ex.name.indexOf(prefix) === 0))
    .forEach(ex => {
    Interceptor.attach(ex.address, {
        onEnter: function (args) {
            var fd = args[0].toInt32();
            var socktype = Socket.type(fd);
            if (socktype !== 'tcp' && socktype !== 'tcp6')
                return;
            var address = Socket.peerAddress(fd);
            if (address === null)
                return;
            console.log(fd, ex.name, address.ip + ':' + address.port);
        }
    });
});
