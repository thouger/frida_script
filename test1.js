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

          console.log('RegisterNatives called from:\n' +
          Thread.backtrace(this.context, Backtracer.ACCURATE)
          .map(DebugSymbol.fromAddress).join('\n') + '\n');

        var sendData = '';
        var sendDataPtr = args[1];
        var sendDataLen = args[2].toInt32();
        if (sendDataLen > 0) {
          var buf = Memory.readByteArray(sendDataPtr, sendDataLen);
          sendData = hexdump(buf, {
            offset: 0,
            length: sendDataLen,
            header: true,
            ansi: true
          });
        }

        console.log('[' + ex.name + '] Socket fd: ' + fd + ', Destination: ' + address.ip + ':' + address.port);
        console.log('[SEND] ' + sendData);

        // 修改返回值
        this.sendRetVal = false;
        var retval = this.context.x0;
        if (retval === 0) {
          this.sendRetVal = true;
        }
      },
      onLeave: function (retval) {
        if (this.sendRetVal) {
          console.log('[RETURN] Success');
        } else {
          console.log('[RETURN] Error: ' + retval.toInt32());
        }
      }
    })
  })
