"use strict";
//@ts-nocheck
var LAST_MSG = '';
Java.perform(() => {
    Interceptor.attach(Module.findExportByName('libbinder.so', 'ioctl'), {
        onEnter: function (args) {
            var binder_write_read_ptr = args[2];
            if (args[1] == 0xC0306201) { // BINDER_WRITE_READ
                var binder_write_read = {
                    // 'fd': args[0].toInt32(),
                    'write_size': binder_write_read_ptr.readU64(),
                    'write_consumed': binder_write_read_ptr.add(Process.pointerSize).readU64(),
                    'write_buffer': binder_write_read_ptr.add(Process.pointerSize * 2).readPointer(),
                };
                if (binder_write_read.write_size > 0) {
                    var ptr = binder_write_read.write_buffer.add(binder_write_read.write_consumed + 4);
                    switch (binder_write_read.write_buffer.readU32() & 0xff) {
                        case 0: // BC_TRANSACTION
                        case 1: // BC_REPLY
                            var binder_transaction_data = {
                                'target': {
                                    'handle': ptr.readU32(),
                                    'ptr': ptr.readPointer()
                                },
                                'cookie': ptr.add(8).readPointer(),
                                'code': ptr.add(16).readU32(),
                                'flags': ptr.add(20).readU32(),
                                'sender_pid': ptr.add(24).readS32(),
                                'sender_euid': ptr.add(28).readU32(),
                                'data_size': ptr.add(32).readU64(),
                                'offsets_size': ptr.add(40).readU64(),
                                'data': {
                                    'ptr': {
                                        'buffer': ptr.add(48).readPointer(),
                                        'offsets': ptr.add(56).readPointer()
                                    },
                                    'buf': ptr.add(48).readByteArray(8)
                                }
                            };
                            var _log = hexdump(binder_transaction_data.data.ptr.buffer, { length: binder_transaction_data.data_size, ansi: true });
                            if (LAST_MSG.toString() != _log.toString()) {
                                console.log(JSON.stringify(binder_transaction_data, null, 2));
                                console.log(_log);
                            }
                            break;
                    }
                }
            }
        }
    });
});
