import frida, sys

f = open('/tmp/log', 'w')    

def on_message(msg, _data):
    f.write(msg['payload']+'\n')

frida_script = """
  Interceptor.attach(Module.findExportByName('/usr/lib/libobjc.A.dylib', 'objc_msgSend'), {
    onEnter: function(args) {
     var m = Memory.readCString(args[1]);
     if (m != 'length' && !m.startsWith('_fastC'))
        send(m);
    }
  });
"""

name = 'Music'
device = frida.get_usb_device()
# pid = device.spawn(["com.apple.Music"]) # or .get_frontmost_application()
# session = device.attach(pid)
session = device.attach(name)
script = session.create_script(frida_script)
script.on('message', on_message)
script.load()
# device.resume(pid)
sys.stdin.read()