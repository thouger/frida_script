import sys
import frida
js_file_names = ['TLS']
process_names = [
    'com.mobile.legends',
    'com.mobile.legends:UnityKillsMe'
]
def raise_send(msg):
    print('[Send] ' + msg)
def raise_info(msg):
    print('\033[0;32m[Info] ' + msg + '\033[0m')
def raise_warning(msg):
    print('\033[0;33m[Warning] ' + msg + '\033[0m')
def raise_error(msg):
    print('\033[0;31m[Error] ' + msg + '\033[0m')
def on_message(message, data):
    if message['type'] == 'send':
        raise_send(message['payload'])
    elif message['type'] == 'error':
        raise_error(message['description'])
    else:
        raise_error(message)
if __name__ == '__main__':
    try:
        raise_info('Current frida version: '+str(frida.__version__))
        manager = frida.get_device_manager()
        devices = manager.enumerate_devices()
        for ldevice in devices:
            raise_info('Device discovered: '+str(ldevice))
        # Google Pixel
        device = manager.get_device('971dcf24')
        # Huawei Nexus 6P
        # device = manager.get_device('84B5T15B03006088')
        raise_info('Connect to the target device successfully: '+str(device))
        front_app = device.get_frontmost_application()
        raise_info('Front Application on the device: '+str(front_app))
        if front_app.identifier not in process_names:
            raise_warning('Device front application is different from all the hooked application ( '+front_app.identifier+' != '+str(process_names)+' )')
        for process_name in process_names:
            process = device.attach(process_name)
            script = process.create_script('/home/thouger/Desktop/code/frida_script/_agent.js').read()
            script.on('message', on_message)
            raise_info('Load script name: Hook' + js_file_name + 'Android.js')
            script.load()
        raise_info('Waiting for scripts...')
        sys.stdin.read()
    except frida.InvalidArgumentError as e:
        raise_error('Invalid argument, maybe a JavaScript syntax error or device disconnected. Details: '+repr(e))
    except frida.ProcessNotFoundError as e:
        raise_error('Cannot find the target process, please check your application status. Details: '+repr(e))
    except frida.ServerNotRunningError as e:
        raise_error('Frida server is not running, please check if it is not start or crash. Details: '+repr(e))
    except Exception as e:
        raise_error('Unknown error or exception. Details: ' + repr(e))