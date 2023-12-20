import frida
manager = frida.get_device_manager()
device = manager.add_remote_device("192.168.101.15:9999")
print(device)
