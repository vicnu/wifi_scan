import netifaces

interfaces = netifaces.interfaces()
print("Interfaces:", interfaces)
for interface in interfaces:
    print(f"Interface: {interface}")
    if netifaces.AF_INET in netifaces.ifaddresses(interface):
        addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET]
        for addr in addresses:
            print(f"IP: {addr.get('addr')}, Netmask: {addr.get('netmask')}")
