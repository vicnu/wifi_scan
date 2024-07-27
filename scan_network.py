from scapy.all import ARP, Ether, srp
import socket
import netifaces
import sys
import time
import requests

# Function to lookup MAC address manufacturer
def lookup_mac_address(mac):
    try:
        response = requests.get(f'https://api.macvendors.com/{mac}')
        if response.status_code == 200:
            return response.text
        elif response.status_code == 429:  # Too Many Requests
            return "Rate Limited"
        else:
            return "Unknown Device"
    except requests.RequestException:
        return "Unknown Device"

def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def get_network_range(interface='en0'):
    addresses = netifaces.ifaddresses(interface)
    if netifaces.AF_INET in addresses:
        link = addresses[netifaces.AF_INET][0]
        ip = link.get('addr')
        netmask = link.get('netmask')
        if ip and netmask:
            cidr = netmask_to_cidr(netmask)
            if cidr is not None:
                print(f"Using interface: {interface} with IP {ip}/{cidr}")
                return f"{ip}/{cidr}"
    print(f"No valid IPv4 address found on {interface}.")
    return None

def netmask_to_cidr(netmask):
    try:
        return sum([bin(int(x)).count('1') for x in netmask.split('.')])
    except ValueError:
        return None

def scan_network(target_ip):
    print(f"Scanning network range: {target_ip}")

    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    devices = []
    # Perform scan and retry up to 3 times with a longer timeout
    for attempt in range(3):
        print(f"Attempt {attempt + 1}")
        result = srp(packet, timeout=10, verbose=1)[0]  # Increased timeout and verbosity
        
        for sent, received in result:
            if received.psrc not in [d['IP'] for d in devices]:
                print(f"Received response from {received.psrc} ({received.hwsrc})")
                device_info = {
                    "IP": received.psrc,
                    "MAC": received.hwsrc,
                    "Name": get_device_name(received.psrc),
                    "Type": lookup_mac_address(received.hwsrc)  # Added manufacturer lookup
                }
                devices.append(device_info)
        
        time.sleep(5)  # Wait before the next attempt

    return devices

def save_to_file(devices, filename):
    with open(filename, 'w') as file:
        file.write("IP Address\tMAC Address\t\tDevice Name\t\tDevice Type\n")
        file.write("=" * 80 + "\n")
        for device in devices:
            # Handling "Rate Limited" and "Unknown Device"
            device_type = device['Type']
            if "Rate Limited" in device_type:
                device_type = "Unknown Device (Rate Limited)"
            elif "Unknown Device" in device_type:
                device_type = "Unknown Device"
            file.write(f"{device['IP']}\t{device['MAC']}\t{device['Name']}\t{device_type}\n")

if __name__ == "__main__":
    target_ip = get_network_range()
    if target_ip:
        devices = scan_network(target_ip)
        save_to_file(devices, "network_devices.txt")
        print(f"Found {len(devices)} devices. Results saved to network_devices.txt")
    else:
        print("Could not determine the network range.")
        sys.exit(1)
