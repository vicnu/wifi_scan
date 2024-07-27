import argparse
import subprocess
import netifaces
import sys
import os
import requests
import json
import time

from scapy.all import ARP, Ether, srp

CACHE_FILE = "mac_cache.json"

def activate_virtualenv():
    # Activate the virtual environment if not already activated
    activate_script = os.path.join(os.getcwd(), 'myenv/bin/activate')
    command = f". {activate_script} && exec python3 {' '.join(sys.argv)}"
    subprocess.run(command, shell=True, check=True)
    sys.exit(0)

def get_network_range(interface):
    # Get the network range for the specified interface
    addresses = netifaces.ifaddresses(interface)
    ip_info = addresses[netifaces.AF_INET][0]
    ip = ip_info['addr']
    netmask = ip_info['netmask']
    cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
    return f"{ip}/{cidr}"

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as file:
            return json.load(file)
    return {}

def save_cache(cache):
    with open(CACHE_FILE, 'w') as file:
        json.dump(cache, file)

def get_device_type(mac_address, cache):
    if mac_address in cache:
        return cache[mac_address]

    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            device_type = response.text
        elif response.status_code == 429:
            return "Rate limit exceeded. Try again later."
        else:
            device_type = "Unknown device"
    except Exception as e:
        device_type = f"Error: {str(e)}"
    
    cache[mac_address] = device_type
    save_cache(cache)
    time.sleep(1)  # Delay to avoid hitting the rate limit
    return device_type

def scan_network(network_range, cache):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_range)
    result = srp(packet, timeout=10, verbose=1)[0]
    devices = []
    for sent, received in result:
        device_type = get_device_type(received.hwsrc, cache)
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "device_type": device_type
        })
    return devices

def save_results(devices, filename):
    with open(filename, 'w') as file:
        file.write("IP\t\tDevice\t\tMAC Address\t\n")
        file.write("-" * 70 + "\n")
        for device in devices:
            file.write(f"{device['ip']}\t{device['device_type']}\t{device['mac']}\n")

def main(interface):
    print("Available interfaces:", netifaces.interfaces())
    if not interface:
        print("No interface specified, using default interface.")
        interface = "wlo1"
    
    try:
        target_ip = get_network_range(interface)
    except (ValueError, KeyError):
        print("Error: You must specify a valid interface name.")
        sys.exit(1)

    print("Scanning network range:", target_ip)
    cache = load_cache()
    devices = scan_network(target_ip, cache)
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Device: {device['device_type']}")
    
    save_results(devices, "network_devices.txt")
    print("Results saved to network_devices.txt")

if __name__ == "__main__":
    if not os.getenv('VIRTUAL_ENV'):
        activate_virtualenv()

    parser = argparse.ArgumentParser(description="Scan the local network for devices.")
    parser.add_argument("-i", "--interface", help="Specify the network interface to scan", default="wlo1")
    args = parser.parse_args()

    main(args.interface)
