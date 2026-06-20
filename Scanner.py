#!/usr/bin/python3

import nmap

# Create the scanner object
scanner = nmap.PortScanner()

print("Welcome! This is a simple Nmap automation tool by X5464")
print("<----------------------------------------------------------->")

# Ask for IP address
ip_addr = input("Please enter the IP address here: ")
print("The IP address entered is:", ip_addr)

# Ask for scan type
resp = input("""
Please enter the type of scan you want to run:
    1) SYN ACK Scan
    2) UDP Scan
    3) Comprehensive Scan
Enter option (1/2/3): """)

print("You have selected the option:", resp)

# Option 1 - SYN ACK
if resp == '1':
    print("Nmap Version:", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("IP Status:", scanner[ip_addr].state())
    print("Protocols:", scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['tcp'].keys())

# Option 2 - UDP
elif resp == '2':
    print("Nmap Version:", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("IP Status:", scanner[ip_addr].state())
    print("Protocols:", scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['udp'].keys())

# Option 3 - Comprehensive
elif resp == '3':
    print("Nmap Version:", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status:", scanner[ip_addr].state())
    print("Protocols:", scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['tcp'].keys())

else:
    print("Invalid option. Please select 1, 2, or 3.")
