# ARP Poisoning Tool

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)  ![Kali](https://img.shields.io/badge/Kali-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white)  ![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)


This Python script implements an ARP poisoning tool for network analysis and security testing purposes. ARP poisoning, also known as ARP spoofing, is a technique used to attack an Ethernet wired or wireless network by falsifying the sender's IP address in ARP packets, making the network believe that the attacker's device is the network gateway.

## Features

- **ARP poisoning:** Spoof ARP packets to redirect traffic intended for one target to the attacker's machine.
- **Packet sniffing:** Capture network packets intended for the victim machine for further analysis.
- **Packet logging:** Save captured packets to a PCAP file for offline analysis using tools like Wireshark.
- **ARP table restoration:** Restore ARP tables to their original state after the attack.

## Dependencies

- [Scapy](https://scapy.net/): A powerful Python-based interactive packet manipulation program.
- [Multiprocessing](https://docs.python.org/3/library/multiprocessing.html): A Python module that supports the spawning of processes using an API similar to the threading module.
- [Subprocess](https://docs.python.org/3/library/subprocess.html): A Python module that allows you to spawn new processes, connect to their input/output/error pipes, and obtain their return codes.

## Screenshots
- **Attacker machine:**<br><br>
![](screenshots\Screenshot_2024-05-03_220237.png)

- **Victim machine:**<br><br>
![](screenshots\Screenshot_2024-05-03.png)

## Usage

1. Make sure you have Python installed on your system.
2. Install the required dependencies using pip:
3. Run the script with Python:

    Replace `[victim_ip]`, `[gateway_ip]`, and `[interface]` with the appropriate values for your network configuration.

## Acknowledgement
**This python script provided by Black Hat Python - 2nd Edition book for self learning**

## Warning

- ARP poisoning attacks should only be performed on networks and devices that you have permission to test.
- Misuse of this tool may lead to legal consequences. Use it responsibly and ethically.


