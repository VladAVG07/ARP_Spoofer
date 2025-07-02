# ARP Spoofer & Packet Sniffer

This Python project performs ARP spoofing to intercept traffic between a target server and router. It also includes a packet sniffer that monitors TCP port 80 traffic.

## ⚠️ Legal Disclaimer

This project is intended **only for educational purposes** and **authorized testing** in lab environments. Unauthorized access or man-in-the-middle (MITM) attacks on networks you do not own or have explicit permission to test are **illegal and unethical**.


## 🛠️ Features

- **ARP Spoofing**: Spoofs ARP replies to redirect traffic between the server and router through your machine.
- **Packet Sniffing**: Captures and displays IP and ARP packets (TCP port 80).
- **Network Restoration**: Automatically restores correct ARP tables upon termination.
- **Threaded Execution**: Spoofing, sniffing, and network activity are handled in separate threads.


## 🔧 Requirements

- Python 3.x
- Root privileges (to send raw packets and sniff interfaces)
- Linux (tested on Kali and Ubuntu)


## 📦 Installation

1. **Clone the repo**:

   ```bash
   git clone https://github.com/VladAVG07/ARP_Spoofer.git
   cd arp-spoofer
   ```

2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the script** (as root):

   ```bash
   sudo python3 arp_spoofer.py
   ```


## ⚙️ Configuration

Edit the script and update the following variables as per your network:

```python
server_ip = '192.168.1.133'  # Target device IP
router_ip = '192.168.1.1'    # Default gateway IP
```

Make sure `iface="eth0"` matches your network interface.


## 📌 Notes

- This script performs ARP spoofing and will disrupt the network for target machines.
- You can enable the `force_network_activity` function to keep packets flowing.


## 👨‍💻 Author

[Vlad Apostol](https://github.com/VladAVG07)
