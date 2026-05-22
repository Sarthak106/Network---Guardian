# 🛡️ Network Guardian — Real-Time Threat Detection & Packet Analysis System

Network Guardian is a real-time network traffic monitoring and packet analysis tool built in Python. It captures live packets, analyzes network protocols, detects suspicious activity, logs security alerts, and exports PCAP files for forensic analysis. The system also includes a live dashboard for visualization and monitoring. It simulates SOC-style (Security Operations Center) network monitoring and demonstrates practical cybersecurity, networking, and packet inspection skills.

## 🚀 Features
- 🔴 Real-time packet sniffing (TCP/UDP/ICMP)  
- 🌐 DNS traffic monitoring  
- 📡 HTTP payload inspection  
- 🚨 Suspicious port detection  
- 🕵️ Port scan detection  
- 📝 Automated alert logging system  
- 📁 PCAP file export for forensic analysis  
- 📊 Live Streamlit dashboard  
- 📈 Protocol-based traffic statistics  
- 🔄 Real-time network monitoring  

## 🛠️ Tech Stack
- Python  
- Socket Programming 
- Matplotlib  
- Pandas  
- Colorama  
- TCP/IP Networking  

## 📂 Project Structure
NetworkGuardian/  
├── main.py — Packet sniffer & threat detection engine  
├── dashboard.py — Streamlit monitoring dashboard  
├── logs/  
│   ├── alerts.txt — Security alerts log  
│   └── stats.txt — Protocol statistics  
├── captures/  
│   └── network_traffic.pcap — Captured packets (PCAP file)  
└── README.md  

## ⚙️ Installation
Clone repository:  
git clone https://github.com/Sarthak106/Network-Guardian---Packet-Sniffing-Tool.git
cd network-guardian  

Create virtual environment (optional):  
python -m venv venv  

Activate:  
Windows: venv\Scripts\activate  
Linux/Mac: source venv/bin/activate  

Install dependencies:  
pip install -r requirements.txt  

## 📦 Requirements
scapy  
streamlit  
matplotlib  
pandas  
colorama  

## 🖥️ Npcap Installation (Windows Only)
Install Npcap: https://npcap.com/#download  
Enable: WinPcap API compatibility mode  

## ▶️ How to Run
Start Sniffer:  
python main.py  

Start Dashboard:  
streamlit run dashboard.py  

## 🔍 Packet Filtering Examples
python main.py --filter tcp  
python main.py --filter udp  
python main.py --filter icmp  
python main.py --filter "port 443"  

## 🚨 Threat Detection Capabilities
Network Guardian detects: suspicious port access (21, 22, 23, 4444), port scanning behavior, DNS queries, HTTP payload activity, and unusual network patterns.

## 📊 Dashboard Features
Live security alerts, protocol distribution charts, packet statistics overview, PCAP monitoring, and real-time system status.

## 📁 PCAP Analysis
Captured traffic can be analyzed using Wireshark and tcpdump.

## 📸 Sample Output
[12:04:01] [TCP] 192.168.1.5:443 -> 172.26.89.87:57902  
[DNS] 192.168.1.5 requested: google.com  
[ALERT] Possible Port Scan Detected from 192.168.1.10  

## 📈 Future Enhancements
GeoIP tracking, machine learning anomaly detection, DDoS detection, SQLite logging, SIEM integration, and live packet table UI.

## 🎯 Learning Outcomes
Network packet analysis, TCP/IP protocol understanding, cybersecurity monitoring, threat detection, SOC-style workflows, Python automation, and real-time data processing.

## 👨‍💻 Author
Sarthak Khaiwal  
GitHub: https://github.com/Sarthak106  
LinkedIn: https://linkedin.com/in/sarthakkhaiwal 

## 📜 License
MIT License
