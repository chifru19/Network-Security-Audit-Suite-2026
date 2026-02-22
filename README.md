# Network Security Audit & IDS Suite 2026

## 📌 Project Overview
A custom Python-based security auditing suite developed to provide real-time network visibility and protocol analysis. This tool bridges the gap between basic asset discovery and active intrusion monitoring.

## 🚀 Key Features
* **Automated Asset Discovery:** Maps the local /24 subnet to identify hardware and unauthorized "rogue" assets.
* **Deep Packet Inspection (DPI):** Utilizes the Scapy library to analyze live TCP/IP traffic at the packet level.
* **Real-time IDS Alerts:** Automatically flags unencrypted **Port 80 (HTTP)** traffic, identifying potential Man-in-the-Middle (MITM) vulnerabilities.
* **Security Reporting:** Implemented an automated logging engine that captures high-fidelity timestamps for forensic analysis.

## 🛠️ Technical Implementation
* **Language:** Python 3.x
* **Core Library:** Scapy
* **Evidence:** See `sample_threat_log.txt` for real-time detection examples.

## 🛡️ Ethical Disclosure
This suite is intended for **educational and authorized auditing purposes only**. All development and testing were performed on a private, controlled network with explicit permission.
