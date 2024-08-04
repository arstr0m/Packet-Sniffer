
# Packet Sniffer 🐶🐕‍🦺

This Python application is designed to capture and display network packets using the Scapy library within a graphical user interface (GUI) created with Tkinter. The application allows users to select a network interface, start and stop the packet sniffing process, and view the captured packets in real-time.

Key Features:

Interface Selection: Users can choose from available network interfaces for packet sniffing. The application dynamically updates the available interfaces using the list_interfaces function.

Real-time Packet Capture: The application captures network packets using the Scapy library. It runs the sniffing process in a separate thread to avoid blocking the main GUI thread.

Start and Stop Sniffing: The user can initiate and halt packet capture through the "Start Sniffing" and "Stop Sniffing" buttons. The application updates the button states to reflect the current status of packet capturing.

Display of Captured Packets: Captured packets are displayed in a scrollable text area. The packet details are shown as they are captured, allowing users to monitor network traffic in real-time.
## Badges
<div style="display: flex; flex-wrap: wrap; justify-content: space-around; width: 300px; margin: auto;">
    <img src="https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54" alt="PYTHON">
</div>
