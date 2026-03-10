# sec_manager.py
import subprocess
import socket
import threading
import json
import os

class SecurityManager:
    def __init__(self, honeypot_alert_callback):
        self.blocked_ips = []
        self.trusted_devices = self.load_trusted()
        self.honeypot_alert_callback = honeypot_alert_callback # ฟังก์ชันส่งแจ้งเตือนกลับไปที่ GUI

    def load_trusted(self):
        if os.path.exists("trusted_devices.json"):
            try:
                with open("trusted_devices.json", "r", encoding="utf-8") as f: return json.load(f)
            except: pass
        return {}

    def save_trusted(self):
        with open("trusted_devices.json", "w", encoding="utf-8") as f: json.dump(self.trusted_devices, f)

    def trust_device(self, mac, name):
        """บันทึกอุปกรณ์ที่เชื่อถือได้"""
        self.trusted_devices[mac] = name
        self.save_trusted()

    def block_ip(self, ip):
        """ยิงคำสั่งบล็อก IP ใน Windows Firewall"""
        try:
            subprocess.run(f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}', shell=True)
            if ip not in self.blocked_ips:
                self.blocked_ips.append(ip)
            return True
        except: return False

    def _handle_honeypot(self, client, addr):
        try:
            client.settimeout(5.0) 
            client.send(b"=== UNATHORIZED ACCESS PROHIBITED ===\r\nLogin: ")
            username = client.recv(1024).decode(errors='ignore').strip()
            client.send(b"Password: ")
            password = client.recv(1024).decode(errors='ignore').strip()
            client.send(b"\r\nACCESS DENIED. IP LOGGED & TRACED.\r\n")
            client.close()
            if username or password:
                # ส่งข้อมูลกลับไปให้ GUI พิมพ์แจ้งเตือน
                self.honeypot_alert_callback(addr[0], username, password)
        except: client.close()

    def start_honeypot(self):
        """เปิดการทำงานของ Honeypot บนพอร์ต 23"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", 23))
        server.listen(5)
        while True:
            client, addr = server.accept()
            threading.Thread(target=self._handle_honeypot, args=(client, addr), daemon=True).start()