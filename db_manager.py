import socket
import os
from mac_vendor_lookup import MacLookup

class DatabaseManager:
    def __init__(self):
        print("🔄 กำลังเตรียมระบบฐานข้อมูล IEEE OUI Database...")
        
        # สร้างโฟลเดอร์ .cache เพื่อป้องกัน Error สิทธิ์การเข้าถึงไฟล์
        cache_dir = os.path.expanduser("~/.cache")
        os.makedirs(cache_dir, exist_ok=True) 
        
        self.mac_lookup = MacLookup()
        
        try:
            print("⏳ กำลังโหลด/ตรวจสอบฐานข้อมูล MAC Address...")
            self.mac_lookup.update_vendors() 
            print("✅ ฐานข้อมูลพร้อมใช้งานเต็มรูปแบบ!")
        except Exception as e:
            print(f"⚠️ ไม่สามารถเตรียมฐานข้อมูลได้: {e}")

        self.custom_ports = {
            "8000": "HTTP-ALT (Dev Server)",
            "8080": "HTTP-Proxy / Web Cache",
            "8443": "HTTPS-ALT"
        }

    def get_vendor(self, mac_address):
        """ค้นหาชื่อผู้ผลิตจากฐานข้อมูลจริง"""
        if not mac_address or mac_address == "Unknown": 
            return "Unknown"
        try:
            return self.mac_lookup.lookup(mac_address)
        except Exception:
            return "Unknown / Private MAC"

    def get_service(self, port):
        """ค้นหาชื่อบริการจาก Port"""
        port_str = str(port)
        if port_str in self.custom_ports:
            return self.custom_ports[port_str]
        try:
            return socket.getservbyport(port).upper()
        except:
            return "Unknown Service"