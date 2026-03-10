# net_scanner.py
import socket
import subprocess
import re

def tcp_ping(ip, port=80, timeout=1.0):
    """Fallback: แอบเคาะพอร์ต (TCP SYN/Connect) กรณีที่เซิร์ฟเวอร์บล็อก ICMP Ping"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except:
        return False

def ping_host(ip):
    """ตรวจสอบว่าเครื่องเป้าหมายออนไลน์หรือไม่ (รองรับการทะลวง Firewall แบบ Nmap -Pn)"""
    # 1. ลอง ICMP Ping แบบปกติก่อน (เร็วกว่า)
    try:
        output = subprocess.check_output(f"ping -n 1 -w 300 {ip}", shell=True, stderr=subprocess.STDOUT).decode(errors='ignore')
        if "TTL=" in output or "ttl=" in output:
            return True
    except:
        pass
    
    # 2. ถ้า Ping ปกติไม่ติด (อาจโดนบล็อก) ให้ลอง TCP Ping ไปที่พอร์ตยอดฮิต
    if tcp_ping(ip, 80) or tcp_ping(ip, 443) or tcp_ping(ip, 21):
        return True
        
    return False

def get_mac(ip):
    """ดึงค่า MAC Address ของเป้าหมาย (ทำงานได้เฉพาะวงแลนเดียวกันเท่านั้น)"""
    try:
        output = subprocess.check_output(f"arp -a {ip}", shell=True).decode(errors='ignore')
        mac = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
        return mac.group(0).replace("-", ":").upper() if mac else "Unknown"
    except: return "Unknown"

def get_banner(ip, port):
    """ดึงข้อมูลซอฟต์แวร์ที่รันอยู่เบื้องหลังพอร์ตนั้น (Layer 7)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect((ip, port))
        if port in [80, 8080]:
            s.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner if banner else "No Banner"
    except: return "No Banner"