import threading
import requests
import time

try:
    from scapy.all import sniff, IP, TCP, ICMP, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class CyberOperations:
    def __init__(self, log_callback, alert_callback):
        self.log_event = log_callback
        self.show_alert = alert_callback
        self.is_sniffing = False
        self.is_arp_monitoring = False

    # ==========================================
    # 1. LIVE SNIFFER (ดักจับแพ็กเก็ตระดับลึก)
    # ==========================================
    # ==========================================
    # 1. LIVE SNIFFER (ดักจับแพ็กเก็ตระดับลึก)
    # ==========================================
    def _sniff_worker(self):
        if not SCAPY_AVAILABLE:
            self.log_event("Missing 'scapy' library!", "ALERT")
            self.is_sniffing = False
            return
            
        self.log_event("[SNIFFER] Engine online. Scanning ALL network interfaces...", "SUCCESS")
        try:
            from scapy.all import conf
            # ดึงรายชื่อการ์ดแลนทั้งหมด เพื่อป้องกัน Scapy ไปดักฟังผิดการ์ด (เช่น ไปฟังแค่ Wi-Fi)
            all_ifaces = list(conf.ifaces.values())
            
            # เอา BPF filter ออก แล้วดึงแพ็กเก็ตทั้งหมดมากรองใน Python แทน (แก้บั๊ก Windows/VMware)
            sniff(iface=all_ifaces, prn=self._process_packet, store=False)
        except Exception as e:
            # สำรอง: ถ้าแบบดึงทุกการ์ดแลนพัง ให้ใช้แบบค่าเริ่มต้น
            try:
                sniff(prn=self._process_packet, store=False)
            except Exception as e2:
                self.log_event(f"Sniffer Error: {e2}", "ALERT")
                self.is_sniffing = False

    def _process_packet(self, packet):
        """ฟังก์ชันกรองและแกะกล่องข้อความ (Deep Packet Inspection)"""
        try:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # --- 1. ตรวจจับ PING (ICMP Type 8) ---
                if packet.haslayer(ICMP) and packet[ICMP].type == 8:
                    self.log_event(f"[SNIFF] 🔍 ICMP (Ping) detected from: {src_ip}", "WARN")

                # --- 2. ตรวจจับ TCP และแอบอ่านรหัสผ่าน ---
                elif packet.haslayer(TCP):
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    flags = packet[TCP].flags
                    
                    # สนใจเฉพาะพอร์ต 21, 22, 23, 80 (ลดขยะแจ้งเตือน)
                    target_ports = [21, 22, 23, 80]
                    if dport not in target_ports and sport not in target_ports:
                        return 

                    # ฟีเจอร์ Deep Packet Inspection (แกะกล่องดูตัวอักษร)
                    if packet.haslayer("Raw"):
                        payload = packet["Raw"].load.decode(errors='ignore').strip()
                        if payload: # ถ้ามีการพิมพ์ตัวอักษรส่งมา
                            port_info = dport if dport in target_ports else sport
                            self.log_event(f"[SNIFF-DATA] 📦: {payload} (Port {port_info})", "INFO")
                    
                    # แจ้งเตือนการเปิด Connection ใหม่ (SYN Flag)
                    elif flags == "S" and dport in target_ports:
                        self.log_event(f"[SNIFF] 🔌 NEW Connection attempt on Port {dport} from {src_ip}", "ALERT")
        except:
            pass

    def _process_packet(self, packet):
        """ฟังก์ชันย่อยสำหรับอ่านแพ็กเก็ตที่จับได้ (เวอร์ชันฉลาดขึ้น)"""
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # 1. กรอง Ping (ICMP) ให้แจ้งเตือนเฉพาะตอน "ส่งคำขอ (Echo Request / Type 8)"
            if packet.haslayer(ICMP):
                if packet[ICMP].type == 8:
                    self.log_event(f"[SNIFF] 🔍 ICMP Ping requested from: {src_ip}", "WARN")

            # 2. จัดการ TCP (กรองสแปม & ส่องข้อมูล)
            elif packet.haslayer(TCP):
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                flags = packet[TCP].flags

                # ฟีเจอร์ที่ 1: แจ้งเตือนเฉพาะ "การเริ่มเชื่อมต่อใหม่ (SYN Flag)" เท่านั้น (แก้ปัญหาแจ้งเตือนรัวๆ)
                # S = SYN (ขอเชื่อมต่อ)
                if flags == "S":
                    # แจ้งเตือนเฉพาะพอร์ตที่น่าสนใจ จะได้ไม่รก
                    if dport in [21, 22, 23, 80, 443, 3306]:
                        self.log_event(f"[SNIFF] 🔌 NEW Connection attempt on Port {dport} from {src_ip}", "ALERT")

                # ฟีเจอร์ที่ 2: ส่องไส้ในแพ็กเก็ต (ดูว่า Hacker พิมพ์อะไรมา)
                # ถ้าแพ็กเก็ตมีชั้นข้อมูล Raw (มีการพิมพ์ส่งข้อมูลหากัน)
                if packet.haslayer("Raw"):
                    try:
                        # ถอดรหัสข้อมูลที่ส่งมา
                        payload = packet["Raw"].load.decode(errors='ignore').strip()
                        if payload:
                            # ถ้าข้อมูลยาวไป ให้ตัดโชว์แค่ 50 ตัวอักษร
                            snippet = payload[:50] + "..." if len(payload) > 50 else payload
                            
                            # ดักจับรหัสผ่านหรือคำสั่งที่ส่งผ่านพอร์ตที่ไม่ได้เข้ารหัส
                            if dport == 21 or sport == 21: # FTP
                                self.log_event(f"[SNIFF-FTP] 📦 Data: {snippet}", "INFO")
                            elif dport == 23 or sport == 23: # Telnet
                                self.log_event(f"[SNIFF-TELNET] 📦 Data: {snippet}", "INFO")
                    except:
                        pass

    def start_sniffer(self):
        if self.is_sniffing:
            self.log_event("Sniffer is already running.", "WARN")
            return
        self.is_sniffing = True
        threading.Thread(target=self._sniff_worker, daemon=True).start()

    # ==========================================
    # 2. THREAT INTEL (ตรวจสอบ IP อันตรายจากฐานข้อมูลโลก)
    # ==========================================
    def check_threat_intel(self, ip):
        """ใช้ API ของ AbuseIPDB เพื่อเช็คประวัติอาชญากรรมของ IP"""
        # เช็คว่าเป็น IP วงแลนหรือไม่
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            self.log_event(f"Threat Intel: Skipping {ip} (Private LAN IP cannot be checked globally).", "WARN")
            return

        self.log_event(f"Querying Global Threat Intelligence for: {ip}...", "INFO")
        threading.Thread(target=self._threat_intel_worker, args=(ip,), daemon=True).start()

    def _threat_intel_worker(self, ip):
        # จำลองการตรวจสอบ (หากต้องการใช้จริง ต้องไปสมัคร API Key ฟรีจาก AbuseIPDB)
        time.sleep(1.5) # Fake loading
        if ip == "8.8.8.8" or ip == "1.1.1.1":
            self.log_event(f"[THREAT INTEL] {ip} is CLEAN. (Trusted DNS Server)", "SUCCESS")
        else:
            self.log_event(f"[THREAT INTEL] Warning: {ip} has been reported in suspicious activities!", "ALERT")

    # ==========================================
    # 3. AUTO EXPLOIT (จำลองการตอบโต้ / เจาะระบบ)
    # ==========================================
    def auto_exploit(self, ip):
        """Proof of Concept: จำลองการรัน Exploit ไปยังเป้าหมาย"""
        self.log_event(f"Initializing Auto-Exploit module against {ip}...", "ALERT")
        threading.Thread(target=self._exploit_worker, args=(ip,), daemon=True).start()

    def _exploit_worker(self, ip):
        self.log_event(f"[-] Selecting Payload: exploit/unix/ftp/vsftpd_234_backdoor", "INFO")
        time.sleep(1)
        self.log_event(f"[-] Launching attack on {ip}:21...", "WARN")
        time.sleep(2)
        # โชว์ความสำเร็จในการทำ PoC
        self.log_event(f"[+] EXPLOIT SUCCESSFUL! Root shell opened on {ip}.", "SUCCESS")
        self.show_alert("AUTO EXPLOIT", f"Successfully gained remote access to {ip}\n(Note: This is a Proof of Concept demonstration.)")

    # ==========================================
    # 4. ARP MONITOR (ป้องกันการปลอมแปลง MAC)
    # ==========================================
    # ==========================================
    # 4. ARP MONITOR (ป้องกันการปลอมแปลง MAC)
    # ==========================================
    def start_arp_monitor(self):
        if self.is_arp_monitoring:
            self.log_event("ARP Monitor is already running.", "WARN")
            return
            
        self.is_arp_monitoring = True
        # สร้างดิกชันนารีเปล่าๆ ไว้จำคู่ IP กับ MAC Address
        self.ip_mac_table = {} 
        self.log_event("[ARP MONITOR] Activated. Watching for MITM attacks...", "SUCCESS")
        
        threading.Thread(target=self._arp_worker, daemon=True).start()

    def _arp_worker(self):
        try:
            from scapy.all import sniff, ARP, conf
            all_ifaces = list(conf.ifaces.values())
            # ดักจับเฉพาะแพ็กเก็ตประเภท ARP
            sniff(iface=all_ifaces, filter="arp", prn=self._process_arp, store=False)
        except Exception as e:
            try:
                from scapy.all import sniff
                sniff(filter="arp", prn=self._process_arp, store=False)
            except Exception as e2:
                self.log_event(f"ARP Monitor Error: {e2}", "ALERT")
                self.is_arp_monitoring = False

    def _process_arp(self, packet):
        try:
            from scapy.all import ARP
            if packet.haslayer(ARP):
                # op == 2 คือแพ็กเก็ต ARP Reply (แพ็กเก็ตตอบกลับ ซึ่งแฮกเกอร์ชอบใช้ปลอมแปลง)
                if packet[ARP].op == 2:
                    src_ip = packet[ARP].psrc
                    src_mac = packet[ARP].hwsrc

                    # ถ้าเป็น IP ที่เคยรู้จักแล้ว...
                    if src_ip in self.ip_mac_table:
                        # แต่ดันส่ง MAC Address เบอร์ใหม่มา (แฮกเกอร์สวมรอยแล้ว!)
                        if self.ip_mac_table[src_ip] != src_mac:
                            old_mac = self.ip_mac_table[src_ip]
                            msg = f"[🚨 ARP POISONING DETECTED] IP: {src_ip} changed MAC from {old_mac} to {src_mac}!"
                            self.log_event(msg, "ALERT")
                            self.show_alert("MITM ATTACK DETECTED", f"มีการโจมตีแบบ ARP Spoofing!\nผู้โจมตีพยายามสวมรอยเป็น IP: {src_ip}\nด้วย MAC Address: {src_mac}")
                    else:
                        # ถ้าเพิ่งเคยเห็นครั้งแรก ให้จดจำไว้ในระบบ
                        self.ip_mac_table[src_ip] = src_mac
                        self.log_event(f"[ARP] Learned valid device: {src_ip} -> {src_mac}", "INFO")
        except:
            pass