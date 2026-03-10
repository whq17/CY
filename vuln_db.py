# พอร์ตเป้าหมายที่ต้องการสแกน
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 8000, 8080, 8443]

# ฐานข้อมูลช่องโหว่ที่จำลองตามสภาวะแวดล้อมจริง (ใช้เทียบกับ Banner)
VULNERABILITY_DB = {
    "vsftpd 2.3.4": "CVE-2011-2523 (Backdoor Command Execution)",
    "OpenSSH 4.7p1": "CVE-2008-0166 (Weak Debian Crypto)",
    "Apache/2.2.8": "CVE-2008-2364 (Memory Leak/DoS)",
    "ProFTPD 1.3.1": "CVE-2010-4221 (Multiple Vulnerabilities)",
    "Metasploitable": "OS Level Vulnerabilities Detected",
    "FreeFloat": "CVE-2012-6112 (Buffer Overflow)"
}

def check_vulnerability(banner, port):
    """วิเคราะห์ระดับความเสี่ยงจาก Banner และ Port"""
    # 1. เช็คช่องโหว่ระดับ Application จาก Banner
    if banner and banner != "No Banner":
        for key, cve_info in VULNERABILITY_DB.items():
            if key.lower() in banner.lower():
                return f"🚨 CRITICAL: {cve_info}", True
                
    # 2. เช็คความเสี่ยงระดับ Protocol (Plaintext)
    if port in [21, 23]: # FTP, Telnet
        return "⚠️ HIGH: Plaintext Protocol Risk (Sniffing)", True
        
    return "✅ Secure (No known issues)", False