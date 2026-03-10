# พอร์ตเป้าหมายที่ต้องการสแกน
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 5432, 6379, 8000, 8080, 8443]

# ฐานข้อมูลช่องโหว่ที่จำลองตามสภาวะแวดล้อมจริง (ใช้เทียบกับ Banner)
VULNERABILITY_DB = {
    "vsftpd 2.3.4": "CVE-2011-2523 (Backdoor Command Execution)",
    "OpenSSH 4.7p1": "CVE-2008-0166 (Weak Debian Crypto)",
    "Apache/2.2.8": "CVE-2008-2364 (Memory Leak/DoS)",
    "ProFTPD 1.3.1": "CVE-2010-4221 (Multiple Vulnerabilities)",
    "Metasploitable": "OS Level Vulnerabilities Detected",
    "FreeFloat": "CVE-2012-6112 (Buffer Overflow)"
}

SERVICE_BY_PORT = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP",
    8080: "HTTP",
    8443: "HTTPS",
}

OWASP_HINTS = {
    "plaintext protocol": "A02:2021-Cryptographic Failures",
    "backend service exposed": "A05:2021-Security Misconfiguration",
    "outdated component banner": "A06:2021-Vulnerable and Outdated Components",
    "auth surface": "A07:2021-Identification and Authentication Failures",
    "misconfiguration indicator": "A05:2021-Security Misconfiguration",
}


def detect_service(port, banner=""):
    """พยายามระบุชื่อ service จากพอร์ตและ banner แบบ heuristic"""
    service = SERVICE_BY_PORT.get(port, "Unknown")
    lowered = (banner or "").lower()

    if "http/" in lowered or "server:" in lowered:
        return "HTTP" if port not in [443, 8443] else "HTTPS"
    if "ftp" in lowered or "vsftpd" in lowered or "proftpd" in lowered:
        return "FTP"
    if "telnet" in lowered:
        return "Telnet"
    if "mysql" in lowered:
        return "MySQL"
    if "redis" in lowered:
        return "Redis"
    if "postgres" in lowered:
        return "PostgreSQL"

    return service


def _build_risk_summary(severity, service, findings):
    owasp_mappings = []
    for finding in findings:
        mapped = OWASP_HINTS.get(finding)
        if mapped and mapped not in owasp_mappings:
            owasp_mappings.append(mapped)

    findings_text = ", ".join(findings) if findings else "none"
    owasp_text = "; ".join(owasp_mappings) if owasp_mappings else "N/A"
    return f"{severity} | Service={service} | Findings={findings_text} | OWASP: {owasp_text}"


def check_vulnerability(banner, port):
    """วิเคราะห์ระดับความเสี่ยงจาก Banner + Port และ map ไป OWASP Top 10 แบบ heuristic"""
    service = detect_service(port, banner)
    lowered_banner = (banner or "").lower()

    findings = []
    severity = "LOW"

    # 1) Protocol risk
    if service in ["FTP", "Telnet", "POP3", "SMTP"]:
        findings.append("plaintext protocol")
        severity = "HIGH"

    # 2) Backend service exposed
    if service in ["MySQL", "Redis", "PostgreSQL", "SMB"]:
        findings.append("backend service exposed")
        severity = "HIGH"

    # 3) Auth surface
    if service in ["SSH", "RDP", "FTP", "MySQL", "PostgreSQL", "Redis", "Telnet"]:
        findings.append("auth surface")
        if severity == "LOW":
            severity = "MEDIUM"

    # 4) Banner-based outdated component + known CVE
    if banner and banner != "No Banner":
        for key, cve_info in VULNERABILITY_DB.items():
            if key.lower() in lowered_banner:
                findings.append("outdated component banner")
                findings.append(f"known vuln: {cve_info}")
                severity = "HIGH"
                break

    # 5) Misconfiguration indicators in banners
    misconfig_markers = ["default", "unauthorized", "forbidden", "debug", "test", "internal"]
    if any(marker in lowered_banner for marker in misconfig_markers):
        findings.append("misconfiguration indicator")
        if severity == "LOW":
            severity = "MEDIUM"

    is_critical = severity == "HIGH"
    summary = _build_risk_summary(severity, service, findings)
    return summary, is_critical, service
