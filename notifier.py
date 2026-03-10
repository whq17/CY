import requests
from datetime import datetime

# 🔴 Discord Webhook URL ของกลุ่ม 5
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1479716455153930473/57w_JJ5YWaSTzO0_ZmaKpX90AcQeNjhGu_00BjeSBYJIPu0x5CXJAkDkaiUaifKhqdFx"

def send_alert(ip, vendor, port_display, banner, vuln_risk):
    # แก้ไขบั๊กแล้ว: ให้เช็คกับคำว่า "ใส่_WEBHOOK_URL_ของคุณที่นี่" (ห้ามแก้บรรทัดนี้)
    if DISCORD_WEBHOOK_URL == "ใส่_WEBHOOK_URL_ของคุณที่นี่" or DISCORD_WEBHOOK_URL == "":
        print("[!] ไม่ได้ส่งแจ้งเตือน: ยังไม่ได้ตั้งค่า Discord Webhook URL")
        return
        
    # จัดรูปแบบกล่องข้อความแจ้งเตือน (Embed) สไตล์ Cybersecurity (ซ่อมโค้ดแหว่งแล้ว)
    data = {
        "username": "Enterprise SOC Alert", 
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/2097/2097946.png",
        "embeds": [
            {
                "title": "🚨 CRITICAL VULNERABILITY DETECTED!",
                "description": "ระบบตรวจพบความเสี่ยงระดับสูงในเครือข่าย กรุณาดำเนินการตรวจสอบทันที (Incident Response)",
                "color": 16711680, # สีแดง
                "fields": [
                    {"name": "🖥️ Target IP", "value": f"`{ip}`", "inline": True},
                    {"name": "🔌 Port", "value": f"`{port_display}`", "inline": True},
                    {"name": "🏷️ Device Vendor", "value": vendor, "inline": False},
                    {"name": "📦 Service/Banner Data", "value": f"`{banner}`", "inline": False},
                    {"name": "⚠️ Vulnerability Risk", "value": vuln_risk, "inline": False}
                ],
                "footer": {"text": f"Alert Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"},
                "timestamp": datetime.now().isoformat()
            }
        ]
    }
    
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=data)
        if response.status_code == 204:
            print(f"[✓] ส่งแจ้งเตือน Discord สำเร็จ: {ip}:{port_display}")
        else:
            print(f"[!] ส่งแจ้งเตือน Discord ล้มเหลว: {response.status_code}")
    except Exception as e:
        print(f"[!] เกิดข้อผิดพลาดในการส่งแจ้งเตือน: {e}")