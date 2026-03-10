import socket

def start_fake_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # จำลองเป็นพอร์ต 21 (FTP)
    server.bind(("0.0.0.0", 21))
    server.listen(5)
    
    print("⚠️ [DUMMY SERVER] กำลังรันเซิร์ฟเวอร์จำลองที่มีช่องโหว่บน Port 21...")
    print("⚠️ รอรับการสแกนจาก Group 5 Scanner...")
    
    while True:
        client, addr = server.accept()
        print(f"[*] มีการสแกนเข้ามาจาก IP: {addr[0]}")
        # ส่ง Banner ที่มีช่องโหว่หลอกๆ กลับไปให้ Scanner ของเรา
        client.send(b"220 (vsFTPd 2.3.4) - Ready for exploit\r\n")
        client.close()

if __name__ == "__main__":
    start_fake_server()