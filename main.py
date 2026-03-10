import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog, scrolledtext
import threading
import ctypes, sys
from queue import Queue
import csv
from datetime import datetime
import socket

# --- 📦 IMPORT OUR MODULES ---
try:
    from db_manager import DatabaseManager
    import vuln_db
    import notifier
    from cyber_ops import CyberOperations
    from net_scanner import ping_host, get_mac, get_banner
    from sec_manager import SecurityManager
except ImportError as e:
    messagebox.showerror("System Error", f"Missing Modules!\n{e}")
    sys.exit()

db = DatabaseManager()

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

if not is_admin():
    ctypes.windll.user32.MessageBoxW(0, "ACCESS DENIED: Please run as Administrator", "Security Policy", 16)
    sys.exit()

# --- 🎨 DARK CYBER THEME PALETTE ---
BG_MAIN = "#1A1B1E"         # พื้นหลังหลัก (เทาเข้มเกือบดำ)
BG_SIDEBAR = "#25262B"      # พื้นหลังแถบข้าง
ACCENT_BLUE = "#339AF0"     # สีฟ้าหลัก
ACCENT_CYAN = "#15AABF"     # สีฟ้าสว่าง
MATRIX_GREEN = "#51CF66"    # สีเขียวสดใส
RED_ALERT = "#FF6B6B"       # สีแดงแจ้งเตือน
YELLOW_WARN = "#FCC419"     # สีเหลืองระวัง
TEXT_BRIGHT = "#F8F9FA"     # ตัวอักษรหลัก
TEXT_DIM = "#ADB5BD"        # ตัวอักษรจาง
BORDER_COLOR = "#373A40"    # สีเส้นขอบ

class SecurityInspectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("[SYS.ADMIN] // VULNERABILITY_SCANNER_G5")
        self.root.geometry("1450x900")
        self.root.configure(bg=BG_MAIN)

        self.sec_mgr = SecurityManager(self.trigger_honeypot_alert)
        self.setup_styles()
        self.setup_ui()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # ตกแต่ง Treeview (ตาราง)
        style.configure("Treeview", 
                        background=BG_SIDEBAR, 
                        foreground=TEXT_BRIGHT, 
                        fieldbackground=BG_SIDEBAR, 
                        rowheight=35, 
                        borderwidth=0,
                        font=("Segoe UI", 10))
        style.configure("Treeview.Heading", 
                        background=BG_MAIN, 
                        foreground=ACCENT_CYAN, 
                        font=("Consolas", 10, "bold"), 
                        borderwidth=0)
        style.map('Treeview', background=[('selected', ACCENT_BLUE)], foreground=[('selected', 'white')])

        # ตกแต่ง Progressbar
        style.configure("Cyber.Horizontal.TProgressbar", 
                        thickness=6, 
                        troughcolor=BG_MAIN, 
                        background=MATRIX_GREEN, 
                        bordercolor=BG_MAIN)

    def create_nav_btn(self, parent, text, icon_text, color, cmd):
        """สร้างปุ่มสไตล์ Sidebar Navigation"""
        btn_frame = tk.Frame(parent, bg=BG_SIDEBAR, pady=5)
        btn_frame.pack(fill="x", padx=10)
        
        btn = tk.Button(btn_frame, text=f" {icon_text}  {text}", command=cmd, 
                        bg=BG_SIDEBAR, fg=color, font=("Segoe UI", 10, "bold"),
                        relief="flat", anchor="w", padx=15, pady=10,
                        activebackground=BG_MAIN, activeforeground=color, cursor="hand2")
        btn.pack(fill="x")
        
        def on_enter(e): btn['bg'] = "#2C2E33"
        def on_leave(e): btn['bg'] = BG_SIDEBAR
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        return btn

    def setup_ui(self):
        # --- 🛠️ SIDEBAR AREA ---
        self.sidebar = tk.Frame(self.root, bg=BG_SIDEBAR, width=280)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Logo / Title in Sidebar
        logo_frame = tk.Frame(self.sidebar, bg=BG_SIDEBAR, pady=30)
        logo_frame.pack(fill="x")
        tk.Label(logo_frame, text="🛡️ CYBER OPS", font=("Consolas", 18, "bold"), fg=TEXT_BRIGHT, bg=BG_SIDEBAR).pack()
        tk.Label(logo_frame, text="VULN_SCANNER_G5", font=("Consolas", 8), fg=ACCENT_CYAN, bg=BG_SIDEBAR).pack()

        # Input Field in Sidebar
        tk.Label(self.sidebar, text="TARGET IP RANGE", font=("Segoe UI", 8, "bold"), fg=TEXT_DIM, bg=BG_SIDEBAR).pack(anchor="w", padx=25, pady=(20, 5))
        ip_entry_frame = tk.Frame(self.sidebar, bg=BG_MAIN, padx=2, pady=2)
        ip_entry_frame.pack(fill="x", padx=20)
        self.ip_entry = tk.Entry(ip_entry_frame, bg=BG_MAIN, fg=MATRIX_GREEN, font=("Consolas", 11, "bold"), 
                                 relief="flat", insertbackground=ACCENT_CYAN)
        self.ip_entry.insert(0, "192.168.1.")
        self.ip_entry.pack(fill="x", padx=10, pady=8)

        # Navigation Buttons
        tk.Label(self.sidebar, text="CORE ENGINE", font=("Segoe UI", 8, "bold"), fg=TEXT_DIM, bg=BG_SIDEBAR).pack(anchor="w", padx=25, pady=(20, 5))
        self.scan_btn = self.create_nav_btn(self.sidebar, "INIT TARGET SCAN", "🚀", ACCENT_BLUE, self.start_scan)
        
        tk.Label(self.sidebar, text="DEFENSE SYSTEMS", font=("Segoe UI", 8, "bold"), fg=TEXT_DIM, bg=BG_SIDEBAR).pack(anchor="w", padx=25, pady=(20, 5))
        self.honeypot_btn = self.create_nav_btn(self.sidebar, "ENGAGE HONEYPOT", "🍯", YELLOW_WARN, self.start_honeypot)
        self.create_nav_btn(self.sidebar, "LIVE SNIFFER", "🔍", ACCENT_CYAN, lambda: self.cyber_ops.start_sniffer())
        self.create_nav_btn(self.sidebar, "ARP MONITOR", "🛡️", MATRIX_GREEN, lambda: self.cyber_ops.start_arp_monitor())

        # Footer Button
        self.export_btn = tk.Button(self.sidebar, text="📥 EXPORT REPORT", command=self.export_csv,
                                   bg=BORDER_COLOR, fg=TEXT_BRIGHT, font=("Segoe UI", 9, "bold"),
                                   relief="flat", pady=8, cursor="hand2")
        self.export_btn.pack(side="bottom", fill="x", padx=20, pady=30)

        # --- 🖥️ MAIN VIEW AREA ---
        main_view = tk.Frame(self.root, bg=BG_MAIN)
        main_view.pack(side="right", fill="both", expand=True, padx=30, pady=20)

        # Top Header (Status Line)
        header_frame = tk.Frame(main_view, bg=BG_MAIN)
        header_frame.pack(fill="x", pady=(0, 20))
        self.status_lbl = tk.Label(header_frame, text="STATUS: SCAN_COMPLETE // READY_FOR_INCIDENT_RESPONSE", 
                                   fg=MATRIX_GREEN, bg=BG_MAIN, font=("Consolas", 10))
        self.status_lbl.pack(side="left")

        # Progress Bar
        self.progress = ttk.Progressbar(main_view, orient="horizontal", mode="determinate", style="Cyber.Horizontal.TProgressbar")
        self.progress.pack(fill="x", pady=(0, 10))

        # Data Table Container
        table_container = tk.Frame(main_view, bg=BORDER_COLOR, pady=1, padx=1)
        table_container.pack(fill="both", expand=True)

        cols = ("Status", "IP Address", "MAC / Vendor", "Port & Service", "Banner Data", "Risk Level")
        self.tree = ttk.Treeview(table_container, columns=cols, show="headings")
        for col in cols: self.tree.heading(col, text=col.upper())
        
        # Adjust column widths
        self.tree.column("Status", width=110, anchor="center")
        self.tree.column("IP Address", width=120, anchor="center")
        self.tree.column("MAC / Vendor", width=200)
        self.tree.column("Port & Service", width=160)
        self.tree.column("Risk Level", width=300)

        # Tags for coloring
        self.tree.tag_configure("safe", foreground=MATRIX_GREEN)
        self.tree.tag_configure("critical", foreground=RED_ALERT, background="#2D1A1A")
        self.tree.tag_configure("blocked", foreground=TEXT_DIM)
        self.tree.tag_configure("trusted", foreground=ACCENT_BLUE)
        
        self.tree.pack(fill="both", expand=True)

        # Quick Action Buttons below table
        action_bar = tk.Frame(main_view, bg=BG_MAIN, pady=15)
        action_bar.pack(fill="x")
        
        self.create_action_btn(action_bar, "🛑 FIREWALL BLOCK (DROP)", RED_ALERT, self.ui_block_device).pack(side="left", padx=(0, 10))
        self.create_action_btn(action_bar, "✔️ TRUST HOST (WHITELIST)", MATRIX_GREEN, self.ui_trust_device).pack(side="left")

        # Live Event Log (Terminal style)
        tk.Label(main_view, text=">_ LIVE EVENT LOG", font=("Consolas", 10, "bold"), fg=ACCENT_CYAN, bg=BG_MAIN).pack(anchor="w", pady=(10, 5))
        log_container = tk.Frame(main_view, bg=BORDER_COLOR, pady=1, padx=1)
        log_container.pack(fill="x")
        self.terminal = scrolledtext.ScrolledText(log_container, height=10, bg="#121214", fg=TEXT_BRIGHT, 
                                                  font=("Consolas", 10), relief="flat", padx=10, pady=10)
        self.terminal.pack(fill="x")

        # Core logic components
        self.cyber_ops = CyberOperations(self.log_event, self.show_ui_alert)
        self.queue = Queue()
        self.is_scanning = False
        self.log_event("Cyber Security Dashboard initialized. All systems go.")

    def create_action_btn(self, parent, text, color, cmd):
        """สร้างปุ่ม Action ใต้ตาราง"""
        btn = tk.Button(parent, text=text, command=cmd, bg=BG_SIDEBAR, fg=color, 
                        font=("Segoe UI", 9, "bold"), relief="solid", borderwidth=1, 
                        padx=15, pady=8, cursor="hand2", activebackground=color, activeforeground=BG_MAIN)
        return btn

    def log_event(self, msg, level="INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        tags = {"ALERT": "red", "WARN": "yellow", "SUCCESS": "green"}
        color = tags.get(level, "white")
        self.terminal.tag_config("red", foreground=RED_ALERT)
        self.terminal.tag_config("yellow", foreground=YELLOW_WARN)
        self.terminal.tag_config("green", foreground=MATRIX_GREEN)
        self.terminal.tag_config("white", foreground=TEXT_BRIGHT)
        
        self.terminal.insert(tk.END, f"[{ts}] [{level}] {msg}\n", color)
        self.terminal.see(tk.END)

    # --- SCANNING LOGIC ---
    def worker(self):
        while True:
            ip = self.work_queue.get()
            if ip is None: break
            if ping_host(ip):
                mac = get_mac(ip)
                vendor = db.get_vendor(mac)
                found_ports = False
                for port in vuln_db.SCAN_PORTS:
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(0.3)
                            if s.connect_ex((ip, port)) == 0:
                                found_ports = True
                                banner = get_banner(ip, port)
                                risk, is_critical = vuln_db.check_vulnerability(banner, port)
                                self.queue.put((ip, mac, vendor, f"Port {port}", banner, risk, is_critical))
                                if is_critical: notifier.send_alert(ip, vendor, f"Port {port}", banner, risk)
                    except: pass
                if not found_ports:
                    self.queue.put((ip, mac, vendor, "Safe", "-", "SECURE", False))
            self.work_queue.task_done()
            self.root.after(0, self.update_progress)

    def update_progress(self):
        self.progress_val += 1
        self.progress['value'] = self.progress_val
        pct = (self.progress_val / self.total_tasks) * 100
        self.status_lbl.config(text=f"STATUS: SCANNING_NETWORK // THREADS_ACTIVE // {pct:.1f}%")

    def check_queue(self):
        try:
            while True:
                ip, mac, vendor, p_disp, banner, risk, is_crit = self.queue.get_nowait()
                tag = "critical" if is_crit else "safe"
                status = "[ CRITICAL ]" if is_crit else "[ SECURE ]"
                self.tree.insert("", "end", values=(status, ip, f"{mac} ({vendor})", p_disp, banner, risk), tags=(tag,))
        except: pass
        if self.is_scanning: self.root.after(500, self.check_queue)
        else:
            self.status_lbl.config(text="STATUS: SCAN_COMPLETE // READY_FOR_INCIDENT_RESPONSE", fg=MATRIX_GREEN)
            self.scan_btn.config(state="normal", text="🚀 INIT TARGET SCAN")

    def run_scan(self, target):
        self.work_queue = Queue()
        tasks = [f"{target}{i}" for i in range(1, 255)] if target.endswith(".") else [target]
        self.total_tasks = len(tasks)
        self.progress_val = 0
        self.progress['maximum'] = self.total_tasks
        for t in tasks: self.work_queue.put(t)
        for _ in range(min(50, len(tasks))): threading.Thread(target=self.worker, daemon=True).start()
        self.work_queue.join()
        self.is_scanning = False

    def start_scan(self):
        if self.is_scanning: return
        self.is_scanning = True
        self.scan_btn.config(state="disabled", text="⏳ SCANNING...")
        for i in self.tree.get_children(): self.tree.delete(i)
        target = self.ip_entry.get()
        threading.Thread(target=self.run_scan, args=(target,), daemon=True).start()
        self.root.after(100, self.check_queue)

    # --- HANDLERS ---
    def show_ui_alert(self, title, message):
        self.root.after(0, lambda: messagebox.showwarning(title, message))

    def trigger_honeypot_alert(self, ip, user, pw):
        msg = f"HONEYPOT TRIGGERED! Attacker: {ip} | Credentials: {user}/{pw}"
        self.root.after(0, lambda: self.log_event(msg, "ALERT"))
        self.root.after(0, lambda: messagebox.showwarning("🚨 INTRUSION", msg))

    def start_honeypot(self):
        self.honeypot_btn.config(state="disabled", text="[ HONEYPOT ACTIVE ]")
        threading.Thread(target=self.sec_mgr.start_honeypot, daemon=True).start()
        self.log_event("Deception System (Honeypot) active on Port 23.", "WARN")

    def ui_trust_device(self):
        sel = self.tree.selection()
        if not sel: return
        item = self.tree.item(sel[0])['values']
        self.log_event(f"Host {item[1]} added to Whitelist.", "SUCCESS")
        self.tree.item(sel[0], tags=("trusted",))

    def ui_block_device(self):
        sel = self.tree.selection()
        if not sel: return
        ip = self.tree.item(sel[0])['values'][1]
        if messagebox.askyesno("Confirm Block", f"Add firewall rule to block {ip}?"):
            self.sec_mgr.block_ip(ip)
            self.log_event(f"IP {ip} has been BLOCKED.", "ALERT")
            self.tree.item(sel[0], tags=("blocked",))

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv")
        if path:
            with open(path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(["Status", "IP", "Vendor", "Port", "Banner", "Risk"])
                for c in self.tree.get_children(): writer.writerow(self.tree.item(c)['values'])
            messagebox.showinfo("Export", "Report generated successfully.")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityInspectorGUI(root)
    root.mainloop()