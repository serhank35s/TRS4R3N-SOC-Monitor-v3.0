import tkinter as tk
from tkinter import ttk
import platform
import ctypes, sys
import psutil
import pandas as pd
import time
import subprocess

# Windows only imports
if platform.system() == "Windows":
    import win32evtlog

# Event log isimleri
SYSMON_LOG = "Microsoft-Windows-Sysmon/Operational"
SECURITY_LOG = "Security"
REFRESH_INTERVAL = 300_000  # 5 dakika

feedback_df = pd.DataFrame(columns=["Event", "Feedback", "Timestamp"])

# --- Admin Check for Windows ---
if platform.system() == "Windows":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

# --- ML prediction ---
def ml_predict(event_text):
    event_lower = event_text.lower()
    if "event id   : 3" in event_lower:
        return "Brute-force (Sysmon)"
    elif "event id   : 4625" in event_lower:
        return "Brute-force (Security)"
    elif "event id   : 4720" in event_lower:
        return "User Creation"
    elif "event id   : 4725" in event_lower:
        return "User Disabled"
    elif "event id   : 4672" in event_lower:
        return "Admin Privilege Assignment"
    elif "failed password" in event_lower or "authentication failure" in event_lower:
        return "Brute-force (Linux/macOS)"
    elif "sudo" in event_lower:
        return "Privilege Escalation"
    else:
        return "Normal"

# --- OS detection & log loading ---
def detect_os():
    os_name = platform.system()
    os_release = platform.release()
    label.config(text=f"Operating System: {os_name} {os_release}")

    listbox.delete(0, tk.END)
    listbox2.delete(0, tk.END)
    ml_listbox.delete(0, tk.END)

    if os_name == "Windows":
        listbox.insert(tk.END, "===== Sysmon Logs =====")
        read_event_log(SYSMON_LOG, listbox, max_events=200)
        listbox.insert(tk.END, "===== Windows Security Logs =====")
        read_event_log(SECURITY_LOG, listbox, max_events=200)
        listbox2.insert(tk.END, "===== Active Directory Logs =====")
        read_active_log(None, listbox2, max_events=200)
    elif os_name == "Linux":
        listbox.insert(tk.END, "===== Auth Logs (/var/log/auth.log) =====")
        read_unix_log("/var/log/auth.log", listbox)
        listbox2.insert(tk.END, "===== Syslog (/var/log/syslog) =====")
        read_unix_log("/var/log/syslog", listbox2)
    elif os_name == "Darwin":  # macOS
        listbox.insert(tk.END, "===== System Log (macOS) =====")
        read_unix_log("/var/log/system.log", listbox)
        listbox2.insert(tk.END, "===== Secure Log (macOS) =====")
        read_unix_log("/var/log/secure.log", listbox2)

    root.after(REFRESH_INTERVAL, detect_os)

# --- Windows log reading ---
def read_event_log(log_name, target_listbox, max_events=50):
    try:
        handle = win32evtlog.OpenEventLog(None, log_name)
    except Exception:
        target_listbox.insert(tk.END, f"Cannot access log: {log_name}")
        return
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(handle, flags, 0)
    count = 0
    for event in events:
        event_id = event.EventID & 0xFFFF
        source = event.SourceName or "Unknown"
        time_generated = event.TimeGenerated or "Unknown"
        event_text = f"Event ID   : {event_id}\nSource     : {source}\nTime       : {time_generated}"
        if event.StringInserts:
            event_text += "\n" + "\n".join(line for line in event.StringInserts if line)
        prediction = ml_predict(event_text)
        ml_listbox.insert(tk.END, f"{prediction} | {source} | Event ID {event_id}")
        target_listbox.insert(tk.END, "="*50)
        target_listbox.insert(tk.END, event_text)
        count += 1
        if count >= max_events:
            break
    win32evtlog.CloseEventLog(handle)

def read_active_log(dc_name=None, target_listbox=None, max_events=200):
    try:
        handle = win32evtlog.OpenEventLog(dc_name, "Security")
    except Exception:
        target_listbox.insert(tk.END, "Cannot access Domain Controller Security Log")
        return
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(handle, flags, 0)
    count = 0
    for event in events:
        event_id = event.EventID & 0xFFFF
        source = event.SourceName or "Unknown"
        time_generated = event.TimeGenerated or "Unknown"
        event_text = f"Event ID : {event_id}\nSource   : {source}\nTime     : {time_generated}"
        prediction = ml_predict(event_text)
        ml_listbox.insert(tk.END, f"{prediction} | {source} | Event ID {event_id}")
        target_listbox.insert(tk.END, "="*50)
        target_listbox.insert(tk.END, event_text)
        count += 1
        if count >= max_events:
            break
    win32evtlog.CloseEventLog(handle)

# --- Unix log reading ---
def read_unix_log(path, target_listbox, max_lines=200):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[-max_lines:]
    except Exception as e:
        target_listbox.insert(tk.END, f"Cannot access log: {path}")
        return
    for line in lines:
        prediction = ml_predict(line)
        ml_listbox.insert(tk.END, f"{prediction} | {line[:50]}")  # kısaltılmış gösterim
        target_listbox.insert(tk.END, line.strip())

# --- Network & Performance functions (same as before) ---
def update_network_connections():
    listbox3.delete(0, tk.END)
    listbox3.insert(tk.END, "===== Active Connections =====")
    for conn in psutil.net_connections(kind='inet'):
        local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
        remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
        status = conn.status
        pid = conn.pid
        try:
            pname = psutil.Process(pid).name() if pid else "Unknown"
        except:
            pname = "Unknown"
        listbox3.insert(tk.END, f"{pname} ({pid}) {local} -> {remote} [{status}]")
    root.after(5000, update_network_connections)

def update_perf_bars():
    cpu_percent = psutil.cpu_percent()
    ram_percent = psutil.virtual_memory().percent
    cpu_bar['value'] = cpu_percent
    ram_bar['value'] = ram_percent
    cpu_label.config(text=f"CPU Usage: {cpu_percent:.1f}%")
    ram_label.config(text=f"RAM Usage: {ram_percent:.1f}%")
    root.after(1000, update_perf_bars)

# --- GUI setup ---
root = tk.Tk()
root.title("TRS4R3N SOC Monitor v3.0")
root.geometry("1400x800")

label = tk.Label(root, text="Operating System:", anchor="w")
label.pack(fill="x", padx=10, pady=5)
btn = tk.Button(root, text="Detect OS & Load Logs", command=detect_os)
btn.pack(anchor="w", padx=5, pady=5)

# Performance bars
perf_frame = tk.Frame(root)
perf_frame.pack(fill="x", padx=10, pady=5)
cpu_label = tk.Label(perf_frame, text="CPU Usage:")
cpu_label.pack(side="left", padx=(0,5))
cpu_bar = ttk.Progressbar(perf_frame, length=200, mode='determinate', maximum=100)
cpu_bar.pack(side="left", padx=5)
ram_label = tk.Label(perf_frame, text="RAM Usage:")
ram_label.pack(side="left", padx=(20,5))
ram_bar = ttk.Progressbar(perf_frame, length=200, mode='determinate', maximum=100)
ram_bar.pack(side="left", padx=5)
update_perf_bars()

# Top frame with 3 listboxes
top_frame = tk.Frame(root)
top_frame.pack(side="top", fill="both", expand=True, padx=10, pady=5)

# Sysmon / Auth logs
left_panel = tk.Frame(top_frame)
left_panel.pack(side="left", fill="both", expand=True)
tk.Label(left_panel, text="System Logs").pack(anchor="w")
scroll_sysmon = tk.Scrollbar(left_panel)
scroll_sysmon.pack(side="right", fill="y")
listbox = tk.Listbox(left_panel, width=50, height=25, yscrollcommand=scroll_sysmon.set)
listbox.pack(fill="both", expand=True)
scroll_sysmon.config(command=listbox.yview)

# AD / Syslog
middle_panel = tk.Frame(top_frame)
middle_panel.pack(side="left", fill="both", expand=True, padx=5)
tk.Label(middle_panel, text="Active Directory / User Logs").pack(anchor="w")
scroll_ad = tk.Scrollbar(middle_panel)
scroll_ad.pack(side="right", fill="y")
listbox2 = tk.Listbox(middle_panel, width=50, height=25, yscrollcommand=scroll_ad.set)
listbox2.pack(fill="both", expand=True)
scroll_ad.config(command=listbox2.yview)

# ML Analysis
right_panel = tk.Frame(top_frame)
right_panel.pack(side="left", fill="both", expand=True, padx=5)
tk.Label(right_panel, text="ML Analysis").pack(anchor="w")
scroll_ml = tk.Scrollbar(right_panel)
scroll_ml.pack(side="right", fill="y")
ml_listbox = tk.Listbox(right_panel, width=50, height=25, yscrollcommand=scroll_ml.set)
ml_listbox.pack(fill="both", expand=True)
scroll_ml.config(command=ml_listbox.yview)

# Network connections
net_frame = tk.Frame(root)
net_frame.pack(side="top", fill="both", expand=True, padx=10, pady=5)
tk.Label(net_frame, text="Network Connections").pack(anchor="w")
scroll_net = tk.Scrollbar(net_frame)
scroll_net.pack(side="right", fill="y")
listbox3 = tk.Listbox(net_frame, height=10, yscrollcommand=scroll_net.set)
listbox3.pack(fill="both", expand=True)
scroll_net.config(command=listbox3.yview)
update_network_connections()

root.mainloop()
