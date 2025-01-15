# gui.py
import tkinter as tk
from tkinter import ttk, PhotoImage
import threading
from src.cyber_sec.network_scanner import NetworkScanner
from src.cyber_sec.port_scanner import PortScanner

class CyberPulseApp:
    def __init__(self, root):
        self.root = root
        self.network_scanner = NetworkScanner()
        self.port_scanner = PortScanner()

        self.root.title("CyberPulse")
        try:
            self.icon = PhotoImage(file="static/favicon-16x16.png")
            self.root.iconphoto(False, self.icon)
        except tk.TclError:
            print("Icon not found or invalid.")

        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        self.root.destroy()

    def start_scan_thread(self):
        scan_thread = threading.Thread(target=self.scan_network)
        scan_thread.start()

    def create_widgets(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill="both")

        scan_frame = ttk.Frame(notebook)
        notebook.add(scan_frame, text="Scan Réseau")

        scan_label = ttk.Label(
            scan_frame,
            text="Cliquez sur le bouton pour scanner le réseau Wi-Fi:",
            wraplength=400,
            justify="left",
        )
        scan_label.pack(padx=10, pady=10)

        scan_button = ttk.Button(scan_frame, text="Scanner", command=self.start_scan_thread)
        scan_button.pack(padx=10, pady=10)

        self.progress = ttk.Progressbar(scan_frame, orient="horizontal", mode="determinate")
        self.progress.pack(padx=10, pady=10, fill="x")

        self.scan_results = tk.Text(scan_frame, wrap="word", height=10)
        self.scan_results.pack(padx=10, pady=10, fill="both", expand=True)

    def scan_network(self):
        network_info = self.network_scanner.get_network_info()
        if not network_info:
            self.scan_results.insert(tk.END, "Default route not found.\n")
            return

        ip_range, selected_interface = network_info
        self.scan_results.insert(
            tk.END, f"Scanning {ip_range} on interface {selected_interface}...\n"
        )
        self.scan_results.update()

        devices = self.network_scanner.perform_network_scan(ip_range, selected_interface, self.progress, self.root)

        if devices:
            self.scan_results.insert(tk.END, "Found devices:\n")
            for device in devices:
                ip = device["ip"]
                mac = device["mac"]
                self.scan_results.insert(tk.END, f"IP: {ip}, MAC: {mac}\n")
                if self.network_scanner.is_ip_reachable(ip):
                    open_ports = self.port_scanner.scan_ports(ip)
                    if open_ports:
                        self.scan_results.insert(tk.END, f"Open ports on {ip}: {open_ports}\n")
                    else:
                        self.scan_results.insert(tk.END, f"No open ports found on {ip}.\n")
        else:
            self.scan_results.insert(tk.END, "No devices found.\n")
