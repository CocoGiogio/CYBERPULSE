# gui.py
import tkinter as tk
from tkinter import ttk, PhotoImage
import threading
from src.cyber_sec.network_scanner import NetworkScanner
from src.cyber_sec.port_scanner import PortScanner
from fpdf import FPDF


class CyberPulseApp:
    def __init__(self, root):  # Constructor
        self.root = root
        self.network_scanner = NetworkScanner()
        self.port_scanner = PortScanner()

        # Set title and window properties
        self.root.title("CyberPulse - Network Security Suite")
        self.root.geometry("800x600")
        self.root.configure(bg="#1f2933")  # Set background color

        # Try setting an icon
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
        # Notebook (Tabs)
        notebook_style = ttk.Style()
        notebook_style.configure(
            "TNotebook",
            background="#1f2933",
            foreground="#ffffff",
            padding=10,
        )
        notebook_style.configure("TNotebook.Tab", font=("Helvetica", 12), padding=[10, 5])

        notebook = ttk.Notebook(self.root, style="TNotebook")
        notebook.pack(expand=True, fill="both", padx=20, pady=20)

        # Frames for tabs
        scan_frame = ttk.Frame(notebook, style="TFrame")
        osint_frame = ttk.Frame(notebook, style="TFrame")
        remediation_frame = ttk.Frame(notebook, style="TFrame")

        notebook.add(scan_frame, text="Scan Réseau")
        notebook.add(osint_frame, text="OSINT / Recherche")
        notebook.add(remediation_frame, text="Remediation")

        # Scan Network Tab
        self.build_scan_tab(scan_frame)

        # Placeholder for other tabs
        osint_label = ttk.Label(osint_frame, text="OSINT Features Coming Soon!", font=("Helvetica", 14), background="#1f2933", foreground="#ffffff")
        osint_label.pack(expand=True, pady=20)

        remediation_label = ttk.Label(remediation_frame, text="Remediation Features Coming Soon!", font=("Helvetica", 14), background="#1f2933", foreground="#ffffff")
        remediation_label.pack(expand=True, pady=20)

    def build_scan_tab(self, scan_frame):
        # Add styling
        style = ttk.Style()
        style.configure("TFrame", background="#1f2933")
        style.configure("TLabel", background="#1f2933", foreground="#ffffff", font=("Helvetica", 12))
        style.configure("TButton", background="#374151", foreground="#ffffff", font=("Helvetica", 12), padding=5)

        scan_frame.configure(style="TFrame")

        # Header
        scan_label = ttk.Label(scan_frame, text="Scan your Wi-Fi network for devices and vulnerabilities:", style="TLabel")
        scan_label.pack(anchor="w", padx=20, pady=(20, 10))

        # Scan Button
        scan_button = ttk.Button(scan_frame, text="Start Scan", command=self.start_scan_thread, style="TButton")
        scan_button.pack(anchor="center", pady=10)

        # Progress Bar
        self.progress = ttk.Progressbar(scan_frame, orient="horizontal", mode="determinate", length=400)
        self.progress.pack(anchor="center", pady=10)

        # Results Text Box
        self.scan_results = tk.Text(scan_frame, wrap="word", height=15, bg="#e5e7eb", fg="#000000", font=("Consolas", 10), relief="flat", highlightthickness=1, highlightbackground="#4b5563")
        self.scan_results.pack(padx=20, pady=10, fill="both", expand=True)

        # Export Section
        export_label = ttk.Label(scan_frame, text="Export Results:", style="TLabel")
        export_label.pack(anchor="w", padx=20, pady=(10, 5))

        export_button = ttk.Button(scan_frame, text="Export to PDF", command=self.export_to_pdf, style="TButton")
        export_button.pack(anchor="w", padx=20, pady=5)

    def export_to_pdf(self):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        results = self.scan_results.get("1.0", tk.END).strip()
        if not results:
            print("No results to export.")
            return
        for line in results.split("\n"):
            pdf.cell(200, 10, txt=line, ln=True)
        pdf.output("scan_results.pdf")
        print("Results exported to scan_results.pdf")

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
