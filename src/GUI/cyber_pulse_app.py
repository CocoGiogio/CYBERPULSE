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
        self.root.geometry("1000x600")
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
        # Left Sidebar Frame with gradient effect
        sidebar_frame = tk.Frame(self.root, width=220, bg="#1f2933")
        sidebar_frame.pack(side="left", fill="y")

        # Sidebar Buttons with hover effect
        self.create_sidebar_buttons(sidebar_frame)

        # Main Content Frame
        self.content_frame = tk.Frame(self.root, bg="#2d3748", relief="solid", bd=1)
        self.content_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        # Default to scan tab
        self.show_scan_tab()

    def create_sidebar_buttons(self, sidebar_frame):
        # Create sidebar buttons with hover effects
        buttons = [
            ("Scan Réseau", self.show_scan_tab),
            ("OSINT / Recherche", self.show_osint_tab),
            ("Remediation", self.show_remediation_tab)
        ]

        for text, command in buttons:
            button = tk.Button(
                sidebar_frame, text=text, command=command,
                font=("Helvetica", 14), bg="#2d3748", fg="#ffffff",
                relief="flat", width=20, anchor="w", padx=20, pady=15
            )
            button.pack(fill="x", pady=5)

            # Hover effect
            button.bind("<Enter>", lambda e, b=button: b.config(bg="#4A5568"))
            button.bind("<Leave>", lambda e, b=button: b.config(bg="#2d3748"))

    def show_scan_tab(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        # Scan Network Tab
        scan_frame = ttk.Frame(self.content_frame, style="TFrame")
        self.build_scan_tab(scan_frame)
        scan_frame.pack(fill="both", expand=True)

    def show_osint_tab(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        # OSINT Tab
        osint_frame = ttk.Frame(self.content_frame, style="TFrame")
        osint_label = ttk.Label(osint_frame, text="OSINT Features Coming Soon!", font=("Helvetica", 16), background="#2d3748", foreground="#ffffff")
        osint_label.pack(expand=True, pady=20)
        osint_frame.pack(fill="both", expand=True)

    def show_remediation_tab(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        # Remediation Tab
        remediation_frame = ttk.Frame(self.content_frame, style="TFrame")
        remediation_label = ttk.Label(remediation_frame, text="Remediation Features Coming Soon!", font=("Helvetica", 16), background="#2d3748", foreground="#ffffff")
        remediation_label.pack(expand=True, pady=20)
        remediation_frame.pack(fill="both", expand=True)

    def build_scan_tab(self, scan_frame):
        # Add styling
        style = ttk.Style()
        style.configure("TFrame", background="#2d3748")
        style.configure("TLabel", background="#2d3748", foreground="#ffffff", font=("Helvetica", 14))
        style.configure("TButton", background="#4A5568", foreground="#ffffff", font=("Helvetica", 14), padding=5)

        scan_frame.configure(style="TFrame")

        # Header
        scan_label = ttk.Label(scan_frame, text="Scan your Wi-Fi network for devices and vulnerabilities:", style="TLabel")
        scan_label.pack(anchor="w", padx=20, pady=(20, 10))

        # Scan Button with hover effect
        scan_button = ttk.Button(scan_frame, text="Start Scan", command=self.start_scan_thread, style="TButton")
        scan_button.pack(anchor="center", pady=10)

        # Progress Bar with improved color
        self.progress = ttk.Progressbar(scan_frame, orient="horizontal", mode="determinate", length=400, style="TProgressbar")
        self.progress.pack(anchor="center", pady=10)

        # Scan Results Box
        self.scan_results = tk.Text(scan_frame, wrap="word", height=15, bg="#f7fafc", fg="#333333", font=("Consolas", 12), relief="flat", highlightthickness=1, highlightbackground="#e2e8f0")
        self.scan_results.pack(padx=20, pady=10, fill="both", expand=True)

        # Export Section
        export_label = ttk.Label(scan_frame, text="Export Results:", style="TLabel")
        export_label.pack(anchor="w", padx=20, pady=(10, 5))

        self.export_options = ttk.Combobox(scan_frame, values=["PDF"], state="readonly", font=("Helvetica", 12))
        self.export_options.pack(anchor="w", padx=20, pady=5)
        self.export_options.bind("<<ComboboxSelected>>", self.export_results)

    def export_results(self, event):
        option = self.export_options.get()
        if option == "PDF":
            self.export_to_pdf()

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


if __name__ == "__main__":
    root = tk.Tk()
    app = CyberPulseApp(root)
    root.mainloop()
