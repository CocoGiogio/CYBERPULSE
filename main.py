import tkinter as tk
from tkinter import ttk
from tkinter import PhotoImage
from scapy.all import ARP, Ether, srp

class CyberPulseApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberPulse")

        # Set window icon
        try:
            self.icon = PhotoImage(file="static/favicon-16x16.png")
            self.root.iconphoto(False, self.icon)
        except tk.TclError:
            print("Icon not found or invalid.")

        self.create_widgets()

    def create_widgets(self):
        # Create a notebook
        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill='both')

        # Create frame for scan tab
        scan_frame = ttk.Frame(notebook)

        notebook.add(scan_frame, text='Scan Réseau')

        # Add content to scan tab
        scan_label = ttk.Label(scan_frame, text="Entrez l'adresse IP pour scanner le réseau:", wraplength=400, justify="left")
        scan_label.pack(padx=10, pady=10)

        self.ip_entry = ttk.Entry(scan_frame)
        self.ip_entry.pack(padx=10, pady=10)

        scan_button = ttk.Button(scan_frame, text="Scanner", command=self.scan_network)
        scan_button.pack(padx=10, pady=10)

        self.scan_results = tk.Text(scan_frame, wrap='word', height=10)
        self.scan_results.pack(padx=10, pady=10, fill='both', expand=True)

    def scan_network(self):
        ip_range = self.ip_entry.get()
        if not ip_range:
            self.scan_results.insert(tk.END, "Veuillez entrer une adresse IP.\n")
            return

        self.scan_results.insert(tk.END, f"Scanning {ip_range}...\n")
        self.scan_results.update()

        # Perform network scan
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=3, verbose=0)[0]

        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        if devices:
            self.scan_results.insert(tk.END, "Found devices:\n")
            for device in devices:
                self.scan_results.insert(tk.END, f"IP: {device['ip']}, MAC: {device['mac']}\n")
        else:
            self.scan_results.insert(tk.END, "No devices found.\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberPulseApp(root)
    root.mainloop()
