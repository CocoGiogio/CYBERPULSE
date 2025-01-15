import tkinter as tk
from tkinter import ttk
from tkinter import PhotoImage
from scapy.all import ARP, Ether, srp, get_if_list, get_if_addr
import ipaddress
import socket
import threading
import psutil

class CyberPulseApp:
    def __init__(self, root):
        self.root = root
        # Initialize the interface map
        self.interface_map = {}
        # Set window title
        self.root.title("CyberPulse")

        # Set window icon
        try:
            self.icon = PhotoImage(file="static/favicon-16x16.png")
            self.root.iconphoto(False, self.icon)
        except tk.TclError:
            print("Icon not found or invalid.")

        self.create_widgets()

        # Bind the close event to the custom close function
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        # Perform any cleanup here if necessary
        self.root.destroy()

    def start_scan_thread(self):
        scan_thread = threading.Thread(target=self.scan_network)
        scan_thread.start()

    def create_widgets(self):
        # Create a notebook
        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill='both')

        # Create frame for scan tab
        scan_frame = ttk.Frame(notebook)
        notebook.add(scan_frame, text='Scan Réseau')

        # Add content to scan tab
        scan_label = ttk.Label(scan_frame, text="Cliquez sur le bouton pour scanner le réseau Wi-Fi:", wraplength=400, justify="left")
        scan_label.pack(padx=10, pady=10)

        # Dropdown for network interfaces
        self.interface_var = tk.StringVar()
        interfaces = get_if_list()
        self.interface_map = {iface: get_if_addr(iface) for iface in interfaces}
        interface_names = [f"{iface} ({addr})" for iface, addr in self.interface_map.items()]
        self.interface_var.set(interface_names[0])  # Set default value to the first interface
        interface_dropdown = ttk.OptionMenu(scan_frame, self.interface_var, *interface_names)
        interface_dropdown.pack(padx=10, pady=10)

        scan_button = ttk.Button(scan_frame, text="Scanner", command=self.start_scan_thread)
        scan_button.pack(padx=10, pady=10)

        self.progress = ttk.Progressbar(scan_frame, orient='horizontal', mode='determinate')
        self.progress.pack(padx=10, pady=10, fill='x')

        self.scan_results = tk.Text(scan_frame, wrap='word', height=10)
        self.scan_results.pack(padx=10, pady=10, fill='both', expand=True)

    def scan_network(self):
        selected_interface = self.interface_var.get().split(' ')[0]
        interfaces = psutil.net_if_addrs().keys()
        if selected_interface not in interfaces:
            self.scan_results.insert(tk.END, f"Selected interface {selected_interface} not found.\n")
            return
        addrs = psutil.net_if_addrs()[selected_interface]
        ip_info = next(addr for addr in addrs if addr.family == socket.AF_INET)
        ip_address = ip_info.address
        subnet_mask = ip_info.netmask
        
        # Calculate the network range
        network = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=False)
        ip_range = str(network)

        self.scan_results.insert(tk.END, f"Scanning {ip_range} on interface {selected_interface}...\n")
        self.scan_results.update()

        # Perform network scan
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, iface=selected_interface, timeout=3, verbose=0)[0]

        devices = []
        total_addresses = len(list(network.hosts()))
        self.progress['maximum'] = total_addresses

        for i, (_, received) in enumerate(result):
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
            self.progress['value'] = i + 1
            self.root.update_idletasks()

        if devices:
            self.scan_results.insert(tk.END, "Found devices:\n")
            for device in devices:
                ip = device['ip']
                mac = device['mac']
                self.scan_results.insert(tk.END, f"IP: {ip}, MAC: {mac}\n")
                if is_ip_reachable(ip):
                    open_ports = scan_ports(ip)
                    if open_ports:
                        self.scan_results.insert(tk.END, f"Open ports on {ip}: {open_ports}\n")
                    else:
                        self.scan_results.insert(tk.END, f"No open ports found on {ip}.\n")
        else:
            self.scan_results.insert(tk.END, "No devices found.\n")

def is_ip_reachable(ip):
    try:
        socket.create_connection((ip, 80), timeout=2)
        return True
    except OSError:
        return False

def scan_ports(ip):
    open_ports = []
    for port in range(1, 1025):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
    return open_ports

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberPulseApp(root)
    root.mainloop()
