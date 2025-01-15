import tkinter as tk
from tkinter import ttk
from tkinter import PhotoImage
from src.cyber_pulse_app import CyberPulseApp


if __name__ == "__main__":
    root = tk.Tk()
    app = CyberPulseApp(root)
    root.mainloop()
