import socket
import threading
import tkinter as tk
from tkinter import messagebox

class PortScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Port Scanner")

        self.label_ip = tk.Label(master, text="Target IP:")
        self.label_ip.grid(row=0, column=0, sticky="e")

        self.entry_ip = tk.Entry(master)
        self.entry_ip.grid(row=0, column=1)

        self.label_start = tk.Label(master, text="Start Port:")
        self.label_start.grid(row=1, column=0, sticky="e")

        self.entry_start = tk.Entry(master)
        self.entry_start.grid(row=1, column=1)

        self.label_end = tk.Label(master, text="End Port:")
        self.label_end.grid(row=2, column=0, sticky="e")

        self.entry_end = tk.Entry(master)
        self.entry_end.grid(row=2, column=1)

        self.scan_button = tk.Button(master, text="Scan", command=self.scan_ports)
        self.scan_button.grid(row=3, columnspan=2)

    def scan_ports(self):
        target = self.entry_ip.get()
        start_port = self.entry_start.get()
        end_port = self.entry_end.get()

        # Validate input
        try:
            start_port = int(start_port)
            end_port = int(end_port)
            if not (0 < start_port <= end_port <= 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Invalid port range.")
            return

        # Clear any previous results
        for widget in self.master.winfo_children():
            widget.destroy()

        self.label_scanning = tk.Label(self.master, text="Scanning...")
        self.label_scanning.grid(row=0, columnspan=2)

        self.result_text = tk.Text(self.master, wrap=tk.WORD, width=50, height=10)
        self.result_text.grid(row=1, columnspan=2)

        # Scan ports in a separate thread to prevent GUI freezing
        threading.Thread(target=self.perform_scan, args=(target, start_port, end_port)).start()

    def perform_scan(self, target, start_port, end_port):
        result_text = ""
        for port in range(start_port, end_port + 1):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)  # Timeout in seconds
                result = s.connect_ex((target, port))
                if result == 0:
                    result_text += f"Port {port}: OPEN\n"
                s.close()
            except Exception as e:
                result_text += f"Error scanning port {port}: {e}\n"

        # Update GUI with scan results
        self.master.after(0, self.update_results, result_text)

    def update_results(self, result_text):
        self.label_scanning.destroy()
        self.result_text.insert(tk.END, result_text)

def main():
    root = tk.Tk()
    gui = PortScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
