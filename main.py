import tkinter as tk
from tkinter import scrolledtext
import threading
from scapy.all import sniff, get_if_list


def list_interfaces():
    return get_if_list()


class PacketSniffer:
    def __init__(self, main):
        self.root = main
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        self.text_area = None
        self.stop_button = None
        self.start_button = None
        self.capture_thread = None
        self.sniffing = False
        self.selected_interface = None
        self.interfaces = list_interfaces()
        self.selected_interface = self.interfaces[0] if self.interfaces else None
        self.create_widgets()

    def create_widgets(self):
        self.start_button = tk.Button(self.root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=0, column=0, padx=10, pady=10)

        self.stop_button = tk.Button(self.root, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.grid(row=0, column=1, padx=10, pady=10)
        self.stop_button.config(state=tk.DISABLED)

        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=100, height=30)
        self.text_area.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

        self.display_interface_selection()

    def display_interface_selection(self):
        interface_label = tk.Label(self.root, text="Select Interface:")
        interface_label.grid(row=2, column=0, padx=10, pady=10)

        interface_menu = tk.StringVar(self.root)
        interface_menu.set(self.selected_interface)

        interface_option_menu = tk.OptionMenu(self.root, interface_menu, *self.interfaces,
                                              command=self.on_interface_change)
        interface_option_menu.grid(row=2, column=1, padx=10, pady=10)

    def on_interface_change(self, value):
        self.selected_interface = value

    def start_sniffing(self):
        if self.selected_interface:
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.capture_thread = threading.Thread(target=self.run_capture)
            self.capture_thread.start()

    def run_capture(self):
        sniff(iface=self.selected_interface, prn=self.process_packet, stop_filter=lambda x: not self.sniffing)

    def stop_sniffing(self):
        self.sniffing = False
        if self.capture_thread:
            self.capture_thread.join()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def process_packet(self, packet):
        self.display_packet(str(packet))

    def display_packet(self, packet):
        self.root.after(0, lambda: self.text_area.insert(tk.END, packet + '\n'))


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSniffer(root)
    root.mainloop()
