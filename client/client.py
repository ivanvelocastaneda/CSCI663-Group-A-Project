import socket
import rsa
import os
import datetime
import random
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

p = 23
g = 5

def generate_dh_keys():
    private_key = random.randint(1, p - 2)
    public_key = pow(g, private_key, p)
    return private_key, public_key

def calculate_shared_key(other_public_key, private_key):
    return pow(other_public_key, private_key, p)

class MessagingClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Encrypted Messaging Client")

        self.message_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, state='disabled', height=15, width=50)
        self.message_area.pack(pady=10)

        self.input_area = tk.Entry(master, width=50)
        self.input_area.pack(pady=10)

        self.send_button = tk.Button(master, text="Send", command=self.send_message)
        self.send_button.pack()

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect_to_server()

        self.client_private_dh, self.client_public_dh = generate_dh_keys()

        self.server_public_dh = int(self.client_socket.recv(1024).decode())
        self.client_socket.send(str(self.client_public_dh).encode())

        self.shared_key = calculate_shared_key(self.server_public_dh, self.client_private_dh)

        public_key_data = self.client_socket.recv(1024)
        self.public_key = rsa.PublicKey.load_pkcs1(public_key_data)

        self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receive_thread.start()

    def connect_to_server(self):
        try:
            self.client_socket.connect(('127.0.0.1', 9999))
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            self.master.quit()

    def send_message(self):
        message = self.input_area.get()
        if message.strip():
            try:
                encrypted_message = rsa.encrypt(message.encode('utf-8'), self.public_key)
                self.client_socket.send(encrypted_message)

                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.display_message(f"[{timestamp}] Sent: {message}")

                self.input_area.delete(0, tk.END)
                ack = self.client_socket.recv(1024)
                if ack != b'ACK':
                    self.display_message("Acknowledgment not received.")
            except Exception as e:
                messagebox.showerror("Encryption Error", str(e))

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)
                if not encrypted_message:
                    break
                if encrypted_message == b'exit':
                    break

                decrypted_message = rsa.decrypt(encrypted_message, self.private_key)
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.display_message(f"[{timestamp}] Received: {decrypted_message.decode('utf-8')}")

                self.client_socket.send(b'ACK')
            except Exception as e:
                messagebox.showerror("Receiving Error", str(e))
                break

        self.client_socket.close()

    def display_message(self, message):
        self.message_area.configure(state='normal')
        self.message_area.insert(tk.END, message + "\n")
        self.message_area.configure(state='disabled')
        self.message_area.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    client = MessagingClient(root)
    root.mainloop()
