import socket
import rsa
import os
import datetime
import random
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

# Define static parameters for Diffie-Hellman
p = 23  # Prime number
g = 5   # Generator

def generate_dh_keys():
    # Generate private and public keys for Diffie-Hellman
    private_key = random.randint(1, p - 2)  # Private key is a random number
    public_key = pow(g, private_key, p)      # Public key is g^private_key mod p
    return private_key, public_key

def calculate_shared_key(other_public_key, private_key):
    # Calculate the shared key using the other party's public key and the client's private key
    return pow(other_public_key, private_key, p)

class MessagingClient:
    def __init__(self, master):
        # Initialize the messaging client GUI
        self.master = master
        self.master.title("Encrypted Messaging Client")

        # Create a text area for displaying messages
        self.message_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, state='disabled', height=15, width=50)
        self.message_area.pack(pady=10)

        # Create an input area for user to type messages
        self.input_area = tk.Entry(master, width=50)
        self.input_area.pack(pady=10)

        # Create a button to send messages
        self.send_button = tk.Button(master, text="Send", command=self.send_message)
        self.send_button.pack()

        # Set up the client socket
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.settimeout(5)  # Set a timeout of 5 seconds
        self.connect_to_server()

        # Generate Diffie-Hellman keys
        self.client_private_dh, self.client_public_dh = generate_dh_keys()

        # Receive server's public key and send client's public key
        self.server_public_dh = int(self.client_socket.recv(1024).decode())
        self.client_socket.send(str(self.client_public_dh).encode())

        # Calculate the shared key
        self.shared_key = calculate_shared_key(self.server_public_dh, self.client_private_dh)

        # Receive the server's RSA public key
        public_key_data = self.client_socket.recv(1024)
        self.public_key = rsa.PublicKey.load_pkcs1(public_key_data)

        # Start a thread to receive messages
        self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receive_thread.start()

    def connect_to_server(self):
        # Connect to the server
        try:
            self.client_socket.connect(('127.0.0.1', 9999))
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            self.master.quit()

    def send_message(self):
        # Send a message to the server
        message = self.input_area.get()
        if message.strip():  # Check if the message is not just whitespace
            if message.lower() == 'exit':
                self.client_socket.send(b'exit')
                self.client_socket.close()
                self.master.quit()  # Close the Tkinter window
                return
            try:
                # Encrypt the message using RSA
                encrypted_message = rsa.encrypt(message.encode('utf-8'), self.public_key)
                self.client_socket.send(encrypted_message)

                # Display the sent message with a timestamp
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.display_message(f"[{timestamp}] Sent: {message}")

                self.input_area.delete(0, tk.END)  # Clear the input area
                ack = self.client_socket.recv(1024)  # Wait for acknowledgment
                if ack != b'ACK':
                    self.display_message("Acknowledgment not received.")
            except Exception as e:
                messagebox.showerror("Encryption Error", str(e))
        else:
            messagebox.showwarning("Input Error", "Message cannot be empty.")

    def receive_messages(self):
        # Continuously receive messages from the server
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)
                if not encrypted_message:
                    break
                if encrypted_message == b'exit':
                    break

                # Decrypt the received message
                decrypted_message = rsa.decrypt(encrypted_message, self.private_key)
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.display_message(f"[{timestamp}] Received: {decrypted_message.decode('utf-8')}")

                # Send acknowledgment back to the server
                self.client_socket.send(b'ACK')
            except socket.timeout:
                continue  # # Ignore timeout exceptions and continue receiving messages
            except Exception as e:
                messagebox.showerror("Receiving Error", str(e))
                break

    def display_message(self, message):
        # Display a message in the text area
        self.message_area.config(state='normal')  # Enable editing
        self.message_area.insert(tk.END, message + '\n')  # Insert the message
        self.message_area.config(state='disabled')  # Disable editing
        self.message_area.yview(tk.END)  # Scroll to the end

if __name__ == "__main__":
    root = tk.Tk()
    client = MessagingClient(root)
    root.mainloop()