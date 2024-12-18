import socket
import rsa
import threading
import os
import datetime
import random

# Define static parameters for Diffie-Hellman
p = 23  # A prime number used in the Diffie-Hellman key exchange
g = 5   # A generator used in the Diffie-Hellman key exchange

def generate_dh_keys():
    # Generate private and public keys for Diffie-Hellman
    private_key = random.randint(1, p - 2)  # Private key is a random number
    public_key = pow(g, private_key, p)      # Public key is g^private_key mod p
    return private_key, public_key
  
def calculate_shared_key(other_public_key, private_key):
    # Calculate the shared key using the other party's public key and the server's private key
    return pow(other_public_key, private_key, p)

def rsa_decrypt(encrypted_message: bytes, private_key: rsa.PrivateKey) -> str:
    # Decrypt an encrypted message using the RSA private key
    decrypted_message = rsa.decrypt(encrypted_message, private_key)
    return decrypted_message.decode('utf-8')

def load_or_generate_keys(private_key_path: str = 'private_key.pem', public_key_path: str = 'public_key.pem'):
    # Load existing RSA keys or generate new ones if they do not exist
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        with open(private_key_path, 'rb') as key_file:
            private_key_data = key_file.read()
        private_key = rsa.PrivateKey.load_pkcs1(private_key_data)
        
        with open(public_key_path, 'rb') as key_file:
            public_key_data = key_file.read()
        public_key = rsa.PublicKey.load_pkcs1(public_key_data)
    else:
        # Generate new RSA keys
        public_key, private_key = rsa.newkeys(512)
        
        # Save the generated keys to files
        with open(private_key_path, 'wb') as key_file:
            key_file.write(private_key.save_pkcs1())
        with open(public_key_path, 'wb') as key_file:
            key_file.write(public_key.save_pkcs1())
    
    return public_key, private_key

def handle_client(client_socket, addr, private_key, public_key, message_history):
    # Handle communication with a connected client
    print(f"New connection from {addr}")

    # Generate Diffie-Hellman keys for the server
    server_private_dh, server_public_dh = generate_dh_keys()
    client_socket.send(str(server_public_dh).encode())  # Send server's public key to client
    
    # Receive client's public key
    client_public_dh = int(client_socket.recv(1024).decode())
    # Calculate the shared key
    shared_key = calculate_shared_key(client_public_dh, server_private_dh)  
    print(f"Shared DH Key with {addr}: {shared_key}")

    # Send the server's RSA public key to the client
    client_socket.send(public_key.save_pkcs1())  

    try:
        while True:
            # Receive encrypted message from the client
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                print(f"No data received, closing connection with {addr}")
                break

            if encrypted_message == b'exit':
                print(f"Client {addr} requested to close the connection.")
                break
            
            # Decrypt the received message
            decrypted_message = rsa_decrypt(encrypted_message, private_key)
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] Received and decrypted message: {decrypted_message}")
            
            # Append the message to the history
            message_history.append(f"[{timestamp}] From {addr}: {decrypted_message}")
            print("Message History:", message_history)
            
            # Send acknowledgment back to client
            client_socket.send(b'ACK')

    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        client_socket.close()  # Close the client socket
        print(f"Connection with {addr} closed.")

def start_server():
    # Start the server and listen for incoming connections
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 9999))  # Bind to localhost on port 9999
    server_socket.listen(5)  # Allow up to 5 connections
    print("Server is listening on 127.0.0.1:9999...")

    # Load or generate RSA keys
    public_key, private_key = load_or_generate_keys()
    message_history = []  # List to store message history

    try:
        while True:
            # Accept a new client connection
            client_socket, addr = server_socket.accept()
            # Start a new thread to handle the client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, addr, private_key, public_key, message_history))
            client_thread.start()
    except KeyboardInterrupt:
        print("Shutting down the server gracefully...")
    finally:
        server_socket.close()  # Close the server socket
        print("Server has been shut down.")

if __name__ == "__main__":
    start_server()  # Start the server when the script is executed