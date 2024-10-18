import socket
import rsa
import threading
import os
import datetime  # Import datetime module

# Function to decrypt the received message
def rsa_decrypt(encrypted_message: bytes, private_key: rsa.PrivateKey) -> str:
    decrypted_message = rsa.decrypt(encrypted_message, private_key)
    return decrypted_message.decode('utf-8')

# Function to load or generate private key
def load_or_generate_keys(private_key_path: str = 'private_key.pem', public_key_path: str = 'public_key.pem'):
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        # Load existing keys
        with open(private_key_path, 'rb') as key_file:
            private_key_data = key_file.read()
        private_key = rsa.PrivateKey.load_pkcs1(private_key_data)
        
        with open(public_key_path, 'rb') as key_file:
            public_key_data = key_file.read()
        public_key = rsa.PublicKey.load_pkcs1(public_key_data)
    else:
        # Generate new key pair if files don't exist
        public_key, private_key = rsa.newkeys(512)
        
        # Save the keys to files
        with open(private_key_path, 'wb') as key_file:
            key_file.write(private_key.save_pkcs1())
        with open(public_key_path, 'wb') as key_file:
            key_file.write(public_key.save_pkcs1())
    
    return public_key, private_key

# Function to handle each client connection
def handle_client(client_socket, addr, private_key, public_key, message_history):
    print(f"New connection from {addr}")
    client_socket.send(public_key.save_pkcs1())  # Send the public key to the client
    
    try:
        while True:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                print(f"No data received, closing connection with {addr}")
                break  # If no message is received, close the connection

            # Check for the exit command
            if encrypted_message == b'exit':
                print(f"Client {addr} requested to close the connection.")
                break
            
            decrypted_message = rsa_decrypt(encrypted_message, private_key)
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get current timestamp
            print(f"[{timestamp}] Received and decrypted message: {decrypted_message}")
            
            # Update message history with timestamp
            message_history.append(f"[{timestamp}] From {addr}: {decrypted_message}")
            print("Message History:", message_history)
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        client_socket.close()
        print(f"Connection with {addr} closed.")

# Function to start the server and handle clients
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 9999))
    server_socket.listen(5)
    print("Server is listening on 127.0.0.1:9999...")

    # Load or generate RSA keys
    public_key, private_key = load_or_generate_keys()
    
    message_history = []  # Initialize message history

    try:
        while True:
            client_socket, addr = server_socket.accept()
            # Handle client in a new thread for concurrent connections
            client_thread = threading.Thread(target=handle_client, args=(client_socket, addr, private_key, public_key, message_history))
            client_thread.start()
    except KeyboardInterrupt:
        print("Shutting down the server gracefully...")
    finally:
        server_socket.close()
        print("Server has been shut down.")

if __name__ == "__main__":
    start_server()
