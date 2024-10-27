import socket
import rsa
import os
import time
import datetime  # Import datetime module
import random  # For generating Diffie-Hellman keys

# Diffie-Hellman parameters
p = 23  # Prime number (use a larger prime for actual use)
g = 5   # Primitive root modulo p

# Function to generate private-public key pair for Diffie-Hellman
def generate_dh_keys():
    private_key = random.randint(1, p - 2)  # Generate a private key
    public_key = pow(g, private_key, p)     # Compute corresponding public key
    return private_key, public_key

# Function to calculate shared Diffie-Hellman key
def calculate_shared_key(other_public_key, private_key):
    return pow(other_public_key, private_key, p)

def clear_console():
    # Clear the console for a cleaner user interface
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 9999))

    # Generate Diffie-Hellman key pair for the client
    client_private_dh, client_public_dh = generate_dh_keys()

    # Receive the server's Diffie-Hellman public key and send the client's public key
    server_public_dh = int(client_socket.recv(1024).decode())
    client_socket.send(str(client_public_dh).encode())

    # Calculate the shared session key using Diffie-Hellman
    shared_key = calculate_shared_key(server_public_dh, client_private_dh)
    print(f"Established shared Diffie-Hellman key with the server: {shared_key}")

    # Receive the RSA public key from the server
    public_key_data = client_socket.recv(1024)
    public_key = rsa.PublicKey.load_pkcs1(public_key_data)
    print("Received RSA public key from server.")

    message_history = []  # Initialize message history

    try:
        while True:
            clear_console()  # Clear the console each time for a fresh look
            print("Message History:", message_history)  # Display message history
            
            # Get user input
            message = input("Enter message (type 'exit' to close): ")
            if message == 'exit':
                client_socket.send(b'exit')  # Send exit signal
                break
            if not message.strip():  # Check for empty message
                print("Empty message. Please enter a valid message.")
                time.sleep(2)  # Pause for 2 seconds to allow the user to see the message
                continue

            try:
                # Encrypt the message using the public key
                encrypted_message = rsa.encrypt(message.encode('utf-8'), public_key)
                print("Sent encrypted message.")
                client_socket.send(encrypted_message)

                # Update message history with timestamp
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                message_history.append(f"[{timestamp}] Sent: {message}")

                
            except Exception as e:
                print("Error during encryption:", e)
    except KeyboardInterrupt:
        print("Client terminated manually.")
    finally:
        client_socket.close()
        print("Client has been disconnected.")

if __name__ == "__main__":
    main()
