import socket
import rsa
import os
import time
import datetime
import random

p = 23  
g = 5   

def generate_dh_keys():
    private_key = random.randint(1, p - 2)  
    public_key = pow(g, private_key, p)     
    return private_key, public_key

def calculate_shared_key(other_public_key, private_key):
    return pow(other_public_key, private_key, p)

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 9999))

    client_private_dh, client_public_dh = generate_dh_keys()

    server_public_dh = int(client_socket.recv(1024).decode())
    client_socket.send(str(client_public_dh).encode())

    shared_key = calculate_shared_key(server_public_dh, client_private_dh)
    print(f"Established shared Diffie-Hellman key with the server: {shared_key}")

    public_key_data = client_socket.recv(1024)
    public_key = rsa.PublicKey.load_pkcs1(public_key_data)
    print("Received RSA public key from server.")

    message_history = []

    try:
        while True:
            clear_console()
            print("Message History:", message_history)
            
            message = input("Enter message (type 'exit' to close): ")
            if message == 'exit':
                client_socket.send(b'exit')  
                break
            if not message.strip():
                print("Empty message. Please enter a valid message.")
                time.sleep(2)
                continue

            try:
                encrypted_message = rsa.encrypt(message.encode('utf-8'), public_key)
                client_socket.send(encrypted_message)

                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                message_history.append(f"[{timestamp}] Sent: {message}")

                # Wait for acknowledgment from the server
                ack = client_socket.recv(1024)
                if ack == b'ACK':
                    print("Message acknowledged by server.")
                else:
                    print("Acknowledgment not received.")

            except Exception as e:
                print("Error during encryption:", e)
    except KeyboardInterrupt:
        print("Client terminated manually.")
    finally:
        client_socket.close()
        print("Client has been disconnected.")

if __name__ == "__main__":
    main()
