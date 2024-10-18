import socket
import rsa
import os
import time
import datetime  # Import datetime module

def clear_console():
    # Clear the console for a cleaner user interface
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 9999))

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
