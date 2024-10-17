import socket
import rsa
import signal
import sys

def rsa_decrypt(encrypted_message, private_key):
    try:
        # Attempt to decrypt the message
        message_bytes = rsa.decrypt(encrypted_message, private_key)
        return message_bytes.decode('utf-8')
    except Exception as e:
        print("Decryption failed:", e)
        return None

def handle_client(client_socket, rsa_private_key):
    try:
        while True:
            # Receive the encrypted message
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                print("No data received, closing connection.")
                break

            print("Received encrypted message.")

            # Decrypt the message
            decrypted_message = rsa_decrypt(encrypted_message, rsa_private_key)
            if decrypted_message is not None:
                if decrypted_message.strip():  # Check for non-empty decrypted message
                    print("Received and decrypted message:", decrypted_message)
                else:
                    print("Received empty message after decryption.")
            else:
                print("Failed to decrypt message.")

    finally:
        print("Closing client connection...")
        client_socket.close()

def signal_handler(sig, frame):
    print("Shutting down the server gracefully...")
    sys.exit(0)

def main():
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)

    # Generate RSA keys
    (public_key, private_key) = rsa.newkeys(512)

    # Create a TCP socket and listen for connections
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 9999))
    server_socket.listen(1)

    print("Server is listening on 127.0.0.1:9999...")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"New connection from {addr}")

        # Send public key to the client
        public_key_data = public_key.save_pkcs1()
        client_socket.send(public_key_data)
        print("Sent RSA public key to the client.")

        handle_client(client_socket, private_key)

if __name__ == "__main__":
    main()
