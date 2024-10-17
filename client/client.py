import socket
import rsa

def main():
    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 9999))

    # Receive the RSA public key from the server
    public_key_data = client_socket.recv(1024)
    public_key = rsa.PublicKey.load_pkcs1(public_key_data)
    print("Received RSA public key from server.")

    while True:
        # Get user input
        message = input("Enter message (type 'exit' to close): ")
        if message == 'exit':
            client_socket.close()  # Close the socket before exiting
            break
        if not message.strip():  # Check for empty message
            print("Empty message. Please enter a valid message.")
            continue
        
        try:
            # Encrypt the message using the public key
            encrypted_message = rsa.encrypt(message.encode('utf-8'), public_key)
            print("Sent encrypted message.")
            client_socket.send(encrypted_message)
        except Exception as e:
            print("Error during encryption:", e)

if __name__ == "__main__":
    main()
