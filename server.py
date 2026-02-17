import socket
import threading
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

HOST = '127.0.0.1'
PORT = 5000

KEY = b'ThisIsA32ByteLongSharedSecretKey!!'  # 32 bytes

clients = []

def encrypt_message(message):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext

def decrypt_message(data):
    iv = data[:16]
    ciphertext = data[16:]

    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()

    return message.decode()

def log_message(encrypted_msg):
    with open("chat_log.enc", "ab") as f:
        f.write(encrypted_msg + b'\n')

def broadcast(message, sender):
    for client in clients:
        if client != sender:
            client.send(message)

def handle_client(client_socket):
    while True:
        try:
            encrypted_msg = client_socket.recv(4096)
            if not encrypted_msg:
                break

            log_message(encrypted_msg)
            message = decrypt_message(encrypted_msg)
            print("Received:", message)

            encrypted_broadcast = encrypt_message(message)
            broadcast(encrypted_broadcast, client_socket)

        except:
            break

    clients.remove(client_socket)
    client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    print(f"Server running on {HOST}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        print("Connected:", addr)
        clients.append(client_socket)

        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()

start_server()