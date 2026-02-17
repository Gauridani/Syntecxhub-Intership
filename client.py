import socket
import threading
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

HOST = '127.0.0.1'
PORT = 5000

KEY = b'ThisIsA32ByteLongSharedSecretKey!!'  # Same key as server

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

def receive_messages(client):
    while True:
        try:
            encrypted_msg = client.recv(4096)
            message = decrypt_message(encrypted_msg)
            print("\nFriend:", message)
        except:
            break

def send_messages(client):
    while True:
        msg = input()
        encrypted_msg = encrypt_message(msg)
        client.send(encrypted_msg)

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    print("Connected to secure chat")

    threading.Thread(target=receive_messages, args=(client,), daemon=True).start()
    send_messages(client)

start_client()