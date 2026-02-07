import os
import json
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

VAULT_FILE = "vault.enc"
SALT_FILE = "salt.bin"

# ------------------ CRYPTO UTILITIES ------------------

def generate_salt():
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    return salt

def load_salt():
    if not os.path.exists(SALT_FILE):
        return generate_salt()
    with open(SALT_FILE, "rb") as f:
        return f.read()

def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def load_fernet(master_password):
    salt = load_salt()
    key = derive_key(master_password, salt)
    return Fernet(key)

# ------------------ VAULT OPERATIONS ------------------

def load_vault(fernet):
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, "rb") as f:
        encrypted_data = f.read()
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    except:
        print("❌ Incorrect master password or corrupted vault.")
        exit()

def save_vault(fernet, vault):
    data = json.dumps(vault).encode()
    encrypted_data = fernet.encrypt(data)
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted_data)



def add_entry(vault):
    service = input("Service name: ").lower()
    username = input("Username: ")
    password = getpass.getpass("Password: ")

    vault[service] = {
        "username": username,
        "password": password
    }
    print("✅ Entry added successfully.")

def retrieve_entry(vault):
    service = input("Service name: ").lower()
    if service in vault:
        print(f"Username: {vault[service]['username']}")
        print(f"Password: {vault[service]['password']}")
    else:
        print("❌ Entry not found.")

def delete_entry(vault):
    service = input("Service name: ").lower()
    if service in vault:
        del vault[service]
        print("🗑 Entry deleted.")
    else:
        print("❌ Entry not found.")

def search_entries(vault):
    keyword = input("Search keyword: ").lower()
    results = [s for s in vault if keyword in s]
    if results:
        print("🔍 Matching services:")
        for s in results:
            print("-", s)
    else:
        print("❌ No matches found.")


def main():
    print("🔐 Secure Password Manager")
    master_password = getpass.getpass("Enter master password: ")

    fernet = load_fernet(master_password)
    vault = load_vault(fernet)

    while True:
        print("\n1. Add Password")
        print("2. Retrieve Password")
        print("3. Delete Password")
        print("4. Search Password")
        print("5. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            add_entry(vault)
        elif choice == "2":
            retrieve_entry(vault)
        elif choice == "3":
            delete_entry(vault)
        elif choice == "4":
            search_entries(vault)
        elif choice == "5":
            save_vault(fernet, vault)
            print("🔒 Vault saved. Goodbye!")
            break
        else:
            print("❌ Invalid option.")

if __name__ == "__main__":
    main()
