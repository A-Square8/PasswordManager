import os
import hashlib
from cryptography.fernet import Fernet

USERS_FILE = 'users.txt'
PASSWORDS_FILE = 'passwords.txt'
KEY_FILE = 'secret.key'
def generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, 'rb') as key_file:
            key = key_file.read()
    return Fernet(key)

def ensure_files():
    if not os.path.exists(USERS_FILE):
        open(USERS_FILE, 'w').close()
    if not os.path.exists(PASSWORDS_FILE):
        open(PASSWORDS_FILE, 'w').close()

def register_user():
    username = input("Enter a new username: ")
    with open(USERS_FILE, 'r') as f:
        for line in f:
            stored_username, _ = line.strip().split(':')
            if stored_username == username:
                print("Username already exists.")
                return False
    while True:
        password = input("Enter a new password (must be 8 characters, include numbers and special characters): ")
        if validate_password(password):
            break
        else:
            print("Weak password. Try again.")
    
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    with open(USERS_FILE, 'a') as f:
        f.write(f"{username}:{hashed_password}\n")
    print("Registration successful.")
    return True

def validate_password(password):
    if len(password) < 8 or not any(c.isdigit() for c in password) or not any(c in "!@#$%^&*()" for c in password):
        return False
    return True

def login_user():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    with open(USERS_FILE, 'r') as f:
        for line in f:
            stored_username, stored_hashed_password = line.strip().split(':')
            if stored_username == username and stored_hashed_password == hashed_password:
                print("Login successful.")
                return username, password
    print("Invalid username or password.")
    return None, None

def encrypt_data(data, fernet):
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(data, fernet):
    return fernet.decrypt(data.encode()).decode()

def add_password(username, fernet):
    service = input("Enter the service name (e.g., Gmail): ")
    service_username = input(f"Enter the username for {service}: ")
    service_password = input(f"Enter the password for {service}: ")
    data = f"{service}|{service_username}|{service_password}"
    encrypted_data = encrypt_data(data, fernet)
    with open(PASSWORDS_FILE, 'a') as f:
        f.write(f"{username}:{encrypted_data}\n")
    print("Password added successfully.")

def view_passwords(username, fernet):
    if not os.path.exists(PASSWORDS_FILE):
        print("No passwords stored.")
        return
    with open(PASSWORDS_FILE, 'r') as f:
        lines = f.readlines()
    found = False
    for line in lines:
        stored_username, encrypted_data = line.strip().split(':', 1)
        if stored_username == username:
            data = decrypt_data(encrypted_data, fernet)
            service, service_username, service_password = data.split('|')
            print(f"Service: {service}")
            print(f"Username: {service_username}")
            print(f"Password: {service_password}")
            print("-" * 20)
            found = True
    if not found:
        print("No passwords found for your account.")

def delete_password(username, fernet):
    if not os.path.exists(PASSWORDS_FILE):
        print("No passwords stored.")
        return
    with open(PASSWORDS_FILE, 'r') as f:
        lines = f.readlines()
    user_entries = []
    other_entries = []
    for line in lines:
        stored_username, encrypted_data = line.strip().split(':', 1)
        if stored_username == username:
            user_entries.append(encrypted_data)
        else:
            other_entries.append(line)
    if not user_entries:
        print("No passwords found for your account.")
        return
    print("Your stored passwords:")
    for idx, encrypted_data in enumerate(user_entries):
        data = decrypt_data(encrypted_data, fernet)
        service, service_username, _ = data.split('|')
        print(f"{idx + 1}. Service: {service}, Username: {service_username}")
    choice = input("Enter the number of the password to delete: ")
    if not choice.isdigit() or not (1 <= int(choice) <= len(user_entries)):
        print("Invalid choice.")
        return
    choice = int(choice) - 1
    del user_entries[choice]
    with open(PASSWORDS_FILE, 'w') as f:
        for entry in other_entries:
            f.write(entry)
        for encrypted_data in user_entries:
            f.write(f"{username}:{encrypted_data}\n")
    print("Password deleted successfully.")

def main():
    fernet = generate_key()
    ensure_files()

    print("Welcome to the Password Manager")
    while True:
        print("\nSelect an option:")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice: ")
        if choice == '1':
            register_user()
        elif choice == '2':
            username, password = login_user()
            if username:
                while True:
                    print("\nSelect an option:")
                    print("1. Add a new password")
                    print("2. View stored passwords")
                    print("3. Delete a password")
                    print("4. Logout")
                    user_choice = input("Enter your choice: ")
                    if user_choice == '1':
                        add_password(username, fernet)
                    elif user_choice == '2':
                        view_passwords(username, fernet)
                    elif user_choice == '3':
                        delete_password(username, fernet)
                    elif user_choice == '4':
                        print("Logging out...")
                        break
                    else:
                        print("Invalid choice.")
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice.")

if __name__ == '__main__':
    main()
