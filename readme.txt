Python Password Manager

A simple and secure password manager application built with Python. This program allows users to securely store, retrieve, and manage their passwords using encryption.

Features:
- User Registration and Login: Supports multiple user accounts with password protection.
- Password Storage: Store passwords securely with encryption.
- Password Retrieval: View stored passwords.
- Password Deletion: Remove stored passwords.
- Password Strength Validation: Enforces strong passwords with minimum length and complexity requirements.
- Secure Encryption: Uses the cryptography library for secure encryption.

Prerequisites:
1. Python: Ensure Python is installed on your system.
   - You can download it from https://www.python.org/downloads/.

2. cryptography Library: This project uses the cryptography library for encryption.
   - Install it using pip (see installation instructions below).

Installation:
1. Clone or Download the Project
   Download the project files or clone the repository:
   git clone <repository-url>
   cd <project-directory>

2. Install Required Python Libraries
   Ensure you have pip installed. Then install the required libraries:
   pip install cryptography

Running the Program:
1. Navigate to the Project Directory:
   Open a Command Prompt or Terminal window and navigate to the project directory where the password_manager.py file is located:
   cd /path/to/your/project

2. Run the Python Script:
   Execute the Python script using the following command:
   python password_manager.py
   For Python 3, use:
   python3 password_manager.py

3. Follow the Prompts:
   - Register a new user or log in with an existing account.
   - Use the provided menu to add, view, or delete passwords.
   - Follow the prompts to manage your passwords.

File Structure:
- password_manager.py: Main Python script containing the application logic.
- users.txt: Stores user credentials (username and hashed password).
- passwords.txt: Stores encrypted passwords for different services.
- secret.key: Stores the encryption key used for encrypting and decrypting passwords.

Basics of the Code:
This Python Password Manager project utilizes the `cryptography` library to securely manage and encrypt user passwords. The core functionality includes user registration, password storage, retrieval, and deletion. User credentials and encrypted passwords are stored in text files, with sensitive data protected by AES encryption. The `cryptography` library is a comprehensive and robust Python library used for encryption and cryptographic operations. It provides simple and secure ways to handle encryption and decryption with advanced algorithms, ensuring that all password data remains confidential. The code employs hashing for user passwords to secure them and relies on `cryptography` to handle encryption of the stored passwords. The program interacts with users through a command-line interface, providing an effective way to manage their passwords while maintaining high security.

Notes:
- The program will automatically create users.txt, passwords.txt, and secret.key files if they do not exist.
- Ensure that you keep your encryption key (secret.key) secure. If lost, you will not be able to decrypt your stored passwords.


Contributing:
Feel free to contribute to the project by submitting issues, feature requests, or pull requests.

Scope of improvement:
Implement advanced password strength requirements, such as checking for common password patterns, and enforcing complexity rules beyond just length and character diversity.
