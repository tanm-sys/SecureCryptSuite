---

# SecureCrypt - First Release  

## Overview  
SecureCrypt is a high-security encryption suite designed for developers and organizations that require strong cryptographic protection. It leverages **RSA encryption**, **Argon2 password hashing**, and **Hardware Security Modules (HSMs)** for maximum security. The suite includes both a **command-line interface (CLI) for automation** and an optional **configuration file** for custom settings.  

## Key Techniques Used  
- **Asynchronous and Multi-threaded Execution** – Optimized performance for encryption operations.  
- **Secure Memory Management** – Prevents sensitive data leaks by automatically wiping memory after use.  
- **Tamper-Proof Logging** – Encrypts logs to prevent unauthorized modifications.  
- **Secure Key Storage** – Uses **HSMs** and **OS-level key stores** for private key protection.  
- **Clipboard Auto-Clear** – Prevents sensitive data exposure.  
- **Digital Signature Support** – Verifies message integrity using cryptographic signing.  
- **Customizable CLI Mode** – Allows for batch processing and automation.  

## Libraries & Technologies  
This project uses several non-obvious but powerful libraries:  
- **[cryptography](https://cryptography.io/en/latest/)** – Provides RSA encryption, digital signatures, and secure key handling.  
- **[Argon2-CFFI](https://argon2-cffi.readthedocs.io/en/stable/)** – Implements the Argon2 key derivation function for password security.  
- **[PyHSM](https://pypi.org/project/pyhsm/)** – Enables interaction with hardware security modules.  
- **[loguru](https://loguru.readthedocs.io/en/stable/)** – Provides structured, encrypted logging for security compliance.  

## Project Structure  
```plaintext
SecureCrypt/
│── main.py          # Main application containing encryption logic and CLI
│── config.json      # Customizable settings for encryption and security
│── requirements.txt # Dependency list for Python package installation
│── README.md        # Project documentation
│── LICENSE          # Open-source license information
```
### Notable Files  
- **main.py** – Contains the entire encryption logic, including CLI operations.  
- **config.json** – Allows users to customize security settings, key storage, and logging behavior.  

## Installation & Usage  
### Install Dependencies  
```bash
pip install -r requirements.txt
```
### Run the Application  
```bash
python main.py
```
### Use the CLI for Encryption  
```bash
python main.py --encrypt --file message.txt --key public.pem
```
### Modify Configuration  
Customize security settings in [`config.json`](./config.json).  

---
