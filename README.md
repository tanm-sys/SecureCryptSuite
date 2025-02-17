# SecureCrypt - Advanced Encryption & Security Suite

## Overview
SecureCrypt is an enterprise-grade, security-hardened encryption suite designed for professionals and organizations requiring robust cryptographic protection. Leveraging RSA, Argon2, and HSM (Hardware Security Modules), SecureCrypt ensures state-of-the-art security, optimized performance, and seamless usability.

## Features
### Advanced Security
- **End-to-End Encryption**: Secure encryption and decryption using RSA with a **2048-bit minimum key length**.
- **Argon2 Key Derivation**: Best-in-class password hashing to prevent brute-force attacks.
- **HSM & Secure Storage**: Supports **Hardware Security Modules (HSM)** and OS-level key storage for maximum protection.
- **Memory Protection**: Sensitive data is automatically **zeroized after use** to prevent memory scraping.
- **Secure Clipboard Handling**: Clipboard auto-clear feature to **prevent data exposure**.
- **Input & File Sanitization**: Protects against **injection attacks** and unauthorized file access.
- **Tamper-Proof Logging**: **Encrypted logs** with strict permissions prevent unauthorized access.
- **Digital Signature Support**: Provides **signing and verification** to ensure data integrity.
- **Quantum-Resistant Cryptography (Upcoming)**: Preparing for post-quantum security measures.

### Performance & Usability
- **Asynchronous & Multi-threaded Execution**: Ensures high-speed operations and responsive UI.
- **Adaptive RSA Message Sizing**: Dynamically calculates max message size based on key length.
- **Cross-Platform Compatibility**: Runs on **Windows, macOS, and Linux** without modification.
- **Modern & Intuitive GUI**: User-friendly interface with **dark mode support**.
- **Command-Line Interface (CLI)**: Headless operation for automation and scripting.

## Installation
### Prerequisites
Ensure you have **Python 3.8+** installed. Then, install the required dependencies:

```bash
pip install -r requirements.txt
```

For Linux users, install Tkinter if not already installed:

```bash
sudo apt-get install python3-tk
```

## Usage
### Running SecureCrypt
1. **Start the Application**:
   ```bash
   python main.py
   ```
2. **Generate or Import RSA Keys**:
   - Supports key import with **automated validity checks**.
   - Ensures compliance with **security best practices**.
3. **Encrypt & Decrypt Messages**:
   - Encrypt messages using a **public key**.
   - Securely decrypt messages using a **private key**.
   - **Sign & Verify Digital Signatures**.
4. **CLI Mode** (for power users & automation):
   - **Encryption**:
     ```bash
     python main.py --encrypt --file message.txt --key public.pem
     ```
   - **Decryption**:
     ```bash
     python main.py --decrypt --file encrypted.txt --key private.pem
     ```
   - **Generate Keys**:
     ```bash
     python main.py --generate-keys --keysize 4096 --output keys/
     ```
   - **Signing & Verification**:
     ```bash
     python main.py --sign --file document.txt --key private.pem
     python main.py --verify --file document.txt --signature document.sig --key public.pem
     ```
   
### CLI Mode (for Power Users & Automation)
SecureCrypt includes an advanced command-line interface for automation, scripting, and headless operation. The CLI supports various options for encryption, decryption, key management, and digital signatures. 

#### CLI Configuration & Customization
To configure CLI behavior, modify `config.json`. This file allows users to customize settings such as:
- **Logging levels** (DEBUG, INFO, WARNING, ERROR)
- **Key storage options** (HSM, local encryption, file-based storage)
- **Clipboard auto-clear timeout**
- **Default encryption algorithm and padding scheme**
- **Threading and performance optimizations**

Example `config.json`:
```json
{
  "log_level": "INFO",
  "key_storage": "HSM",
  "clipboard_timeout": 10,
  "default_algorithm": "RSA-OAEP",
  "threading": true
}
```

### Security Best Practices
- **Enable HSM for Key Storage**: Prevents key leakage by using **OS-level key protection**.
- **Use Strong Passwords**: Enforce long, unique passphrases for key protection.
- **Rotate Keys Periodically**: Avoid long-term exposure of cryptographic material.
- **Keep Dependencies Updated**: Regular updates ensure protection from known vulnerabilities.
- **Restrict Access to Log Files**: Prevent unauthorized data leakage from logs.

## API & Integration
SecureCrypt provides an **API for developers** to integrate encryption into their applications.

```python
from securecrypt import SecureCrypt
crypto = SecureCrypt()
encrypted_data = crypto.encrypt("Hello World", "public.pem")
```

## Contributing
We welcome contributions from security experts and developers:
1. Fork the repository.
2. Create a new feature branch.
3. Implement improvements, ensuring adherence to security best practices.
4. Submit a pull request with **detailed documentation**.

## License
SecureCrypt is licensed under the **MIT License**. See `LICENSE` for full details.

## Contact & Support
For security reports, feature requests, or enterprise support:
- **GitHub Issues**: Open a ticket on the repository.
- **Email**: Contact our security team at `security@securecrypt.com`.
- **Discord Community**: Join discussions with experts and contributors.

## Acknowledgments
Special thanks to **security researchers, cryptographers, and contributors** for their valuable insights in cryptographic best practices and secure software development.

