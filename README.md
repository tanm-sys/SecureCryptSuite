# 🔐 SecureCrypt – Enterprise-Grade Encryption & Security Suite

> **Unparalleled Security | Military-Grade Encryption | Enterprise-Level Compliance**

![SecureCrypt](flowchart.svg)

SecureCrypt is a cutting-edge, enterprise-class encryption suite engineered for professionals, businesses, and government entities requiring **state-of-the-art cryptographic security**. By integrating **RSA and AES encryption**, **Argon2 key derivation**, **tamper-proof logging**, and **HSM (Hardware Security Module) support**, SecureCrypt ensures the highest level of **data integrity, confidentiality, and authentication**.

---

## 🛤️ User Journey

![User Journey](user_journey.svg)

---

## 🚀 Key Features & Innovations

### 🛡️ **Military-Grade Security & Compliance**
✅ **AES-256 & RSA-4096 Hybrid Encryption** – Combining the strongest symmetric and asymmetric encryption standards.  
✅ **Argon2 Key Derivation** – Industry-leading password hashing to prevent brute-force attacks.  
✅ **Multi-Factor Secure Key Storage** – OS-level security and HSM integration for advanced key protection.  
✅ **Quantum-Resistant Roadmap** – Designed with future cryptographic advancements in mind.  
✅ **Digital Signatures & Verification** – RSA-based cryptographic signing to validate file integrity.  
✅ **Tamper-Proof Logging** – Secure, immutable, encrypted log storage ensuring audit traceability.  

### ⚡ **Performance & Optimization**
✅ **Asynchronous, Multi-threaded Processing** – Ensuring encryption & key generation do not block UI operations.  
✅ **Adaptive RSA Message Sizing** – Smart memory allocation for efficient encryption.  
✅ **Cross-Platform Compatibility** – Runs seamlessly on **Windows, macOS, and Linux**.  
✅ **Customizable Security Policies via `config.json`** – Enterprise-grade flexibility.  
✅ **Dual-Mode Support** – **Graphical User Interface (GUI)** and **Command-Line Interface (CLI)**.  

---

## 🛠️ Technologies & Libraries

| Library | Purpose | Documentation |
|---------|---------|--------------|
| **[cryptography](https://cryptography.io/en/latest/)** | RSA, AES encryption, key management | [Docs](https://cryptography.io) |
| **[Argon2-CFFI](https://argon2-cffi.readthedocs.io/en/stable/)** | Secure password hashing | [Docs](https://argon2-cffi.readthedocs.io) |
| **[PyHSM](https://pypi.org/project/pyhsm/)** | Hardware Security Module (HSM) support | [Docs](https://pypi.org/project/pyhsm/) |
| **[loguru](https://loguru.readthedocs.io/en/stable/)** | Structured, encrypted logging | [Docs](https://loguru.readthedocs.io) |
| **[tkinter](https://docs.python.org/3/library/tkinter.html)** | Graphical User Interface (GUI) | [Docs](https://docs.python.org/3/library/tkinter.html) |

---

## 📂 Project Structure

```plaintext
SecureCrypt/
│── main.py          # Core encryption engine, CLI, and GUI
│── config.json      # Customizable security, logging, and key storage settings
│── requirements.txt # Dependencies for installation
│── README.md        # Documentation (this file)
│── LICENSE          # Open-source license info
│── app.log          # Secure, encrypted logging file
│── user_journey.svg # Visual representation of the user workflow
```

### 📌 **Key Files Explained**
🔹 [`main.py`](./main.py) – **Core logic handling encryption, CLI commands, and GUI operations**.  
🔹 [`config.json`](./config.json) – **Adjust security parameters, key storage, and logging settings**.  
🔹 `app.log` – **Immutable encrypted log file for security audits**.  
🔹 [`user_journey.svg`](./user_journey.svg) – **Graphical representation of the user workflow in SecureCrypt**.  

---

## 🚀 Installation & Quickstart

### 🔧 **1. Install Dependencies**
```bash
pip install -r requirements.txt
```

### 🔑 **2. Generate Encryption Keys**
```bash
openssl genrsa -out private.pem 4096
openssl rsa -in private.pem -pubout -out public.pem
```

### 🔐 **3. Encrypt a File via CLI**
```bash
python main.py --encrypt --file secret.txt --key public.pem
```

### 🔓 **4. Decrypt Data**
```bash
python main.py --decrypt --file secret.enc --key private.pem
```

### 🖥️ **5. Launch the Graphical User Interface (GUI)**
```bash
python main.py --gui
```
🔹 **Note:** Ensure `tkinter` is installed on your system. For installation guidance, refer to the [Tkinter documentation](https://docs.python.org/3/library/tkinter.html).  

### 🛠 **6. Customize Security Settings via `config.json`**
```json
{
    "logging_level": "INFO",
    "hsm_enabled": true,
    "clipboard_timeout": 10,
    "encryption_algorithm": "RSA-4096"
}
```

---

## 🏆 Best Practices for Maximum Security

🔒 **Enable HSM for Secure Key Storage** – Utilize **hardware-backed key management**.  
🔏 **Use Strong Passphrases** – Minimum **16-character passwords recommended**.  
🔄 **Rotate Keys Regularly** – Prevents long-term cryptographic vulnerabilities.  
🛡 **Restrict Log Access** – Encrypted logs must be stored in **secure environments**.  

---

## 📢 Get Involved!

We welcome contributions from security experts and developers.

1. **Fork & Clone** the repository.
2. **Create a Feature Branch** for improvements.
3. **Submit a Pull Request** with documentation and rationale.

---

## 📜 License

SecureCrypt is **open-source** under the **BSD 3-Clause License**. See [`LICENSE`](./LICENSE) for details.

---

## 🛠 Support & Contact

📧 **Email**: `tanmayspatil2006@gmail.com`  
📌 **GitHub Issues**: Report bugs or suggest features [here](../../issues).  

---

### 🔗 More Resources

🔐 **Cryptography Best Practices**: [OWASP Guide](https://owasp.org)  
💡 **RSA Key Management**: [NIST Guidelines](https://csrc.nist.gov)  

---

🔹 **Note:** To access the GUI features, ensure that the `tkinter` library is installed on your system. For detailed installation instructions and troubleshooting, refer to the [Tkinter documentation](https://docs.python.org/3/library/tkinter.html).

