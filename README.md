# 🔐 Secure-Encrypt

A military-grade encryption web application built with Python Flask that provides robust file and text encryption using AES-256-GCM authenticated encryption.

[![Python](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/flask-3.0.0-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Encryption](https://img.shields.io/badge/encryption-AES--256--GCM-red.svg)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)

## ✨ Features

### Core Encryption
- **AES-256-GCM Encryption**: Military-grade authenticated encryption with integrity verification
- **Text Encryption**: Secure plaintext encryption with base64 encoding
- **File Encryption**: Support for any file type up to 50MB
- **Batch Processing**: Encrypt multiple files at once, downloaded as a ZIP archive

### Advanced Features
- **🕐 Self-Destruct (Expiry)**: Set time-based expiration on encrypted files (30 minutes to 7 days)
- **🖼️ Steganography**: Hide encrypted files inside images using LSB steganography
- **🔑 Passphrase Generator**: Built-in cryptographically secure passphrase generator (12-32 characters)
- **📊 Password Strength Meter**: Real-time password strength analysis using zxcvbn
- **🔒 Zero-Knowledge Architecture**: All encryption happens server-side but no data is stored

### Security Features
- **PBKDF2 Key Derivation**: 200,000 iterations with SHA-256
- **Random Salt & Nonce**: Unique salt (16 bytes) and nonce (12 bytes) for each encryption
- **Authenticated Encryption**: GCM mode provides both confidentiality and authenticity
- **Secure Key Handling**: Keys are derived and immediately deleted from memory
- **No Storage**: Server never stores passphrases or decrypted content

## 📋 Requirements

- Python 3.7+
- Flask 3.0.0
- cryptography 41.0.7
- Pillow (for steganography)
- stepic (for steganography)
- zxcvbn (for password strength)

## 🚀 Quick Start

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/SiddharthMathur01/Secure-Encrypt.git
cd Secure-Encrypt
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the application**
```bash
python app.py
```

4. **Open your browser**
```
http://127.0.0.1:5000
```

## 💻 Usage

### Web Interface

The application provides a beautiful, modern web interface with three main tabs:

#### 🔒 Encrypt Tab
1. Choose between **Text** or **File(s)** mode
2. Enter your sensitive data or select files
3. Create a strong passphrase (or generate one)
4. Optional: Enable self-destruct with expiration time
5. Click **Encrypt Now**

#### 🔓 Decrypt Tab
1. Choose between **Text** or **File** mode
2. Paste encrypted text or upload encrypted file
3. Enter the original passphrase
4. Click **Decrypt Now**

#### 👁️ Steganography Tab
- **Hide Mode**: Conceal encrypted files inside cover images
- **Reveal Mode**: Extract and decrypt hidden files from stego images

### API Endpoints

#### Text Encryption
```bash
curl -X POST http://127.0.0.1:5000/encrypt/text \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "Secret message", "passphrase": "strongpass123"}'
```

#### Text Decryption
```bash
curl -X POST http://127.0.0.1:5000/decrypt/text \
  -H "Content-Type: application/json" \
  -d '{"encrypted": "ENCV1:...", "passphrase": "strongpass123"}'
```

#### File Encryption
```bash
curl -X POST http://127.0.0.1:5000/encrypt/file \
  -F "file=@document.pdf" \
  -F "passphrase=strongpass123" \
  --output document.pdf.encrypted
```

#### File Decryption
```bash
curl -X POST http://127.0.0.1:5000/decrypt/file \
  -F "file=@document.pdf.encrypted" \
  -F "passphrase=strongpass123" \
  --output document.pdf
```

#### Batch Encryption
```bash
curl -X POST http://127.0.0.1:5000/encrypt/batch \
  -F "files=@file1.txt" \
  -F "files=@file2.pdf" \
  -F "passphrase=strongpass123" \
  --output encrypted_batch.zip
```

#### Expiring File Encryption
```bash
curl -X POST http://127.0.0.1:5000/encrypt/file_with_expiry \
  -F "file=@secret.txt" \
  -F "passphrase=strongpass123" \
  -F "expire_minutes=60" \
  --output secret.txt.expiring.encrypted
```

#### Steganography - Hide
```bash
curl -X POST http://127.0.0.1:5000/steg/encrypt \
  -F "image=@cover.png" \
  -F "file=@secret.txt" \
  -F "passphrase=strongpass123" \
  --output stego.png
```

#### Steganography - Reveal
```bash
curl -X POST http://127.0.0.1:5000/steg/decrypt \
  -F "image=@stego.png" \
  -F "passphrase=strongpass123" \
  -F "filename=secret.txt" \
  --output revealed.txt
```

## 🔐 Technical Details

### Encryption Algorithm

**Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 96 bits (12 bytes) - recommended for GCM
- **Authentication**: Built-in GMAC for authenticated encryption

### Key Derivation

**Function**: PBKDF2-HMAC-SHA256
- **Iterations**: 200,000
- **Salt Size**: 128 bits (16 bytes)
- **Output**: 256-bit encryption key

### Encrypted Data Format

#### Text Format
```
ENCV1:<base64-encoded-envelope>
```

#### File Format
```
ENCV1
<base64-encoded-envelope>
```

#### Envelope Structure
```
[Salt (16 bytes)][Nonce (12 bytes)][Ciphertext][Auth Tag (16 bytes)]
```

#### Expiring File Format
```
EXPIRY:<ISO-8601-timestamp>|<encrypted-envelope>
```

### Supported File Types

The application supports all file types, with MIME type detection for:
- Documents: PDF, DOC, DOCX, TXT, RTF, ODT
- Images: JPG, PNG, GIF, BMP, SVG
- Archives: ZIP, RAR, 7Z, TAR, GZ
- Data: JSON, XML, CSV

## 🛡️ Security Best Practices

### For Users
1. **Use Strong Passphrases**: Minimum 12 characters with mixed case, numbers, and symbols
2. **Never Reuse Passphrases**: Use unique passphrases for different files
3. **Store Passphrases Securely**: Use a password manager
4. **Verify Downloads**: Check file integrity after decryption
5. **Secure Your Environment**: Use HTTPS in production, secure your endpoints

### For Developers
1. **HTTPS Only**: Always deploy with TLS/SSL in production
2. **Rate Limiting**: Implement rate limiting on encryption endpoints
3. **Input Validation**: All inputs are validated and sanitized
4. **Memory Security**: Sensitive data is deleted from memory after use
5. **Error Handling**: Generic error messages prevent information leakage

## ⚙️ Configuration

### File Size Limits
Default maximum file size is 50MB. Modify in `app.py`:
```python
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB
```

### PBKDF2 Iterations
Adjust security vs. performance in `main.py`:
```python
PBKDF2_ITERATIONS = 200_000  # Increase for higher security
```

### Encryption Parameters
```python
SALT_LENGTH = 16      # 128 bits
NONCE_LENGTH = 12     # 96 bits (GCM recommended)
KEY_LENGTH = 32       # 256 bits
```

## 🎨 Features Overview

### Password Strength Meter
Real-time analysis using the zxcvbn algorithm:
- Very Weak (red)
- Weak (orange)
- Fair (yellow)
- Good (light green)
- Strong (green)

### Passphrase Generator
- Adjustable length: 12-32 characters
- Character set: a-z, A-Z, 0-9, special characters
- Cryptographically secure random generation
- One-click insertion into passphrase field

### Drag & Drop
- Intuitive file upload with drag-and-drop support
- Multiple file selection for batch encryption
- Visual feedback with file previews

### Self-Destruct Feature
Set expiration times:
- 30 minutes
- 1 hour
- 6 hours
- 24 hours
- 7 days

Files cannot be decrypted after expiration.

## 🧪 Testing

### Test Encryption Functions
```bash
python main.py
```

This runs built-in tests for:
- Text encryption/decryption
- File content encryption/decryption
- SHA-256 hashing

### Manual Testing
1. Encrypt a test file
2. Verify the encrypted file differs from original
3. Decrypt with correct passphrase
4. Verify decrypted content matches original
5. Try decrypting with wrong passphrase (should fail)

## 📁 Project Structure

```
Secure-Encrypt/
├── app.py                 # Flask application & API endpoints
├── main.py                # Core encryption/decryption logic
├── requirements.txt       # Python dependencies
├── templates/
│   └── index.html        # Web interface
└── README.md             # Documentation
```

## 🔧 API Response Format

### Success Response
```json
{
  "success": true,
  "encrypted": "ENCV1:base64data..."
}
```

### Error Response
```json
{
  "success": false,
  "error": "Error message"
}
```

## ⚠️ Important Notes

### Security Warnings
- **Lost Passphrases Cannot Be Recovered**: There is no passphrase recovery mechanism
- **No Server-Side Storage**: Files and passphrases are never stored on the server
- **Use HTTPS**: Always use HTTPS in production to prevent man-in-the-middle attacks
- **Backup Important Data**: Keep backups of original files before encryption

### Limitations
- Maximum file size: 50MB (configurable)
- Steganography requires PNG images for best results
- Self-destruct timing is based on UTC time
- Browser-based file handling has memory limits

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Areas for Contribution
- Additional encryption algorithms
- Mobile-responsive UI improvements
- Additional file format support
- Performance optimizations
- Security enhancements
- Documentation improvements

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔒 Cryptographic Notice

This software uses strong cryptography. Before using this software, please check your country's laws, regulations, and policies concerning the import, possession, or use, and re-export of encryption software, to ensure compliance.

## ⚖️ Legal Disclaimer

This tool is provided for legitimate encryption purposes only. Users are responsible for:
- Complying with all applicable laws and regulations
- Using the tool ethically and legally
- Understanding that encrypted data may be unrecoverable without the passphrase
- Maintaining proper backups of important data

The developers assume no liability for:
- Loss of data due to lost passphrases
- Misuse of the software
- Legal consequences of use in restricted jurisdictions

## 🐛 Bug Reports & Security Issues

### General Bugs
Report bugs via GitHub Issues:
[Create an issue](https://github.com/SiddharthMathur01/Secure-Encrypt/issues)

### Security Vulnerabilities
For security vulnerabilities, please contact privately before public disclosure.

## 📚 Resources & References

- [AES-GCM Specification](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [PBKDF2 RFC 2898](https://tools.ietf.org/html/rfc2898)
- [Python Cryptography Library](https://cryptography.io/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

## 🙏 Acknowledgments

- Flask framework and contributors
- Python Cryptography library team
- Bootstrap for UI components
- zxcvbn password strength estimator
- Stepic library for steganography
- Open-source security community

## 👤 Author

**Siddharth Mathur**
- GitHub: [@SiddharthMathur01](https://github.com/SiddharthMathur01)
- Project: [Secure-Encrypt](https://github.com/SiddharthMathur01/Secure-Encrypt)

## 📈 Version History

- **v1.0.0** - Initial release
  - AES-256-GCM encryption
  - Text and file encryption
  - Batch processing
  - Self-destruct feature
  - Steganography support
  - Web interface with modern UI

---

**Made with 🔐 for Privacy and Security**

*Encrypt your data. Protect your privacy. Stay secure.*