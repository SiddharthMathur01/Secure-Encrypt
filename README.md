# 🔐 Secure-Encrypt

A military-grade encryption web application built with Python Flask that provides robust file and text encryption using AES-256-GCM authenticated encryption with multithreaded steganography for optimal performance.

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
- **🖼️ Steganography**: Hide encrypted files inside images using LSB steganography with multithreading
- **⚡ Multithreaded Processing**: 3-5x faster steganography operations using parallel processing
- **🔑 Passphrase Generator**: Built-in cryptographically secure passphrase generator (12-32 characters)
- **📊 Password Strength Meter**: Real-time password strength analysis using zxcvbn
- **🔒 Zero-Knowledge Architecture**: All encryption happens server-side but no data is stored
- **📝 Comprehensive Logging**: Track operations, security events, and errors with detailed logs
- **📈 Log Analytics**: Built-in log analyzer for monitoring and statistics

### Security Features
- **PBKDF2 Key Derivation**: 200,000 iterations with SHA-256
- **Random Salt & Nonce**: Unique salt (16 bytes) and nonce (12 bytes) for each encryption
- **Authenticated Encryption**: GCM mode provides both confidentiality and authenticity
- **Secure Key Handling**: Keys are derived and immediately deleted from memory
- **No Storage**: Server never stores passphrases or decrypted content
- **Security Audit Logging**: Monitor failed attempts, weak passwords, and suspicious activity
- **IP Tracking**: Log client IP addresses for security monitoring

### Performance
- **Optimized Steganography**: Custom LSB implementation with ThreadPoolExecutor
- **NumPy Acceleration**: Fast array operations for image processing
- **Parallel Processing**: Automatic multi-core CPU utilization
- **Efficient Memory Usage**: Chunked processing for large files

## 📋 Requirements

- Python 3.7+
- Flask 3.0.0
- cryptography 41.0.7
- Pillow (for steganography)
- NumPy (for multithreaded steganography)
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

## 📁 Project Structure

```
Secure-Encrypt/
├── app.py                      # Flask application & API endpoints
├── main.py                     # Core encryption/decryption logic
├── logging_config.py           # Logging configuration
├── log_analyzer.py             # Log analysis tool
├── requirements.txt            # Python dependencies
├── .gitignore                  # Git ignore rules
├── LICENSE                     # MIT License
│
├── templates/                  # HTML templates
│   └── index.html             # Main web interface
│
├── static/                     # Static assets
│   ├── css/
│   │   └── styles.css         # Application styles
│   └── js/
│       └── app.js             # JavaScript functionality
│
└── logs/                       # Application logs (auto-created)
    ├── app.log                # General application logs
    ├── security.log           # Security events
    └── error.log              # Error logs
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
- **Hide Mode**: Conceal encrypted files inside cover images (now 3-5x faster!)
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

## 📝 Logging System

The application includes a comprehensive logging system that tracks all operations:

### Log Files

- **app.log**: General application activity, API requests, and user interactions
- **security.log**: Security events, encryption/decryption operations, failed attempts
- **error.log**: Errors and exceptions with full stack traces

### Log Analysis

Analyze application logs with the built-in tool:

```bash
python log_analyzer.py
```

This provides:
- API request statistics
- Encryption/decryption success rates
- Security event monitoring
- Error analysis
- Time distribution of activity

### What's Logged

✅ Operation types and timestamps  
✅ IP addresses  
✅ Success/failure status  
✅ File types and sizes  
✅ Security events (weak passwords, failed attempts)  

❌ **Never Logged**: Passphrases, plaintext content, decrypted data

## ⚡ Performance Benchmarks

### Steganography Operations (Multithreaded)

| Image Size | Hide Operation | Extract Operation | CPU Cores Used |
|-----------|----------------|-------------------|----------------|
| 1MB (HD) | 0.5-1s | 0.4-0.8s | 4 |
| 5MB (Full HD) | 2-4s | 1.8-3.5s | 4 |
| 10MB+ (4K) | 5-8s | 4.5-7s | 4 |

**Performance Improvement**: 3-5x faster than single-threaded implementation

### System Requirements for Optimal Performance

- **Minimum**: 2 CPU cores, 2GB RAM
- **Recommended**: 4+ CPU cores, 4GB+ RAM
- **Best**: 8+ CPU cores, 8GB+ RAM

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

### Steganography Implementation

**Method**: LSB (Least Significant Bit) Steganography
- **Processing**: Multithreaded with ThreadPoolExecutor
- **Chunk Size**: 8KB per chunk for optimal performance
- **Workers**: Up to 4 parallel threads
- **Format**: PNG output for lossless storage
- **Delimiter**: 16-bit pattern for data boundary detection

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
6. **Monitor Logs**: Regularly review security logs for suspicious activity

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

### Logging Configuration
Modify log levels and rotation in `logging_config.py`:
```python
# Adjust log level (DEBUG, INFO, WARNING, ERROR)
app_logger = setup_logger('app', APP_LOG_FILE, level=logging.INFO)

# Adjust log rotation (10MB default)
maxBytes=10 * 1024 * 1024
backupCount=5
```

### Multithreading Configuration
Adjust thread count in `main.py`:
```python
# Default: up to 4 threads
num_threads = min(4, os.cpu_count() or 1)

# For more threads (use cautiously):
num_threads = min(8, os.cpu_count() or 1)
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

### Modern UI
- Glassmorphism design
- Dark theme optimized
- Responsive for mobile devices
- Smooth animations and transitions
- Accessible keyboard navigation
- Separated CSS and JavaScript for maintainability

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

### Test Logging
```bash
# Run the application
python app.py

# Perform some operations

# Analyze logs
python log_analyzer.py
```

### Performance Testing
```bash
# Time steganography operations
python -c "
import time
from main import hide_in_image

with open('test.png', 'rb') as f:
    img = f.read()

data = b'X' * 10000
start = time.time()
hide_in_image(img, data)
print(f'Time: {time.time() - start:.2f}s')
"
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
- Steganography requires PNG output for best results
- Self-destruct timing is based on UTC time
- Browser-based file handling has memory limits
- Steganography capacity: 1 bit per pixel channel (RGB: width × height × 3 bits)

### Compatibility Notes
- Steganography files created with v2.1.0+ are **not compatible** with earlier versions
- Use consistent version for hiding and extracting data
- All other encryption features remain backward compatible

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Areas for Contribution
- GPU acceleration for steganography
- Additional encryption algorithms
- Mobile-responsive UI improvements
- Additional file format support
- Performance optimizations
- Security enhancements
- Documentation improvements
- Logging enhancements
- Unit tests and integration tests

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
- [LSB Steganography](https://en.wikipedia.org/wiki/Bit_numbering)
- [ThreadPoolExecutor Documentation](https://docs.python.org/3/library/concurrent.futures.html)

## 🙏 Acknowledgments

- Flask framework and contributors
- Python Cryptography library team
- Bootstrap for UI components
- zxcvbn password strength estimator
- NumPy for high-performance array operations
- Pillow for image processing
- Open-source security community

## 👤 Author

**Siddharth Mathur**
- GitHub: [@SiddharthMathur01](https://github.com/SiddharthMathur01)
- Project: [Secure-Encrypt](https://github.com/SiddharthMathur01/Secure-Encrypt)

## 📈 Version History

- **v2.1.0** - Performance Update (Current)
  - Added multithreaded steganography (3-5x faster)
  - Custom LSB implementation with NumPy
  - Parallel processing with ThreadPoolExecutor
  - Removed stepic dependency
  - Optimized memory usage
  - Enhanced error handling

- **v2.0.0** - Major Update
  - Separated CSS and JavaScript into external files
  - Added comprehensive logging system
  - Added log analysis tool
  - Improved file structure and organization
  - Enhanced security monitoring
  - Better code maintainability

- **v1.0.0** - Initial Release
  - AES-256-GCM encryption
  - Text and file encryption
  - Batch processing
  - Self-destruct feature
  - Steganography support
  - Web interface with modern UI

---

**Made with 🔐 for Privacy and Security**

*Encrypt your data. Protect your privacy. Stay secure.*

**⚡ Now with multithreaded steganography for blazing-fast performance!**