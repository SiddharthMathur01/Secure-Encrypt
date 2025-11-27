from flask import Flask, render_template, request, jsonify, send_file
import io
import os
import zipfile
import traceback
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename

from main import (
    encrypt_text, decrypt_text,
    encrypt_file_content, decrypt_file_content,
    get_mime_type,
    EncryptionError, DecryptionError,
    hide_in_image, extract_from_image,
    sha256_hash
)

# Import logging utilities
from logging_config import (
    app_logger,
    security_logger,
    error_logger,
    log_encryption_attempt,
    log_decryption_attempt,
    log_api_request,
    log_error,
    log_security_event
)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024 

# Disable default werkzeug logging
import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr

@app.route('/')
def index():
    """Serve the main application page"""
    app_logger.info(f"Index page accessed from IP: {get_client_ip()}")
    return render_template('index.html')


@app.route('/encrypt/text', methods=['POST'])
def encrypt_text_endpoint():
    """Encrypt text provided by the user."""
    client_ip = get_client_ip()
    
    try:
        data = request.get_json()
        plaintext = data.get('plaintext', '')
        passphrase = data.get('passphrase', '')
        
        app_logger.info(f"Text encryption request from IP: {client_ip}")
        
        if not plaintext:
            log_security_event('INVALID_INPUT', 'Empty plaintext provided')
            return jsonify({'success': False, 'error': 'Plaintext cannot be empty'}), 400
        
        if not passphrase or len(passphrase) < 8:
            log_security_event('WEAK_PASSPHRASE', f'Passphrase length: {len(passphrase)}')
            return jsonify({'success': False, 'error': 'Passphrase must be at least 8 characters'}), 400
        
        encrypted = encrypt_text(plaintext, passphrase)
        del plaintext, passphrase
        
        log_encryption_attempt('text', file_type='text', success=True)
        log_api_request('/encrypt/text', 'POST', 200, client_ip)
        
        return jsonify({'success': True, 'encrypted': encrypted})
    
    except EncryptionError as e:
        log_encryption_attempt('text', success=False)
        log_error('EncryptionError', str(e))
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        log_error('UnexpectedError', str(e), traceback.format_exc())
        return jsonify({'success': False, 'error': 'Encryption failed'}), 500

@app.route('/decrypt/text', methods=['POST'])
def decrypt_text_endpoint():
    """Decrypt encrypted text"""
    client_ip = get_client_ip()
    
    try:
        data = request.get_json()
        encrypted = data.get('encrypted', '')
        passphrase = data.get('passphrase', '')
        
        app_logger.info(f"Text decryption request from IP: {client_ip}")
        
        if not encrypted:
            return jsonify({'success': False, 'error': 'Encrypted text cannot be empty'}), 400
        
        if not passphrase:
            return jsonify({'success': False, 'error': 'Passphrase cannot be empty'}), 400
        
        plaintext = decrypt_text(encrypted, passphrase)
        del passphrase
        
        log_decryption_attempt('text', success=True)
        log_api_request('/decrypt/text', 'POST', 200, client_ip)
        
        return jsonify({'success': True, 'plaintext': plaintext})
    
    except DecryptionError as e:
        log_decryption_attempt('text', success=False, error_msg=str(e))
        log_security_event('DECRYPTION_FAILED', f'IP: {client_ip}, Error: {str(e)}')
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        log_error('UnexpectedError', str(e), traceback.format_exc())
        return jsonify({'success': False, 'error': 'Decryption failed'}), 500


@app.route('/encrypt/file', methods=['POST'])
def encrypt_file_endpoint():
    """Encrypt a single file"""
    client_ip = get_client_ip()
    
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        passphrase = request.form.get('passphrase', '')
        
        app_logger.info(f"File encryption request from IP: {client_ip}, File: {file.filename}")
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        if not passphrase or len(passphrase) < 8:
            log_security_event('WEAK_PASSPHRASE', f'File encryption attempt with weak passphrase')
            return jsonify({'success': False, 'error': 'Passphrase must be at least 8 characters'}), 400
        
        file_content = file.read()
        file_size = len(file_content)
        
        if file_size == 0:
            return jsonify({'success': False, 'error': 'File is empty'}), 400
        
        encrypted_content = encrypt_file_content(file_content, passphrase)
        del file_content, passphrase
        
        original_filename = secure_filename(file.filename)
        encrypted_filename = f"{original_filename}.encrypted"
        
        log_encryption_attempt('file', file_type=original_filename.split('.')[-1], 
                              file_size=f"{file_size/1024:.2f}KB", success=True)
        log_api_request('/encrypt/file', 'POST', 200, client_ip)
        
        return send_file(
            io.BytesIO(encrypted_content),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=encrypted_filename
        )
    
    except EncryptionError as e:
        log_encryption_attempt('file', success=False)
        log_error('EncryptionError', str(e))
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        log_error('UnexpectedError', str(e), traceback.format_exc())
        return jsonify({'success': False, 'error': f'File encryption failed: {str(e)}'}), 500

@app.route('/decrypt/file', methods=['POST'])
def decrypt_file_endpoint():
    """Decrypt an encrypted file"""
    client_ip = get_client_ip()
    
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        passphrase = request.form.get('passphrase', '')
        
        app_logger.info(f"File decryption request from IP: {client_ip}, File: {file.filename}")
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        if not passphrase:
            return jsonify({'success': False, 'error': 'Passphrase cannot be empty'}), 400
        
        encrypted_content = file.read()
        
        if len(encrypted_content) == 0:
            return jsonify({'success': False, 'error': 'File is empty'}), 400
        
        decrypted_content = decrypt_file_content(encrypted_content, passphrase)
        del encrypted_content, passphrase
        
        original_filename = secure_filename(file.filename)
        if original_filename.endswith('.encrypted'):
            decrypted_filename = original_filename[:-10]
        else:
            decrypted_filename = f"{original_filename}.decrypted"
        
        mime_type = get_mime_type(decrypted_filename)
        
        log_decryption_attempt('file', success=True)
        log_api_request('/decrypt/file', 'POST', 200, client_ip)
        
        return send_file(
            io.BytesIO(decrypted_content),
            mimetype=mime_type,
            as_attachment=True,
            download_name=decrypted_filename
        )
    
    except DecryptionError as e:
        log_decryption_attempt('file', success=False, error_msg=str(e))
        log_security_event('DECRYPTION_FAILED', f'IP: {client_ip}, File: {file.filename}')
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        log_error('UnexpectedError', str(e), traceback.format_exc())
        return jsonify({'success': False, 'error': f'File decryption failed: {str(e)}'}), 500


@app.route('/encrypt/batch', methods=['POST'])
def encrypt_batch_files():
    """Encrypt multiple files and return as ZIP"""
    client_ip = get_client_ip()
    
    try:
        if 'files' not in request.files:
            return jsonify({'success': False, 'error': 'No files provided'}), 400
        
        files = request.files.getlist('files')
        passphrase = request.form.get('passphrase', '')
        
        app_logger.info(f"Batch encryption request from IP: {client_ip}, Files count: {len(files)}")
        
        if not files or len(files) == 0:
            return jsonify({'success': False, 'error': 'No files selected'}), 400
        
        if not passphrase or len(passphrase) < 8:
            log_security_event('WEAK_PASSPHRASE', 'Batch encryption with weak passphrase')
            return jsonify({'success': False, 'error': 'Passphrase must be at least 8 characters'}), 400
        
        archive_io = io.BytesIO()
        encrypted_count = 0
        
        with zipfile.ZipFile(archive_io, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in files:
                if file.filename:
                    data = file.read()
                    if len(data) > 0:
                        encrypted = encrypt_file_content(data, passphrase)
                        safe_filename = secure_filename(file.filename)
                        zipf.writestr(safe_filename + '.encrypted', encrypted)
                        encrypted_count += 1
        
        archive_io.seek(0)
        
        log_encryption_attempt('batch', file_type='multiple', 
                              file_size=f"{encrypted_count} files", success=True)
        log_api_request('/encrypt/batch', 'POST', 200, client_ip)
        
        return send_file(
            archive_io,
            mimetype='application/zip',
            as_attachment=True,
            download_name='encrypted_batch.zip'
        )
    
    except Exception as e:
        log_error('UnexpectedError', str(e), traceback.format_exc())
        return jsonify({'success': False, 'error': f'Batch encryption failed: {str(e)}'}), 500


@app.route('/encrypt/file_with_expiry', methods=['POST'])
def encrypt_file_with_expiry():
    """Encrypt file with time-based expiration"""
    client_ip = get_client_ip()
    
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        passphrase = request.form.get('passphrase', '')
        expire_minutes = int(request.form.get('expire_minutes', 60))
        
        app_logger.info(
            f"Expiring file encryption from IP: {client_ip}, "
            f"File: {file.filename}, Expiry: {expire_minutes}min"
        )
        
        if not passphrase or len(passphrase) < 8:
            return jsonify({'success': False, 'error': 'Passphrase required'}), 400
        
        expiry = (datetime.utcnow() + timedelta(minutes=expire_minutes)).isoformat()
        file_content = file.read()
        encrypted_content = encrypt_file_content(file_content, passphrase)
        envelope = f"EXPIRY:{expiry}|".encode() + encrypted_content
        
        encrypted_filename = secure_filename(file.filename) + '.expiring.encrypted'
        
        log_encryption_attempt('file_expiry', file_type=file.filename.split('.')[-1],
                              file_size=f"{len(file_content)/1024:.2f}KB", success=True)
        security_logger.info(f"Expiring file created - Expires: {expiry}")
        log_api_request('/encrypt/file_with_expiry', 'POST', 200, client_ip)
        
        return send_file(
            io.BytesIO(envelope),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=encrypted_filename
        )
    
    except Exception as e:
        log_error('UnexpectedError', str(e), traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/decrypt/file_with_expiry', methods=['POST'])
def decrypt_file_with_expiry():
    """Decrypt file with expiration check"""
    client_ip = get_client_ip()
    
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        passphrase = request.form.get('passphrase', '')
        
        app_logger.info(f"Expiring file decryption from IP: {client_ip}, File: {file.filename}")
        
        if not passphrase:
            return jsonify({'success': False, 'error': 'Passphrase required'}), 400
        
        content = file.read()
        
        if not content.startswith(b'EXPIRY:'):
            return jsonify({'success': False, 'error': 'Not an expiring file'}), 400
        
        try:
            header_end = content.index(b'|')
            expiry_str = content[7:header_end].decode('utf-8')
            encrypted_content = content[header_end + 1:]
            
            expiry_time = datetime.fromisoformat(expiry_str)
            
            if datetime.utcnow() > expiry_time:
                log_security_event('EXPIRED_FILE_ACCESS', 
                                  f'IP: {client_ip}, Expired: {expiry_time}')
                return jsonify({
                    'success': False,
                    'error': f'File expired on {expiry_time.strftime("%Y-%m-%d %H:%M:%S")} UTC'
                }), 403
            
            decrypted_content = decrypt_file_content(encrypted_content, passphrase)
            
            original_filename = secure_filename(file.filename)
            if original_filename.endswith('.expiring.encrypted'):
                decrypted_filename = original_filename[:-19]
            else:
                decrypted_filename = original_filename + '.decrypted'
            
            mime_type = get_mime_type(decrypted_filename)
            
            log_decryption_attempt('file_expiry', success=True)
            log_api_request('/decrypt/file_with_expiry', 'POST', 200, client_ip)
            
            return send_file(
                io.BytesIO(decrypted_content),
                mimetype=mime_type,
                as_attachment=True,
                download_name=decrypted_filename
            )
        
        except ValueError as e:
            log_error('ValueError', str(e))
            return jsonify({'success': False, 'error': 'Invalid expiry format'}), 400
    
    except DecryptionError as e:
        log_decryption_attempt('file_expiry', success=False, error_msg=str(e))
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        log_error('UnexpectedError', str(e), traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/steg/encrypt', methods=['POST'])
def steg_encrypt():
    """Hide encrypted file data inside an image using steganography"""
    client_ip = get_client_ip()
    
    try:
        if 'image' not in request.files or 'file' not in request.files:
            return jsonify({'success': False, 'error': 'Image and file required'}), 400
        
        image = request.files['image']
        file = request.files['file']
        passphrase = request.form.get('passphrase', '')
        
        app_logger.info(
            f"Steganography hide request from IP: {client_ip}, "
            f"Image: {image.filename}, File: {file.filename}"
        )
        
        if not passphrase or len(passphrase) < 8:
            return jsonify({'success': False, 'error': 'Passphrase required'}), 400
        
        file_data = file.read()
        encrypted_data = encrypt_file_content(file_data, passphrase)
        image_data = image.read()
        stego_image = hide_in_image(image_data, encrypted_data)
        
        log_encryption_attempt('steganography', file_type='image', 
                              file_size=f"{len(file_data)/1024:.2f}KB", success=True)
        log_api_request('/steg/encrypt', 'POST', 200, client_ip)
        
        return send_file(
            io.BytesIO(stego_image),
            mimetype='image/png',
            as_attachment=True,
            download_name='stego.png'
        )
    
    except Exception as e:
        log_error('SteganographyError', str(e), traceback.format_exc())
        return jsonify({'success': False, 'error': f'Steganography failed: {str(e)}'}), 500

@app.route('/steg/decrypt', methods=['POST'])
def steg_decrypt():
    """Extract and decrypt hidden data from steganographic image"""
    client_ip = get_client_ip()
    
    try:
        if 'image' not in request.files:
            return jsonify({'success': False, 'error': 'Image required'}), 400
        
        image = request.files['image']
        passphrase = request.form.get('passphrase', '')
        original_filename = request.form.get('filename', 'revealed.bin')
        
        app_logger.info(f"Steganography reveal request from IP: {client_ip}, Image: {image.filename}")
        
        if not passphrase:
            return jsonify({'success': False, 'error': 'Passphrase required'}), 400
        
        image_data = image.read()
        encrypted_data = extract_from_image(image_data)
        decrypted_data = decrypt_file_content(encrypted_data, passphrase)
        
        mime_type = get_mime_type(original_filename)
        
        log_decryption_attempt('steganography', success=True)
        log_api_request('/steg/decrypt', 'POST', 200, client_ip)
        
        return send_file(
            io.BytesIO(decrypted_data),
            mimetype=mime_type,
            as_attachment=True,
            download_name=secure_filename(original_filename)
        )
    
    except Exception as e:
        log_error('SteganographyError', str(e), traceback.format_exc())
        return jsonify({'success': False, 'error': f'Extraction failed: {str(e)}'}), 500


@app.errorhandler(413)
def too_large(e):
    """Handle file too large errors"""
    log_security_event('FILE_TOO_LARGE', f'IP: {get_client_ip()}')
    return jsonify({'success': False, 'error': 'File too large (max 50MB)'}), 413

@app.errorhandler(500)
def internal_error(e):
    """Handle internal server errors"""
    log_error('InternalServerError', str(e), traceback.format_exc())
    return jsonify({'success': False, 'error': 'Internal server error'}), 500


if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    
    app_logger.info("="*70)
    app_logger.info("🔒 Secure Encryption Web App Starting")
    app_logger.info("="*70)
    app_logger.info("Server starting on http://127.0.0.1:5000")
    app_logger.info("Logging system initialized")
    app_logger.info("="*70)
    
    print("\n" + "="*70)
    print("🔒 Secure Encryption Web App")
    print("="*70)
    print("\n🌐 Starting server on http://127.0.0.1:5000")
    print("📝 Logs directory: ./logs/")
    print("   - app.log: Application logs")
    print("   - security.log: Security events")
    print("   - error.log: Error logs")
    print("\nPress CTRL+C to stop the server")
    print("="*70 + "\n")
    
    app.run(debug=True, host='127.0.0.1', port=5000)