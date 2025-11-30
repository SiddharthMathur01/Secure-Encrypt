import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from concurrent.futures import ThreadPoolExecutor
import numpy as np


SALT_LENGTH = 16
NONCE_LENGTH = 12
KEY_LENGTH = 32
PBKDF2_ITERATIONS = 200_000
ENVELOPE_HEADER = b"ENCV1"


SUPPORTED_FILE_TYPES = {
    '.pdf': 'application/pdf',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.txt': 'text/plain',
    '.rtf': 'application/rtf',
    '.odt': 'application/vnd.oasis.opendocument.text',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.bmp': 'image/bmp',
    '.svg': 'image/svg+xml',
    '.zip': 'application/zip',
    '.rar': 'application/x-rar-compressed',
    '.7z': 'application/x-7z-compressed',
    '.tar': 'application/x-tar',
    '.gz': 'application/gzip',
    '.json': 'application/json',
    '.xml': 'application/xml',
    '.csv': 'text/csv',
}

class EncryptionError(Exception):
    pass

class DecryptionError(Exception):
    pass

def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode('utf-8'))

def encrypt_data(plaintext: bytes, passphrase: str) -> bytes:
    try:
        salt = os.urandom(SALT_LENGTH)
        nonce = os.urandom(NONCE_LENGTH)
        key = derive_key(passphrase, salt)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        del key
        return salt + nonce + ciphertext
    except Exception as e:
        raise EncryptionError(f"Encryption failed: {str(e)}")

def decrypt_data(envelope: bytes, passphrase: str) -> bytes:
    try:
        if len(envelope) < SALT_LENGTH + NONCE_LENGTH:
            raise DecryptionError("Invalid encrypted data: too short")
        
        salt = envelope[:SALT_LENGTH]
        nonce = envelope[SALT_LENGTH:SALT_LENGTH + NONCE_LENGTH]
        ciphertext = envelope[SALT_LENGTH + NONCE_LENGTH:]
        key = derive_key(passphrase, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        del key
        return plaintext
    except InvalidTag:
        raise DecryptionError("Decryption failed: incorrect passphrase or corrupted data")
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {str(e)}")

def encrypt_text(plaintext: str, passphrase: str) -> str:
    plaintext_bytes = plaintext.encode('utf-8')
    envelope = encrypt_data(plaintext_bytes, passphrase)
    encoded = base64.b64encode(envelope).decode('ascii')
    return f"{ENVELOPE_HEADER.decode('ascii')}:{encoded}"

def decrypt_text(encrypted_text: str, passphrase: str) -> str:
    if not encrypted_text.startswith(f"{ENVELOPE_HEADER.decode('ascii')}:"):
        raise DecryptionError("Invalid encrypted text format: missing header")
    
    encoded = encrypted_text[len(ENVELOPE_HEADER) + 1:]
    
    try:
        envelope = base64.b64decode(encoded)
    except Exception:
        raise DecryptionError("Invalid encrypted text format: bad base64 encoding")
    
    plaintext_bytes = decrypt_data(envelope, passphrase)
    return plaintext_bytes.decode('utf-8')

def encrypt_file_content(file_content: bytes, passphrase: str) -> bytes:
    envelope = encrypt_data(file_content, passphrase)
    encoded = base64.b64encode(envelope)
    return ENVELOPE_HEADER + b'\n' + encoded

def decrypt_file_content(encrypted_content: bytes, passphrase: str) -> bytes:
    if not encrypted_content.startswith(ENVELOPE_HEADER + b'\n'):
        raise DecryptionError("Invalid encrypted file format: missing header")
    
    encoded = encrypted_content[len(ENVELOPE_HEADER) + 1:]
    
    try:
        envelope = base64.b64decode(encoded)
    except Exception:
        raise DecryptionError("Invalid encrypted file format: bad base64 encoding")
    
    return decrypt_data(envelope, passphrase)

def get_mime_type(filename: str) -> str:
    ext = os.path.splitext(filename.lower())[1]
    return SUPPORTED_FILE_TYPES.get(ext, 'application/octet-stream')

def is_supported_file_type(filename: str) -> bool:
    ext = os.path.splitext(filename.lower())[1]
    return ext in SUPPORTED_FILE_TYPES

def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _encode_chunk(args):
    chunk_data, chunk_index, pixels_array = args
    start_idx = chunk_index * 8
    for i, bit in enumerate(chunk_data):
        if start_idx + i < len(pixels_array):
            pixels_array[start_idx + i] = (pixels_array[start_idx + i] & 0xFE) | int(bit)
    return chunk_index, pixels_array[start_idx:start_idx + 8]

def _decode_chunk(args):
    start_idx, chunk_size, pixels_array = args
    bits = []
    for i in range(start_idx, min(start_idx + chunk_size, len(pixels_array))):
        bits.append(str(pixels_array[i] & 1))
    return start_idx, ''.join(bits)

def hide_in_image(image_bytes: bytes, data_bytes: bytes) -> bytes:
    try:
        from PIL import Image
        from io import BytesIO
        
        img = Image.open(BytesIO(image_bytes))
        
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        data_str = base64.b64encode(data_bytes).decode('ascii')
        binary_data = ''.join(format(ord(char), '08b') for char in data_str)
        
        delimiter = '1111111111111110'
        binary_data_with_delimiter = binary_data + delimiter
        
        pixels = np.array(img)
        original_shape = pixels.shape
        pixels_flat = pixels.flatten()
        
        if len(binary_data_with_delimiter) > len(pixels_flat):
            raise EncryptionError("Data too large for image capacity")
        
        num_threads = min(4, os.cpu_count() or 1)
        chunk_size = 8 * 1024
        num_chunks = (len(binary_data_with_delimiter) + chunk_size - 1) // chunk_size
        
        chunks = []
        for i in range(num_chunks):
            start = i * chunk_size
            end = min(start + chunk_size, len(binary_data_with_delimiter))
            chunks.append((binary_data_with_delimiter[start:end], i, pixels_flat))
        
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            results = list(executor.map(_encode_chunk, chunks))
        
        for chunk_index, modified_pixels in results:
            start_idx = chunk_index * 8
            pixels_flat[start_idx:start_idx + len(modified_pixels)] = modified_pixels
        
        pixels_modified = pixels_flat.reshape(original_shape)
        img_encoded = Image.fromarray(pixels_modified.astype('uint8'), 'RGB')
        
        out_bytes = BytesIO()
        img_encoded.save(out_bytes, format='PNG')
        return out_bytes.getvalue()
    
    except ImportError:
        raise EncryptionError("Pillow library not installed. Install with: pip install Pillow")
    except Exception as e:
        raise EncryptionError(f"Steganography encoding failed: {str(e)}")

def extract_from_image(image_bytes: bytes) -> bytes:
    try:
        from PIL import Image
        from io import BytesIO
        
        img = Image.open(BytesIO(image_bytes))
        pixels = np.array(img)
        pixels_flat = pixels.flatten()
        
        delimiter = '1111111111111110'
        delimiter_length = len(delimiter)
        
        num_threads = min(4, os.cpu_count() or 1)
        chunk_size = 8 * 1024
        max_bits = len(pixels_flat)
        num_chunks = (max_bits + chunk_size - 1) // chunk_size
        
        chunks = []
        for i in range(num_chunks):
            start = i * chunk_size
            end = min(start + chunk_size, max_bits)
            chunks.append((start, end - start, pixels_flat))
        
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            results = list(executor.map(_decode_chunk, chunks))
        
        results.sort(key=lambda x: x[0])
        binary_data = ''.join(result[1] for result in results)
        
        delimiter_index = binary_data.find(delimiter)
        if delimiter_index == -1:
            raise DecryptionError("No hidden data found in image")
        
        binary_data = binary_data[:delimiter_index]
        
        chars = []
        for i in range(0, len(binary_data), 8):
            byte = binary_data[i:i+8]
            if len(byte) == 8:
                chars.append(chr(int(byte, 2)))
        
        data_str = ''.join(chars)
        return base64.b64decode(data_str)
    
    except ImportError:
        raise DecryptionError("Pillow library not installed. Install with: pip install Pillow")
    except Exception as e:
        raise DecryptionError(f"Steganography decoding failed: {str(e)}")

if __name__ == "__main__":
    print("=== Crypto Utils Test ===\n")
    
    test_text = "Hello, this is a secret message!"
    test_passphrase = "super_secret_passphrase_123"
    
    print(f"Original text: {test_text}")
    print(f"Passphrase: {test_passphrase}\n")
    
    encrypted = encrypt_text(test_text, test_passphrase)
    print(f"Encrypted: {encrypted[:50]}...\n")
    
    decrypted = decrypt_text(encrypted, test_passphrase)
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_text == decrypted}\n")
    
    print("--- Testing file encryption ---")
    test_file_content = b"%PDF-1.4\nSimulated PDF content"
    print(f"Original size: {len(test_file_content)} bytes")
    
    encrypted_file = encrypt_file_content(test_file_content, test_passphrase)
    print(f"Encrypted size: {len(encrypted_file)} bytes")
    
    decrypted_file = decrypt_file_content(encrypted_file, test_passphrase)
    print(f"Decrypted size: {len(decrypted_file)} bytes")
    print(f"Match: {test_file_content == decrypted_file}\n")
    
    print("--- Testing SHA-256 hash ---")
    hash_val = sha256_hash(test_file_content)
    print(f"SHA-256: {hash_val}\n")