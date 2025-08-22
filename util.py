from cryptography.fernet import Fernet
from PIL import Image
import io

# Generate Fernet key from password
def get_fernet(password: str) -> Fernet:
    from hashlib import sha256
    key = sha256(password.encode()).digest()
    return Fernet(Fernet.generate_key().decode()[:32].encode())  # Fallback for Fernet requirement

# Simplified key derivation for Fernet (must be 32-byte base64-encoded)
def password_to_fernet(password: str) -> Fernet:
    import base64
    from hashlib import sha256
    key = sha256(password.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))

def encode_message(image: Image.Image, message: str, output_path: str):
    """
    Embed a message into an image using LSB steganography.
    Raises ValueError if the message is too large for the image.
    """
    EOF_MARKER = '11111110'  # 8 bits
    binary = ''.join([format(ord(c), '08b') for c in message]) + EOF_MARKER
    img = image.convert('RGB')
    pixels = img.load()
    width, height = img.size
    max_bits = width * height * 3
    if len(binary) > max_bits:
        raise ValueError('Message is too large to encode in this image.')
    idx = 0
    for i in range(width):
        for j in range(height):
            if idx < len(binary):
                r, g, b = pixels[i, j]
                r = (r & ~1) | int(binary[idx])
                idx += 1
                if idx < len(binary):
                    g = (g & ~1) | int(binary[idx])
                    idx += 1
                if idx < len(binary):
                    b = (b & ~1) | int(binary[idx])
                    idx += 1
                pixels[i, j] = (r, g, b)
            else:
                break
    img.save(output_path)

def decode_message(image: Image.Image) -> str:
    """
    Extract a hidden message from an image using LSB steganography.
    Returns the decoded message as a string.
    """
    EOF_MARKER = '11111110'  # 8 bits
    binary = ''
    img = image.convert('RGB')
    pixels = img.load()
    width, height = img.size
    for i in range(width):
        for j in range(height):
            r, g, b = pixels[i, j]
            binary += str(r & 1)
            binary += str(g & 1)
            binary += str(b & 1)
    bytes_list = [binary[i:i+8] for i in range(0, len(binary), 8)]
    message = ''
    for byte in bytes_list:
        if byte == EOF_MARKER:
            break
        message += chr(int(byte, 2))
    return message

def encrypt_message(message: str, password: str) -> str:
    """
    Encrypt a message using a password-derived Fernet key.
    Returns the encrypted message as a string.
    """
    f = password_to_fernet(password)
    token = f.encrypt(message.encode())
    return token.decode()

def decrypt_message(token: str, password: str) -> str:
    """
    Decrypt a message using a password-derived Fernet key.
    Returns the decrypted message as a string.
    """
    f = password_to_fernet(password)
    return f.decrypt(token.encode()).decode()
