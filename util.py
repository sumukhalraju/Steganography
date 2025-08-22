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
    # Embed message into image pixels using LSB
    binary = ''.join([format(ord(c), '08b') for c in message]) + '1111111111111110'  # EOF marker
    img = image.convert('RGB')
    pixels = img.load()
    idx = 0
    for i in range(img.size[0]):
        for j in range(img.size[1]):
            if idx < len(binary):
                r, g, b = pixels[i, j]
                r = (r & ~1) | int(binary[idx])
                if idx + 1 < len(binary):
                    g = (g & ~1) | int(binary[idx + 1])
                if idx + 2 < len(binary):
                    b = (b & ~1) | int(binary[idx + 2])
                pixels[i, j] = (r, g, b)
                idx += 3
            else:
                break
    img.save(output_path)

def decode_message(image: Image.Image) -> str:
    binary = ''
    img = image.convert('RGB')
    pixels = img.load()
    for i in range(img.size[0]):
        for j in range(img.size[1]):
            r, g, b = pixels[i, j]
            binary += str(r & 1)
            binary += str(g & 1)
            binary += str(b & 1)
    bytes_list = [binary[i:i+8] for i in range(0, len(binary), 8)]
    message = ''
    for byte in bytes_list:
        if byte == '11111110':  # EOF
            break
        message += chr(int(byte, 2))
    return message

def encrypt_message(message: str, password: str) -> str:
    f = password_to_fernet(password)
    token = f.encrypt(message.encode())
    return token.decode()

def decrypt_message(token: str, password: str) -> str:
    f = password_to_fernet(password)
    return f.decrypt(token.encode()).decode()
