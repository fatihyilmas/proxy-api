import os
import json
import requests
import base64
import hashlib
from http.server import BaseHTTPRequestHandler
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# --- Environment Variables ---
API_SECRET_KEY = os.environ.get("API_SECRET_KEY")
CLOUDFLARE_WORKER_URL_B64 = os.environ.get("CLOUDFLARE_WORKER_URL_B64")
CLOUDFLARE_ACCESS_KEY = os.environ.get("CLOUDFLARE_ACCESS_KEY")

# --- Constants for Client-Side Decryption ---
SALT = b'jbot_salt_v1'
ITERATIONS = 100_000

def _derive_key_from_secret(secret: str) -> bytes:
    """Derives a 256-bit encryption key from a shared secret using PBKDF2."""
    if not secret:
        raise ValueError("Shared secret is not provided.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(secret.encode('utf-8'))

def decrypt_from_client(encrypted_text: str, secret: str) -> str:
    """Decrypts a base64 encoded string encrypted with AES-GCM from the client."""
    if not encrypted_text or not secret:
        return ""
    try:
        key = _derive_key_from_secret(secret)
        data = base64.b64decode(encrypted_text.encode('utf-8'))
        iv = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode('utf-8')
    except Exception:
        # Decryption failed (e.g., wrong key, corrupted data)
        return ""

def encrypt_for_api(data_str: str) -> str:
    """
    Encrypts a string for API communication using AES-GCM.
    """
    if not API_SECRET_KEY:
        raise ValueError("API_SECRET_KEY is not set in environment variables.")
        
    try:
        key = _derive_key_from_secret(API_SECRET_KEY)
        iv = os.urandom(12) # GCM için 12 byte IV
        
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        
        ciphertext = encryptor.update(data_str.encode('utf-8')) + encryptor.finalize()
        
        # IV + tag + ciphertext birleştirilerek base64 olarak kodlanır
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode('utf-8')
    except Exception as e:
        # Hata durumunda boş bir dize veya uygun bir hata yönetimi
        return ""

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if not all([API_SECRET_KEY, CLOUDFLARE_WORKER_URL_B64, CLOUDFLARE_ACCESS_KEY]):
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": False, "message": "Server configuration error: Missing environment variables."}).encode())
            return

        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            client_payload = json.loads(post_data)

            # Decrypt the payload received from the client
            encrypted_data_from_client = client_payload.get("encrypted_data")
            if not encrypted_data_from_client:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Bad Request: Missing 'encrypted_data'."}).encode())
                return

            decrypted_payload_str = decrypt_from_client(encrypted_data_from_client, API_SECRET_KEY)
            if not decrypted_payload_str:
                self.send_response(403)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Forbidden: Invalid encryption or key."}).encode())
                return
            
            client_ip = self.headers.get('X-Forwarded-For', self.client_address[0])

            decrypted_payload = json.loads(decrypted_payload_str)
            decrypted_payload['client_ip'] = client_ip
            
            payload_to_encrypt_str = json.dumps(decrypted_payload)
            encrypted_payload_for_cf = encrypt_for_api(payload_to_encrypt_str)
            final_data_to_send = {"encrypted_data": encrypted_payload_for_cf}

            decoded_url = base64.b64decode(CLOUDFLARE_WORKER_URL_B64).decode('utf-8')

            headers = {
                'Content-Type': 'application/json',
                'X-Custom-Auth-Key': CLOUDFLARE_ACCESS_KEY
            }

            response = requests.post(decoded_url, data=json.dumps(final_data_to_send), headers=headers, timeout=20)
            
            self.send_response(response.status_code)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(response.content)

        except json.JSONDecodeError:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": False, "message": "Bad Request: Invalid JSON."}).encode())
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": False, "message": f"An internal server error occurred: {str(e)}"}).encode())
