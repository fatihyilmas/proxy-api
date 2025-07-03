import os
import json
import requests
import base64
import hashlib
from http.server import BaseHTTPRequestHandler
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- Environment Variables ---
# These must be set in your hosting environment (e.g., Vercel, AWS).
API_SECRET_KEY = os.environ.get("API_SECRET_KEY")
CLOUDFLARE_WORKER_URL_B64 = os.environ.get("CLOUDFLARE_WORKER_URL_B64")
CLOUDFLARE_ACCESS_KEY = os.environ.get("CLOUDFLARE_ACCESS_KEY")

def encrypt_for_api(data_str: str) -> str:
    """
    Encrypts a string for API communication, compatible with AES-256-CBC.
    """
    if not API_SECRET_KEY:
        raise ValueError("API_SECRET_KEY is not set in environment variables.")
        
    key = hashlib.sha256(API_SECRET_KEY.encode()).digest()
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data_str.encode()) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    
    return base64.b64encode(iv + ct).decode('utf-8')

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

            # Encrypt the payload received from the client
            payload_str = json.dumps(client_payload)
            encrypted_payload_str = encrypt_for_api(payload_str)
            final_data_to_send = {"encrypted_data": encrypted_payload_str}

            # Get the real Cloudflare Worker URL
            decoded_url = base64.b64decode(CLOUDFLARE_WORKER_URL_B64).decode('utf-8')

            headers = {
                'Content-Type': 'application/json',
                'X-Custom-Auth-Key': CLOUDFLARE_ACCESS_KEY
            }

            # Forward the request to the Cloudflare Worker
            response = requests.post(decoded_url, data=json.dumps(final_data_to_send), headers=headers, timeout=20)
            
            # Send the response from the Cloudflare Worker back to the client
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
