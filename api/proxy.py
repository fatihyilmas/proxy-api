import os
import json
import base64
import hashlib
from http.server import BaseHTTPRequestHandler
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sys

def derive_key_python(secret: str) -> bytes:
    return hashlib.sha256(secret.encode('utf-8')).digest()

def decrypt_python_logic(encrypted_data_b64: str, secret_key: str) -> str | None:
    try:
        key = derive_key_python(secret_key)
        data = base64.b64decode(encrypted_data_b64)
        if len(data) < 16: return None
        iv, ciphertext = data[:16], data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(padded_data) + unpadder.finalize()
        
        return unpadded_data.decode('utf-8')
    except Exception as e:
        print(f"Python iş mantığı deşifreleme hatası: {e}", file=sys.stderr)
        return None

ENCRYPTED_PROXY_LOGIC = os.environ.get('ENCRYPTED_PROXY_LOGIC')
DECRYPTION_KEY_PROXY = os.environ.get('DECRYPTION_KEY_PROXY')

decrypted_proxy_logic_code = None

if ENCRYPTED_PROXY_LOGIC and DECRYPTION_KEY_PROXY:
    decrypted_proxy_logic_code = decrypt_python_logic(ENCRYPTED_PROXY_LOGIC, DECRYPTION_KEY_PROXY)
    if not decrypted_proxy_logic_code:
        print("ERROR: Decrypted proxy logic is empty. Check ENCRYPTED_PROXY_LOGIC and DECRYPTION_KEY_PROXY.", file=sys.stderr)
else:
    print("ERROR: ENCRYPTED_PROXY_LOGIC or DECRYPTION_KEY_PROXY environment variables are missing.", file=sys.stderr)

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if not decrypted_proxy_logic_code:
            self._send_response(500, {'success': False, 'message': 'Server configuration error: Business logic could not be loaded.'})
            return
        
        env = {
            "API_SECRET_KEY": os.environ.get('API_SECRET_KEY'),
            "CLOUDFLARE_WORKER_URL_B64": os.environ.get('CLOUDFLARE_WORKER_URL_B64'),
            "CLOUDFLARE_ACCESS_KEY": os.environ.get('CLOUDFLARE_ACCESS_KEY')
        }

        local_scope = {'request_handler_instance': self, 'env': env}
        
        try:
            exec(decrypted_proxy_logic_code, globals(), local_scope)
            local_scope['execute_proxy_business_logic'](self, env)
        except Exception as e:
            print(f"BUSINESS_LOGIC_EXECUTION_ERROR: {e}", file=sys.stderr)
            self._send_response(500, {'success': False, 'message': f'Internal server error: {str(e)}'})

    def _send_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))
