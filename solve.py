import requests
import hashlib
import json
import time
import base64
import random
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

BASE_URL = "http://51.195.24.179:8000"

AES_KEY = b"CandidateTestKey"
AES_IV = b"CandidateTest_IV"
SALT = "(9999dfhfdfdhdfsjhdfshjddhfdh5656)"

def sha256_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def md5_hash(data: str) -> str:
    return hashlib.md5(data.encode()).hexdigest()

def generate_random_string(length: int = 32) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def solve_math_proof(v1_b64: str, v2_b64: str, v3_b64: str) -> int:
    v1 = int(base64.b64decode(v1_b64).decode())
    v2 = int(base64.b64decode(v2_b64).decode())
    v3 = int(base64.b64decode(v3_b64).decode())
    return ((v1 * v2) + v3) % 1000

def decode_sequence(seq_b64_list: list) -> list:
    return [int(base64.b64decode(item).decode()) for item in seq_b64_list]

def solve_sequence_proof(sequence: list) -> int:
    return sequence[-1] + sequence[-2]

def compute_hash_chain(seed: str, iterations: int) -> str:
    result = seed
    for _ in range(iterations):
        result = sha256_hash(result)
    return result

def compute_credential_proof(email: str, password: str) -> str:
    email_hash = md5_hash(email)
    password_hash = md5_hash(password)
    salt_hex = SALT.encode('utf-8').hex()
    combined = f"{email_hash}:{password_hash}:{salt_hex}"
    return md5_hash(combined)

def encrypt_payload(payload: dict) -> str:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    payload_json = json.dumps(payload)
    padded_data = pad(payload_json.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted).decode()

def generate_mouse_data() -> list:
    mouse_data = []
    base_time = int(time.time() * 1000)
    x, y = random.randint(100, 300), random.randint(100, 300)
    
    for i in range(random.randint(15, 30)):
        x += random.randint(-20, 50)
        y += random.randint(-20, 50)
        x = max(0, min(1000, x))
        y = max(0, min(700, y))
        mouse_data.append({
            "x": x,
            "y": y,
            "t": base_time + (i * random.randint(50, 150))
        })
    
    return mouse_data

def generate_canvas_fingerprint() -> str:
    return "CLLpuugAiI6VqJlmaowP8D6+PGq3jr/ngAAAAASUVORK5CYII="

def main():
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Origin": BASE_URL,
        "Referer": f"{BASE_URL}/",
        "Connection": "keep-alive",
    })
    
    username = "testuser_" + generate_random_string(8)
    email = f"{username}@example.com"
    password = "SecureP@ssw0rd123"
    
    print(f"[*] Starting registration for: {email}")
    
    init_response = session.get(f"{BASE_URL}/api/v1/init")
    if init_response.status_code != 200:
        print(f"[-] Failed to initialize: {init_response.status_code}")
        return
    
    init_data = init_response.json()
    
    c1_b64 = init_data.get("c1", init_data.get("v1", ""))
    c2_b64 = init_data.get("c2", init_data.get("v2", ""))
    c3_b64 = init_data.get("c3", init_data.get("v3", ""))
    seq_b64 = init_data.get("seq", init_data.get("sequence", []))
    hc_seed = init_data.get("hc_s", init_data.get("hash_seed", ""))
    hc_iterations = init_data.get("hc_i", init_data.get("hash_iterations", 0))
    session_id = init_data.get("session_id", init_data.get("sid", ""))
    request_token = init_data.get("request_token", "")
    v_token = init_data.get("v_token", init_data.get("vt", ""))
    
    sequence = decode_sequence(seq_b64)
    math_proof = solve_math_proof(c1_b64, c2_b64, c3_b64)
    integrity_token = generate_random_string(32)
    
    device_data = {
        "canvas_fingerprint": generate_canvas_fingerprint(),
        "webgl_vendor": "Google Inc. (NVIDIA)",
        "webgl_renderer": "ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Direct3D11 vs_5_0 ps_5_0)",
        "math_proof": math_proof,
        "session_id": session_id,
        "request_token": request_token
    }
    
    headers = {
        "Content-Type": "application/json",
        "X-Integrity-Token": integrity_token
    }
    
    device_response = session.post(
        f"{BASE_URL}/api/v1/device_check",
        json=device_data,
        headers=headers
    )
    
    if device_response.status_code != 200:
        print(f"[-] Device check failed: {device_response.status_code}")
        return
    
    device_result = device_response.json()
    v_token = device_result.get("v_token", v_token)
    
    sequence_proof = solve_sequence_proof(sequence)
    
    user_hash = sha256_hash(email)
    nonce = generate_random_string(16)
    payload = {
        "timestamp": int(time.time() * 1000),
        "user_hash": user_hash,
        "nonce": nonce,
        "session": session_id
    }
    
    encrypted_payload = encrypt_payload(payload)
    
    security_data = {
        "payload": encrypted_payload,
        "seq_proof": sequence_proof,
        "v_token": v_token
    }
    
    security_response = session.post(
        f"{BASE_URL}/api/v1/security_verify",
        json=security_data,
        headers=headers
    )
    
    if security_response.status_code != 200:
        print(f"[-] Security verify failed: {security_response.status_code}")
        return
    
    security_result = security_response.json()
    v_token = security_result.get("v_token", v_token)
    final_token = security_result.get("final_token", "")
    
    hash_chain_proof = compute_hash_chain(hc_seed, hc_iterations)
    
    geo_data = {
        "timezone": "Asia/Kolkata",
        "country": "IN",
        "currency": "INR",
        "hash_proof": hash_chain_proof,
        "v_token": v_token,
        "session_id": session_id,
        "request_token": request_token
    }
    
    geo_response = session.post(
        f"{BASE_URL}/api/v1/geo_validate",
        json=geo_data,
        headers=headers
    )
    
    if geo_response.status_code != 200:
        print(f"[-] Geo validation failed: {geo_response.status_code}")
        return
    
    geo_result = geo_response.json()
    v_token = geo_result.get("v_token", v_token)
    final_token = geo_result.get("final_token", final_token)
    
    credential_proof = compute_credential_proof(email, password)
    mouse_data = generate_mouse_data()
    
    registration_data = {
        "username": username,
        "email": email,
        "password": password,
        "email_hash": md5_hash(email),
        "password_hash": md5_hash(password),
        "credential_proof": credential_proof,
        "mouse_data": mouse_data,
        "v_token": v_token,
        "session_id": session_id,
        "request_token": request_token,
        "final_token": final_token
    }
    
    registration_response = session.post(
        f"{BASE_URL}/api/v1/complete_registration",
        json=registration_data,
        headers=headers
    )
    
    try:
        result = registration_response.json()
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
