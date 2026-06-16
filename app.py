from flask import Flask, request, jsonify, render_template
import requests, urllib.parse, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ==========================================
# AES ENCRYPTION & PROTOBUF HELPERS (For Login History)
# ==========================================
AeSkEy, AeSiV = b'Yg&tc%DEuh6%Zc^8', b'6oyZDr22E3ychjM%'

def enc(d): return AES.new(AeSkEy, AES.MODE_CBC, AeSiV).encrypt(pad(d, 16))
def dec(d): return unpad(AES.new(AeSkEy, AES.MODE_CBC, AeSiV).decrypt(d), 16)

def read_varint(data, offset):
    res, shift = 0, 0
    while True:
        if offset >= len(data): break
        b = data[offset]; offset += 1
        res |= (b & 0x7f) << shift
        if not (b & 0x80): break
        shift += 7
    return res, offset

def parse_record(data):
    rec, offset = {}, 0
    while offset < len(data):
        tag, offset = read_varint(data, offset)
        wt, f = tag & 7, tag >> 3
        if wt == 0:
            val, offset = read_varint(data, offset)
            if f == 1: rec['ts'] = val
            elif f == 2: rec['ram'] = val
        elif wt == 2:
            length, offset = read_varint(data, offset)
            val = data[offset:offset+length]; offset += length
            if f == 3: rec['dev'] = val.decode(errors='ignore')
            elif f == 4: rec['arch'] = val.decode(errors='ignore')
        else: break
    return rec

# ==========================================
# COMMON HEADERS
# ==========================================
def get_headers():
    return {"User-Agent": "GarenaMSDK/4.0.30", "Content-Type": "application/x-www-form-urlencoded"}

# ==========================================
# ROUTES & APIs
# ==========================================
@app.route('/')
def index():
    return render_template('index.html')

# 1. Check Bind Info
@app.route('/api/bind_info', methods=['POST'])
def bind_info():
    access_token = request.json.get('token')
    try:
        url = "https://100067.connect.garena.com/game/account_security/bind:get_bind_info"
        response = requests.get(url, params={'app_id': "100067", 'access_token': access_token}, headers=get_headers(), timeout=15)
        return jsonify(response.json())
    except Exception as e: return jsonify({"error": str(e)}), 500

# 2. Send OTP (For Bind, Change, or Unbind)
@app.route('/api/send_otp', methods=['POST'])
def send_otp():
    data = request.json
    payload = {"email": data.get('email'), "locale": "en_PK", "region": "PK", "app_id": "100067", "access_token": data.get('token')}
    try:
        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:send_otp", headers=get_headers(), data=payload)
        return jsonify(r.json())
    except Exception as e: return jsonify({"error": str(e)}), 500

# 3. Verify OTP (Returns verifier_token)
@app.route('/api/verify_otp', methods=['POST'])
def verify_otp():
    data = request.json
    payload = {"app_id": "100067", "access_token": data.get('token'), "email": data.get('email'), "code": data.get('otp'), "otp": data.get('otp')}
    try:
        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_otp", headers=get_headers(), data=payload)
        return jsonify(r.json())
    except Exception as e: return jsonify({"error": str(e)}), 500

# 4. Create Bind Request
@app.route('/api/bind_email', methods=['POST'])
def bind_email():
    data = request.json
    payload = {"email": data.get('email'), "app_id": "100067", "access_token": data.get('token'), "verifier_token": data.get('v_token'), "secondary_password": data.get('sec_code')}
    try:
        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:create_bind_request", headers=get_headers(), data=payload)
        return jsonify(r.json())
    except Exception as e: return jsonify({"error": str(e)}), 500

# 5. Verify Identity (For Unbind/Change Email via OTP or Sec Code)
@app.route('/api/verify_identity', methods=['POST'])
def verify_identity():
    data = request.json
    payload = {"email": data.get('email'), "app_id": "100067", "access_token": data.get('token')}
    
    if data.get('otp'):
        payload['otp'] = data.get('otp')
    elif data.get('sec_code'):
        payload['secondary_password'] = hashlib.sha256(data.get('sec_code').encode('utf-8')).hexdigest()

    try:
        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_identity", headers=get_headers(), data=payload)
        return jsonify(r.json()) # identity_token मिलेगा
    except Exception as e: return jsonify({"error": str(e)}), 500

# 6. Change Email (Create Rebind Request)
@app.route('/api/change_email', methods=['POST'])
def change_email():
    data = request.json
    payload = {"identity_token": data.get('id_token'), "email": data.get('new_email'), "app_id": "100067", "verifier_token": data.get('v_token'), "access_token": data.get('token')}
    try:
        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:create_rebind_request", headers=get_headers(), data=payload)
        return jsonify(r.json())
    except Exception as e: return jsonify({"error": str(e)}), 500

# 7. Unbind Email
@app.route('/api/unbind_email', methods=['POST'])
def unbind_email():
    data = request.json
    payload = {"app_id": "100067", "access_token": data.get('token'), "identity_token": data.get('id_token')}
    try:
        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:create_unbind_request", headers=get_headers(), data=payload)
        return jsonify(r.json())
    except Exception as e: return jsonify({"error": str(e)}), 500

# 8. Cancel Bind Request
@app.route('/api/cancel_bind', methods=['POST'])
def cancel_bind():
    data = request.json
    try:
        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:cancel_request", headers=get_headers(), data={"app_id": "100067", "access_token": data.get('token')})
        return jsonify(r.json())
    except Exception as e: return jsonify({"error": str(e)}), 500

# 9. Check Bound Accounts Platforms
@app.route('/api/bound_platforms', methods=['POST'])
def bound_platforms():
    data = request.json
    try:
        r = requests.get("https://100067.connect.garena.com/bind/app/platform/info/get", params={"access_token": data.get('token')}, headers=get_headers())
        d = r.json()
        P_MAP = {1: "Garena", 3: "Facebook", 4: "Guest", 5: "VK", 8: "Google", 11: "X (Twitter)", 13: "Apple ID"}
        platforms = [P_MAP.get(p_id, f'Unknown ({p_id})') for p_id in d.get("bounded_accounts", [])]
        return jsonify({"platforms": platforms})
    except Exception as e: return jsonify({"error": str(e)}), 500

# 10. Eat to Access Token
@app.route('/api/eat_to_token', methods=['POST'])
def eat_to_token():
    eat_url = request.json.get('eat')
    if "?" in eat_url: eat_url = urllib.parse.parse_qs(urllib.parse.urlparse(eat_url).query).get('eat', [''])[0]
    try:
        res = requests.get(f"https://api-otrss.garena.com/support/callback/?access_token={eat_url}", headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
        token = urllib.parse.parse_qs(urllib.parse.urlparse(res.url).query).get('access_token', [''])[0]
        return jsonify({"access_token": token})
    except Exception as e: return jsonify({"error": "Failed to extract token"}), 500

# 11. Get Login History (AES Decryption)
@app.route('/api/login_history', methods=['POST'])
def login_history():
    jwt_token = request.json.get('token')
    if "ey" not in jwt_token:
        return jsonify({"error": "Game JWT Token required (starts with 'ey'). Access Token will not work here."}), 400
    try:
        r = requests.post("https://client.ind.freefiremobile.com/GetLoginHistory", headers={"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/x-www-form-urlencoded"}, data=enc(b""), verify=False)
        d = dec(r.content)
        records, offset = [], 0
        while offset < len(d):
            tag, offset = read_varint(d, offset)
            if (tag & 7) == 2:
                length, offset = read_varint(d, offset)
                records.append(parse_record(d[offset:offset+length]))
                offset += length
            else: break
        return jsonify({"login_records": records})
    except Exception as e: return jsonify({"error": "Decode Failed or Token Invalid"}), 500

if __name__ == '__main__':
    app.run(debug=True)
