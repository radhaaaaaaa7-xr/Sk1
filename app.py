from flask import Flask, request, jsonify, render_template
import requests, urllib.parse, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

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

def get_headers():
    return {"User-Agent": "GarenaMSDK/4.0.30", "Content-Type": "application/x-www-form-urlencoded"} #[span_4](start_span)[span_4](end_span)

@app.route('/')
def index():
    return render_template('index.html')

# 1. Player Info Feature
@app.route('/api/player_info', methods=['POST'])
def player_info():
    access_token = request.json.get('token')
    try:
        player_url = f"https://api-otrss.garena.com/support/callback/?access_token={access_token}" #[span_5](start_span)[span_5](end_span)
        p_res = requests.get(player_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15, allow_redirects=True) #[span_6](start_span)[span_6](end_span)
        q_params = urllib.parse.parse_qs(urllib.parse.urlparse(p_res.url).query) #[span_7](start_span)[span_7](end_span)
        return jsonify({
            "result": 0,
            "UID": q_params.get('account_id', ['Unknown'])[0], #[span_8](start_span)[span_8](end_span)
            "Nickname": q_params.get('nickname', ['Unknown'])[0], #[span_9](start_span)[span_9](end_span)
            "Region": q_params.get('region', ['Unknown'])[0] #[span_10](start_span)[span_10](end_span)
        })
    except Exception as e: return jsonify({"result": 1, "error": "Failed to fetch Player Info"})

# 2. Check Bind Info
@app.route('/api/bind_info', methods=['POST'])
def bind_info():
    access_token = request.json.get('token')
    try:
        url = "https://100067.connect.garena.com/game/account_security/bind:get_bind_info" #[span_11](start_span)[span_11](end_span)
        payload = {'app_id': "100067", 'access_token': access_token} #[span_12](start_span)[span_12](end_span)
        headers = {'User-Agent': "GarenaMSDK/4.0.19P9", 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip"} #[span_13](start_span)[span_13](end_span)
        response = requests.get(url, params=payload, headers=headers, timeout=15) #[span_14](start_span)[span_14](end_span)
        return jsonify(response.json())
    except Exception as e: return jsonify({"result": 1, "error": str(e)})

@app.route('/api/send_otp', methods=['POST'])
def send_otp():
    data = request.json
    payload = {"email": data.get('email'), "locale": "en_PK", "region": "PK", "app_id": "100067", "access_token": data.get('token')} #[span_15](start_span)[span_15](end_span)
    try:
        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:send_otp", headers=get_headers(), data=payload) #[span_16](start_span)[span_16](end_span)
        return jsonify(r.json())
    except Exception as e: return jsonify({"result": 1, "error": str(e)})

@app.route('/api/verify_otp', methods=['POST'])
def verify_otp():
    data = request.json
    payload = {"app_id": "100067", "access_token": data.get('token'), "email": data.get('email'), "code": data.get('otp'), "otp": data.get('otp')} #[span_17](start_span)[span_17](end_span)
    try:
        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_otp", headers=get_headers(), data=payload) #[span_18](start_span)[span_18](end_span)
        return jsonify(r.json())
    except Exception as e: return jsonify({"result": 1, "error": str(e)})

@app.route('/api/bind_email', methods=['POST'])
def bind_email():
    data = request.json
    payload = {"email": data.get('email'), "app_id": "100067", "access_token": data.get('token'), "verifier_token": data.get('v_token'), "secondary_password": data.get('sec_code')} #[span_19](start_span)[span_19](end_span)
    try:
        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:create_bind_request", headers=get_headers(), data=payload) #[span_20](start_span)[span_20](end_span)
        return jsonify(r.json())
    except Exception as e: return jsonify({"result": 1, "error": str(e)})

@app.route('/api/verify_identity', methods=['POST'])
def verify_identity():
    data = request.json
    payload = {"email": data.get('email'), "app_id": "100067", "access_token": data.get('token')} #[span_21](start_span)[span_21](end_span)
    if data.get('otp'): payload['otp'] = data.get('otp') #[span_22](start_span)[span_22](end_span)
    elif data.get('sec_code'): payload['secondary_password'] = hashlib.sha256(data.get('sec_code').encode('utf-8')).hexdigest() #[span_23](start_span)[span_23](end_span)
    try:
        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_identity", headers=get_headers(), data=payload) #[span_24](start_span)[span_24](end_span)
        return jsonify(r.json())
    except Exception as e: return jsonify({"result": 1, "error": str(e)})

@app.route('/api/change_email', methods=['POST'])
def change_email():
    data = request.json
    payload = {"identity_token": data.get('id_token'), "email": data.get('new_email'), "app_id": "100067", "verifier_token": data.get('v_token'), "access_token": data.get('token')} #[span_25](start_span)[span_25](end_span)
    try:
        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:create_rebind_request", headers=get_headers(), data=payload) #[span_26](start_span)[span_26](end_span)
        return jsonify(r.json())
    except Exception as e: return jsonify({"result": 1, "error": str(e)})

@app.route('/api/unbind_email', methods=['POST'])
def unbind_email():
    data = request.json
    payload = {"app_id": "100067", "access_token": data.get('token'), "identity_token": data.get('id_token')} #[span_27](start_span)[span_27](end_span)
    try:
        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:create_unbind_request", headers=get_headers(), data=payload) #[span_28](start_span)[span_28](end_span)
        return jsonify(r.json())
    except Exception as e: return jsonify({"result": 1, "error": str(e)})

@app.route('/api/cancel_bind', methods=['POST'])
def cancel_bind():
    data = request.json
    try:
        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:cancel_request", headers=get_headers(), data={"app_id": "100067", "access_token": data.get('token')}) #[span_29](start_span)[span_29](end_span)
        return jsonify(r.json())
    except Exception as e: return jsonify({"result": 1, "error": str(e)})

@app.route('/api/bound_platforms', methods=['POST'])
def bound_platforms():
    data = request.json
    try:
        r = requests.get("https://100067.connect.garena.com/bind/app/platform/info/get", params={"access_token": data.get('token')}, headers=get_headers()) #[span_30](start_span)[span_30](end_span)
        d = r.json()
        P_MAP = {1: "Garena", 3: "Facebook", 4: "Guest", 5: "VK", 8: "Google", 11: "X (Twitter)", 13: "Apple ID"} #[span_31](start_span)[span_31](end_span)
        return jsonify({"result": 0, "platforms": [P_MAP.get(p_id, f'Unknown ({p_id})') for p_id in d.get("bounded_accounts", [])]}) #[span_32](start_span)[span_32](end_span)
    except Exception as e: return jsonify({"result": 1, "error": str(e)})

@app.route('/api/eat_to_token', methods=['POST'])
def eat_to_token():
    eat_url = request.json.get('eat')
    if "?" in eat_url: eat_url = urllib.parse.parse_qs(urllib.parse.urlparse(eat_url).query).get('eat', [''])[0] #[span_33](start_span)[span_33](end_span)
    try:
        res = requests.get(f"https://api-otrss.garena.com/support/callback/?access_token={eat_url}", headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True) #[span_34](start_span)[span_34](end_span)
        return jsonify({"result": 0, "access_token": urllib.parse.parse_qs(urllib.parse.urlparse(res.url).query).get('access_token', [''])[0]}) #[span_35](start_span)[span_35](end_span)
    except Exception as e: return jsonify({"result": 1, "error": "Failed to extract"})

@app.route('/api/login_history', methods=['POST'])
def login_history():
    jwt_token = request.json.get('token')
    if "ey" not in jwt_token: return jsonify({"result": 1, "error": "JWT Token required"})
    try:
        r = requests.post("https://client.ind.freefiremobile.com/GetLoginHistory", headers={"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/x-www-form-urlencoded"}, data=enc(b""), verify=False) #[span_36](start_span)[span_36](end_span)
        d = dec(r.content) #[span_37](start_span)[span_37](end_span)
        records, offset = [], 0
        while offset < len(d):
            tag, offset = read_varint(d, offset) #[span_38](start_span)[span_38](end_span)
            if (tag & 7) == 2:
                length, offset = read_varint(d, offset) #[span_39](start_span)[span_39](end_span)
                records.append(parse_record(d[offset:offset+length])) #[span_40](start_span)[span_40](end_span)
                offset += length #[span_41](start_span)[span_41](end_span)
            else: break
        return jsonify({"result": 0, "login_records": records})
    except Exception as e: return jsonify({"result": 1, "error": "Decode Failed"})

if __name__ == '__main__':
    app.run(debug=True)
