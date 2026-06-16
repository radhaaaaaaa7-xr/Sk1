from flask import Flask, render_template, request, jsonify
import requests, urllib.parse, hashlib, sys, urllib3
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/get_info', methods=['POST'])
def get_info():
    token = request.json.get('token')
    res_data = {}
    try:
        p_url = f"https://api-otrss.garena.com/support/callback/?access_token={token}"
        p_res = requests.get(p_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(p_res.url).query)
        res_data['profile'] = {
            'uid': q.get('account_id', ['Unknown'])[0],
            'nickname': q.get('nickname', ['Unknown'])[0],
            'region': q.get('region', ['Unknown'])[0]
        }
    except: res_data['profile'] = {'uid': 'Error', 'nickname': 'Error', 'region': 'Error'}

    try:
        url = "https://100067.connect.garena.com/game/account_security/bind:get_bind_info"
        response = requests.get(url, params={'app_id': "100067", 'access_token': token}, headers={'User-Agent': "GarenaMSDK/4.0.19P9"}, timeout=10).json()
        res_data['bind'] = {
            'email': response.get("email", "None"),
            'email_to_be': response.get("email_to_be", "None"),
            'countdown': response.get("request_exec_countdown", 0)
        }
    except Exception as e: return jsonify({'status': 'error', 'msg': str(e)})
    return jsonify({'status': 'success', 'data': res_data})
@app.route('/api/send_otp', methods=['POST'])
def send_otp():
    token, email = request.json.get('token'), request.json.get('email')
    url = "https://100067.connect.garena.com/game/account_security/bind:send_otp"
    r = requests.post(url, headers={"User-Agent": "GarenaMSDK/4.0.30"}, data={"email": email, "locale": "en_PK", "region": "PK", "app_id": "100067", "access_token": token})
    return jsonify(r.json() if r.status_code==200 else {'result': -1})

@app.route('/api/verify_identity', methods=['POST'])
def verify_identity():
    data = request.json
    token, email, sec_code = data.get('token'), data.get('email'), data.get('sec_code')
    payload = {"email": email, "app_id": "100067", "access_token": token}
    if sec_code: payload["secondary_password"] = hashlib.sha256(sec_code.encode('utf-8')).hexdigest()
    else: payload["otp"] = data.get('otp')
    
    r = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_identity", headers={"User-Agent": "GarenaMSDK/4.0.30"}, data=payload)
    return jsonify(r.json() if r.status_code==200 else {'result': -1})

@app.route('/api/rebind', methods=['POST'])
def rebind():
    data = request.json
    token, id_tok, new_email, otp = data.get('token'), data.get('id_token'), data.get('new_email'), data.get('otp')
    headers = {"User-Agent": "GarenaMSDK/4.0.30"}
    r_v = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_otp", headers=headers, data={"email": new_email, "app_id": "100067", "access_token": token, "otp": otp})
    v_tok = r_v.json().get("verifier_token")
    if not v_tok: return jsonify({'result': -1, 'error': 'Invalid OTP'})
    
    r_reb = requests.post("https://100067.connect.garena.com/game/account_security/bind:create_rebind_request", headers=headers, data={"identity_token": id_tok, "email": new_email, "app_id": "100067", "verifier_token": v_tok, "access_token": token})
    return jsonify(r_reb.json())

if __name__ == "__main__":
    app.run(debug=True)
