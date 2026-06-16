from flask import Flask, render_template, request, jsonify
import requests, urllib.parse, hashlib, urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# AES (unused abhi but rakha hai)
AeSkEy, AeSiV = b'Yg&tc%DEuh6%Zc^8', b'6oyZDr22E3ychjM%'

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/get_info', methods=['POST'])
def get_info():
    token = request.json.get('token')
    res_data = {}
    # Profile
    try:
        p_url = f"https://api-otrss.garena.com/support/callback/?access_token={token}"
        p_res = requests.get(p_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=12)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(p_res.url).query)
        res_data['profile'] = {
            'uid': q.get('account_id', ['Unknown'])[0],
            'nickname': q.get('nickname', ['Unknown'])[0],
            'region': q.get('region', ['Unknown'])[0]
        }
    except:
        res_data['profile'] = {'uid': 'Error', 'nickname': 'Error', 'region': 'Error'}

    # Bind Info
    try:
        url = "https://100067.connect.garena.com/game/account_security/bind:get_bind_info"
        resp = requests.get(url, params={'app_id': "100067", 'access_token': token},
                           headers={'User-Agent': "GarenaMSDK/4.0.19P9"}, timeout=12)
        data = resp.json() if resp.status_code == 200 else {}
        res_data['bind'] = {
            'email': data.get("email", "None"),
            'email_to_be': data.get("email_to_be", "None"),
            'countdown': data.get("request_exec_countdown", 0)
        }
    except:
        res_data['bind'] = {'email': 'Error', 'email_to_be': 'Error', 'countdown': 0}

    return jsonify({'status': 'success', 'data': res_data})

@app.route('/api/send_otp', methods=['POST'])
def send_otp():
    token = request.json.get('token')
    email = request.json.get('email')
    headers = {"User-Agent": "GarenaMSDK/4.0.30", "Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post("https://100067.connect.garena.com/game/account_security/bind:send_otp",
                      headers=headers,
                      data={"email": email, "locale": "en_PK", "region": "PK", "app_id": "100067", "access_token": token})
    return jsonify(r.json() if r.status_code == 200 else {'result': -1})

@app.route('/api/verify_identity', methods=['POST'])
def verify_identity():
    data = request.json
    token = data.get('token')
    email = data.get('email')
    sec_code = data.get('sec_code')

    payload = {"email": email, "app_id": "100067", "access_token": token}
    if sec_code:
        payload["secondary_password"] = hashlib.sha256(sec_code.encode('utf-8')).hexdigest()
    else:
        payload["otp"] = data.get('otp')

    headers = {"User-Agent": "GarenaMSDK/4.0.30", "Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_identity",
                      headers=headers, data=payload)
    return jsonify(r.json() if r.status_code == 200 else {'result': -1})

@app.route('/api/rebind', methods=['POST'])
def rebind():
    data = request.json
    token = data.get('token')
    id_tok = data.get('id_token')
    new_email = data.get('new_email')
    otp = data.get('otp')

    headers = {"User-Agent": "GarenaMSDK/4.0.30", "Content-Type": "application/x-www-form-urlencoded"}

    # Verify OTP
    r_v = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_otp",
                        headers=headers,
                        data={"email": new_email, "app_id": "100067", "access_token": token, "otp": otp})
    try:
        v_tok = r_v.json().get("verifier_token")
    except:
        v_tok = None

    if not v_tok:
        return jsonify({'result': -1, 'error': 'Invalid OTP'})

    # Create Rebind
    r_reb = requests.post("https://100067.connect.garena.com/game/account_security/bind:create_rebind_request",
                          headers=headers,
                          data={"identity_token": id_tok, "email": new_email, "app_id": "100067",
                                "verifier_token": v_tok, "access_token": token})
    return jsonify(r_reb.json() if r_reb.status_code == 200 else {'result': -1})

if __name__ == "__main__":
    app.run(debug=True)
