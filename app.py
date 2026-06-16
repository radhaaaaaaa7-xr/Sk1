from flask import Flask, render_template, request, jsonify
import requests, urllib.parse, hashlib, urllib3

app = Flask(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "GarenaMSDK/4.0.30",
    "Content-Type": "application/x-www-form-urlencoded"
}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/get_info', methods=['POST'])
def get_info():
    token = request.json.get('token')
    res_data = {}
    try:
        p_url = f"https://api-otrss.garena.com/support/callback/?access_token={token}"
        p_res = requests.get(p_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(p_res.url).query)
        res_data['profile'] = {
            'uid': q.get('account_id', ['Unknown'])[0],
            'nickname': q.get('nickname', ['Unknown'])[0],
            'region': q.get('region', ['Unknown'])[0]
        }
    except:
        res_data['profile'] = {'uid': 'Error', 'nickname': 'Error', 'region': 'Error'}

    try:
        url = "https://100067.connect.garena.com/game/account_security/bind:get_bind_info"
        resp = requests.get(url, params={'app_id': "100067", 'access_token': token}, headers=HEADERS, timeout=15)
        data = resp.json()
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
    data = request.json
    r = requests.post("https://100067.connect.garena.com/game/account_security/bind:send_otp",
                      headers=HEADERS, data={
                          "email": data.get('email'),
                          "locale": "en_PK",
                          "region": "PK",
                          "app_id": "100067",
                          "access_token": data.get('token')
                      })
    return jsonify(r.json() if r.status_code == 200 else {'result': -1})

@app.route('/api/verify_identity', methods=['POST'])
def verify_identity():
    data = request.json
    payload = {
        "email": data.get('email'),
        "app_id": "100067",
        "access_token": data.get('token')
    }
    if data.get('sec_code'):
        payload["secondary_password"] = hashlib.sha256(data['sec_code'].encode()).hexdigest()
    else:
        payload["otp"] = data.get('otp')

    r = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_identity",
                      headers=HEADERS, data=payload)
    return jsonify(r.json() if r.status_code == 200 else {'result': -1})

@app.route('/api/rebind', methods=['POST'])
def rebind():
    data = request.json
    headers = HEADERS.copy()
    # Verify OTP for new email
    r_v = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_otp",
                        headers=headers, data={
                            "email": data.get('new_email'),
                            "app_id": "100067",
                            "access_token": data.get('token'),
                            "otp": data.get('otp')
                        })
    v_tok = r_v.json().get("verifier_token") if r_v.status_code == 200 else None
    if not v_tok:
        return jsonify({'result': -1, 'error': 'Invalid OTP'})

    # Rebind
    r_reb = requests.post("https://100067.connect.garena.com/game/account_security/bind:create_rebind_request",
                          headers=headers, data={
                              "identity_token": data.get('id_token'),
                              "email": data.get('new_email'),
                              "app_id": "100067",
                              "verifier_token": v_tok,
                              "access_token": data.get('token')
                          })
    return jsonify(r_reb.json() if r_reb.status_code == 200 else {'result': -1})

# === NEW: Bind New Email ===
@app.route('/api/bind_new', methods=['POST'])
def bind_new():
    data = request.json
    headers = HEADERS.copy()
    # send OTP (already covered)
    # verify OTP
    r_v = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_otp",
                        headers=headers, data={
                            "email": data.get('email'),
                            "app_id": "100067",
                            "access_token": data.get('token'),
                            "otp": data.get('otp')
                        })
    v_tok = r_v.json().get("verifier_token") if r_v.status_code == 200 else None
    if not v_tok:
        return jsonify({'result': -1, 'error': 'Invalid OTP'})

    # Create Bind Request
    r_bind = requests.post("https://100067.connect.garena.com/game/account_security/bind:create_bind_request",
                           headers=headers, data={
                               "email": data.get('email'),
                               "app_id": "100067",
                               "access_token": data.get('token'),
                               "verifier_token": v_tok,
                               "secondary_password": hashlib.sha256(data.get('sec_code', '123456').encode()).hexdigest() if data.get('sec_code') else ""
                           })
    return jsonify(r_bind.json() if r_bind.status_code == 200 else {'result': -1})

# === NEW: Unbind ===
@app.route('/api/unbind', methods=['POST'])
def unbind():
    data = request.json
    headers = HEADERS.copy()
    r = requests.post("https://100067.connect.garena.com/game/account_security/bind:create_unbind_request",
                      headers=headers, data={
                          "app_id": "100067",
                          "access_token": data.get('token'),
                          "identity_token": data.get('id_token')
                      })
    return jsonify(r.json() if r.status_code == 200 else {'result': -1})
