from flask import Flask, render_template, request, jsonify
import requests
import urllib.parse
import hashlib

app = Flask(__name__)

# वेब सर्वर पर टोकन सेव रखने के लिए एक टेम्परेरी डिक्शनरी
SESSION_CACHE = {}

@app.route('/')
def home():
    return render_template('index.html')

# 1. Load Account Info API (खिलाड़ी की जानकारी और पुराना ईमेल निकालना)
@app.route('/api/load_info', methods=['POST'])
def load_info():
    data = request.json
    token = data.get('token')

    try:
        # Player Profile Fetch 
        p_res = requests.get(f"https://api-otrss.garena.com/support/callback/?access_token={token}", headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
        q_params = urllib.parse.parse_qs(urllib.parse.urlparse(p_res.url).query)
        uid = q_params.get('account_id', ['-'])[0]
        nickname = q_params.get('nickname', ['-'])[0]
        region = q_params.get('region', ['-'])[0]

        # Bind Info Fetch
        b_url = "https://100067.connect.garena.com/game/account_security/bind:get_bind_info"
        b_res = requests.get(b_url, params={'app_id': "100067", 'access_token': token}, headers={'User-Agent': "GarenaMSDK/4.0.19P9"}).json()
        current_email = b_res.get("email", "-")

        # ईमेल को कैश में सेव करना ताकि आगे Verify Code के टाइम काम आए
        if token not in SESSION_CACHE:
            SESSION_CACHE[token] = {}
        SESSION_CACHE[token]['old_email'] = current_email if current_email != "-" else ""

        return jsonify({
            "status": "success", 
            "message": "Account & Bind Data Fetched Successfully!", 
            "data": {
                "uid": uid,
                "nickname": nickname,
                "region": region,
                "email": current_email
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": f"Error loading info: {str(e)}"})


# 2. Verify Security Code API (6 डिजिट कोड को हैश करके Garena को भेजना)
@app.route('/api/verify_code', methods=['POST'])
def verify_code():
    data = request.json
    token = data.get('token')
    sec_code = data.get('code')
    
    # पुराना ईमेल कैश से उठाना
    old_email = SESSION_CACHE.get(token, {}).get('old_email', '')
    if not old_email:
        return jsonify({"status": "error", "message": "Old email not found! Please click 'Load Account Info' first."})

    try:
        # Termux वाला शा256 हैशिंग लॉजिक
        hashed_sec = hashlib.sha256(sec_code.encode('utf-8')).hexdigest()
        headers = {"User-Agent": "GarenaMSDK/4.0.30", "Content-Type": "application/x-www-form-urlencoded"}
        
        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_identity", 
                          headers=headers, 
                          data={"email": old_email, "app_id": "100067", "access_token": token, "secondary_password": hashed_sec})
        
        response_data = r.json()
        
        # अगर identity_token मिलता है तो इसे कैश में सेव कर लो 
        if "identity_token" in response_data:
            SESSION_CACHE[token]['id_tok'] = response_data['identity_token']
            return jsonify({"status": "success", "message": "Security Code Bypassed! Now Send OTP to New Email."})
        else:
            return jsonify({"status": "error", "message": "Verification Failed! Incorrect Security Code."})
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


# 3. Send OTP API (नए जीमेल पर ओटीपी भेजना)
@app.route('/api/send_otp', methods=['POST'])
def send_otp():
    data = request.json
    token = data.get('token')
    new_email = data.get('email')

    try:
        headers = {"User-Agent": "GarenaMSDK/4.0.30", "Content-Type": "application/x-www-form-urlencoded"}
        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:send_otp", 
                          headers=headers, 
                          data={"email": new_email, "locale": "en_PK", "region": "PK", "app_id": "100067", "access_token": token})
        
        result_code = r.json().get('result')
        if result_code == 0:
            return jsonify({"status": "success", "message": f"OTP successfully sent to {new_email}!"})
        else:
            return jsonify({"status": "error", "message": f"Failed to send OTP. (Result Code: {result_code})"})
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


# 4. Confirm Rebind API (ओटीपी वेरीफाई करके नया जीमेल सेट करना)
@app.route('/api/confirm_rebind', methods=['POST'])
def confirm_rebind():
    data = request.json
    token = data.get('token')
    new_email = data.get('email')
    otp = data.get('otp')
    
    # कैश से identity_token उठाना जो स्टेप 2 में सेव किया था
    id_tok = SESSION_CACHE.get(token, {}).get('id_tok')
    
    if not id_tok:
        return jsonify({"status": "error", "message": "Identity Token Missing! Please bypass Security Code first."})

    try:
        headers = {"User-Agent": "GarenaMSDK/4.0.30", "Content-Type": "application/x-www-form-urlencoded"}

        # पहले नए ईमेल का OTP Verify करो (इससे verifier_token मिलेगा)
        r_v = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_otp", 
                            headers=headers, 
                            data={"email": new_email, "app_id": "100067", "access_token": token, "otp": otp})
        
        v_tok = r_v.json().get("verifier_token")
        if not v_tok:
            return jsonify({"status": "error", "message": "Incorrect OTP! Verification failed."})

        # फाइनली Rebind (चेंज ईमेल) रिक्वेस्ट लगाओ
        r_reb = requests.post("https://100067.connect.garena.com/game/account_security/bind:create_rebind_request", 
                              headers=headers, 
                              data={"identity_token": id_tok, "email": new_email, "app_id": "100067", "verifier_token": v_tok, "access_token": token})
        
        if r_reb.json().get('result') == 0:
            # काम हो जाने पर कैश डिलीट कर दो
            del SESSION_CACHE[token]
            return jsonify({"status": "success", "message": "Rebind Successful! Email has been changed."})
        else:
            return jsonify({"status": "error", "message": "Final Bind Failed! Check token or limits."})
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# Vercel के लिए सेटअप
app.wsgi_app = app.wsgi_app

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
      
