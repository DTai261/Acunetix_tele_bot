from flask import Flask, request, jsonify
import jwt
import requests
from config import SECRET_KEY, HOST, ACUNETIX_API_KEY
import Acunetix

headers = {"X-Auth":ACUNETIX_API_KEY,"content-type": "application/json"}

app = Flask(__name__)

def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.route('/api/start', methods=['POST'])
def start():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"response": "Missing token."}), 401

    user_id = verify_token(token)
    if not user_id:
        return jsonify({"response": "Invalid or expired token."}), 401

    return jsonify({"response": "Hello! This is a response from the /api/start endpoint."})

@app.route('/api/acunetix/<path:forward_part>', methods=['GET', 'POST'])
def acunetix(forward_part):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"response": "Missing token."}), 401

    user_id = verify_token(token)
    if not user_id:
        return jsonify({"response": "Invalid or expired token."}), 401

    url = f"{HOST}/api/v1/{forward_part}"

    if request.method == 'POST':
        response = requests.post(url, headers=headers, json=request.json, verify=False)
    else:  # GET request
        response = requests.get(url, headers=headers, params=request.args, verify=False)

    return jsonify(response.json()), response.status_code


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

