from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, x-apikey, Key, Accept',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
}

@app.route('/')
def home():
    return jsonify({'status': 'OCCS-SOC Backend running'})

@app.route('/vtapi/<path:endpoint>', methods=['GET', 'POST', 'OPTIONS'])
def virustotal_proxy(endpoint):
    if request.method == 'OPTIONS':
        return '', 204, CORS_HEADERS
    
    api_key = request.headers.get('x-apikey', '')
    url = f'https://www.virustotal.com/api/v3/{endpoint}'
    
    headers = {'x-apikey': api_key}
    
    try:
        if request.method == 'POST':
            resp = requests.post(url, headers=headers, data=request.get_data(), timeout=30)
        else:
            resp = requests.get(url, headers=headers, params=request.args, timeout=30)
        
        response = jsonify(resp.json())
        for key, value in CORS_HEADERS.items():
            response.headers[key] = value
        response.status_code = resp.status_code
        return response
    except Exception as e:
        response = jsonify({'error': str(e)})
        for key, value in CORS_HEADERS.items():
            response.headers[key] = value
        return response, 500

@app.route('/abuseapi/<path:endpoint>', methods=['GET', 'OPTIONS'])
def abuseipdb_proxy(endpoint):
    if request.method == 'OPTIONS':
        return '', 204, CORS_HEADERS
    
    api_key = request.headers.get('Key', '')
    url = f'https://api.abuseipdb.com/api/v2/{endpoint}'
    
    headers = {'Key': api_key, 'Accept': 'application/json'}
    
    try:
        resp = requests.get(url, headers=headers, params=request.args, timeout=30)
        response = jsonify(resp.json())
        for key, value in CORS_HEADERS.items():
            response.headers[key] = value
        response.status_code = resp.status_code
        return response
    except Exception as e:
        response = jsonify({'error': str(e)})
        for key, value in CORS_HEADERS.items():
            response.headers[key] = value
        return response, 500

if __name__ == '__main__':
    app.run(debug=False)
