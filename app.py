
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, x-apikey, Key, Accept',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
}


def make_response(resp):
    """Transmet la réponse de l'API externe au navigateur."""
    try:
        data = resp.json()
    except ValueError:
        data = {
            'error': 'La réponse du service externe n’est pas au format JSON.',
            'details': resp.text[:1000]
        }

    response = jsonify(data)
    response.status_code = resp.status_code

    for key, value in CORS_HEADERS.items():
        response.headers[key] = value

    return response


def error_response(message):
    """Renvoie une erreur avec les en-têtes CORS."""
    response = jsonify({'error': message})
    response.status_code = 500

    for key, value in CORS_HEADERS.items():
        response.headers[key] = value

    return response


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
            headers['Content-Type'] = request.headers.get(
                'Content-Type',
                'application/x-www-form-urlencoded'
            )

            resp = requests.post(
                url,
                headers=headers,
                data=request.get_data(),
                timeout=30
            )
        else:
            resp = requests.get(
                url,
                headers=headers,
                params=request.args,
                timeout=30
            )

        return make_response(resp)

    except requests.RequestException as e:
        return error_response(
            f'Erreur de communication avec VirusTotal : {str(e)}'
        )


@app.route('/abuseapi/<path:endpoint>', methods=['GET', 'OPTIONS'])
def abuseipdb_proxy(endpoint):
    if request.method == 'OPTIONS':
        return '', 204, CORS_HEADERS

    api_key = request.headers.get('Key', '')
    url = f'https://api.abuseipdb.com/api/v2/{endpoint}'

    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }

    try:
        resp = requests.get(
            url,
            headers=headers,
            params=request.args,
            timeout=30
        )

        return make_response(resp)

    except requests.RequestException as e:
        return error_response(
            f'Erreur de communication avec AbuseIPDB : {str(e)}'
        )


if __name__ == '__main__':
    app.run(debug=False)
