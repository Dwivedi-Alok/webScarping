from flask import Flask, request, jsonify
import ssl
import socket
from datetime import datetime
import google.generativeai as genai
import os
from flask_cors import CORS
import logging
import re
import requests
import traceback

# === CONFIG ===
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
genai.configure(api_key=GEMINI_API_KEY)

# === SETUP ===
app = Flask(__name__)
CORS(app)

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === UTILS ===
def is_valid_hostname(hostname):
    return re.match(r'^[a-zA-Z0-9.-]+$', hostname) is not None

def get_certificate_info(hostname):
    context = ssl.create_default_context()
    try:
        logger.info(f"📡 Connecting to {hostname}:443 for SSL cert")
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert()
    except socket.gaierror as e:
        logger.error(f"🧨 DNS lookup failed for '{hostname}': {e}")
        raise Exception(f"DNS lookup failed for hostname '{hostname}'.")
    except ssl.SSLCertVerificationError as e:
        logger.warning(f"🔐 SSL cert verification error for {hostname}: {e}")
        raise Exception(f"SSL certificate verification failed for '{hostname}'.")
    except Exception as e:
        logger.error(f"❗ General SSL cert retrieval error for {hostname}: {e}")
        raise Exception(f"Could not retrieve SSL certificate: {str(e)}")

def verify_certificate(cert):
    result = {}
    try:
        not_after = datetime.strptime(cert.get('notAfter', ''), '%b %d %H:%M:%S %Y %Z')
        not_before = datetime.strptime(cert.get('notBefore', ''), '%b %d %H:%M:%S %Y %Z')
        now = datetime.utcnow()
        result['valid'] = now >= not_before and now <= not_after
        result['valid_from'] = cert.get('notBefore', 'Unknown')
        result['valid_until'] = cert.get('notAfter', 'Unknown')
    except Exception as e:
        result['valid'] = False
        result['valid_from'] = 'Invalid date'
        result['valid_until'] = 'Invalid date'
        logger.warning(f"⚠️ Date parsing error: {e}")

    issuer_info = {}
    for item in cert.get('issuer', []):
        for sub_item in item:
            issuer_info[sub_item[0]] = sub_item[1]
    result['issuer'] = issuer_info.get('organizationName') or \
                       issuer_info.get('organizationalUnitName') or \
                       issuer_info.get('commonName') or 'Unknown'

    subject_info = {}
    for item in cert.get('subject', []):
        for sub_item in item:
            subject_info[sub_item[0]] = sub_item[1]
    result['common_name'] = subject_info.get('commonName', 'Unknown')

    return result

def generate_feedback_with_gemini(cert_data):
    suspicious_keywords = ['paypal', 'verify', 'secure', 'login', 'account', 'update']
    domain = cert_data.get("common_name", "").lower()

    prompt = (
        f"Analyze this SSL certificate:\n\n"
        f"Issuer: {cert_data['issuer']}\n"
        f"Common Name (Domain): {cert_data['common_name']}\n"
        f"Valid From: {cert_data['valid_from']}\n"
        f"Valid Until: {cert_data['valid_until']}\n"
        f"Validity: {'Valid' if cert_data['valid'] else 'Invalid'}\n\n"
    )

    if any(keyword in domain for keyword in suspicious_keywords):
        prompt += (
            "The domain name contains suspicious keywords. "
            "Please determine if this domain might be malicious or attempting phishing.\n"
        )

    prompt += "Keep your explanation under 150 words."

    try:
        model = genai.GenerativeModel("gemini-2.0-flash")
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        logger.error(f"🤖 Gemini feedback error: {e}")
        return "AI feedback unavailable due to internal error."

def check_url_with_google_safe_browsing(url_to_check):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    payload = {
        "client": {
            "clientId": "student-checker",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url_to_check}]
        }
    }

    try:
        response = requests.post(endpoint, json=payload)
        result = response.json()
        if result.get("matches"):
            return {"safe": False, "details": result["matches"]}
        return {"safe": True, "details": None}
    except Exception as e:
        logger.error(f"🛡️ Google Safe Browsing API error: {e}")
        return {"safe": None, "error": "Google Safe Browsing check failed."}

def calculate_risk(cert_data, google_check, feedback):
    score = 0
    domain = cert_data.get("common_name", "").lower()

    if not cert_data.get("valid", False):
        score += 2

    if any(keyword in domain for keyword in ['paypal', 'verify', 'secure', 'login', 'update']):
        score += 3

    if "phishing" in feedback.lower() or "suspicious" in feedback.lower():
        score += 4

    if google_check.get("safe") is False:
        score += 5

    if score >= 8:
        return "High Risk"
    elif score >= 4:
        return "Medium Risk"
    else:
        return "Low Risk"

# === API ROUTE ===
@app.route('/api/check-ssl', methods=['POST'])
def check_ssl():
    data = request.get_json()
    hostname = data.get('hostname')
    logger.info(f"🔍 Incoming SSL check for: {hostname}")

    if not hostname:
        return jsonify({"error": "Hostname is required."}), 400

    hostname = hostname.rstrip('/')
    if not is_valid_hostname(hostname):
        return jsonify({"error": "Invalid hostname format."}), 400

    try:
        cert = get_certificate_info(hostname)
        cert_data = verify_certificate(cert)
    except Exception as ssl_error:
        logger.warning(f"⚠️ SSL certificate could not be retrieved: {ssl_error}")
        return jsonify({"error": str(ssl_error)}), 500

    try:
        feedback = generate_feedback_with_gemini(cert_data)
        google_result = check_url_with_google_safe_browsing(f"https://{hostname}")
        risk = calculate_risk(cert_data, google_result, feedback)

        return jsonify({
            "hostname": hostname,
            "certificate": cert_data,
            "feedback": feedback,
            "google_safe_browsing": google_result,
            "risk_level": risk
        })

    except Exception as e:
        logger.error(f"❌ Unexpected error:\n{traceback.format_exc()}")
        return jsonify({"error": f"Internal error during analysis: {str(e)}"}), 500

# === RUN ===
if __name__ == '__main__':
    app.run(debug=True, port=5000)
