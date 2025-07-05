from flask import Flask, request, jsonify
import ssl
import socket
from datetime import datetime
import google.generativeai as genai
import os
from flask_cors import CORS
import logging
import re

# === CONFIG ===
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
genai.configure(api_key=GEMINI_API_KEY)

# === Setup ===
app = Flask(__name__)
CORS(app)

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def is_valid_hostname(hostname):
    """
    Validates that the hostname contains only allowed characters.
    """
    return re.match(r'^[a-zA-Z0-9.-]+$', hostname) is not None

def get_certificate_info(hostname):
    """
    Connects to the given hostname on port 443 and retrieves its SSL certificate.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert()
    except socket.gaierror:
        raise Exception(f"DNS lookup failed for hostname '{hostname}'.")
    except ssl.SSLCertVerificationError as e:
        logger.warning(f"SSL certificate verification error for {hostname}: {e}")
        raise e
    except Exception as e:
        logger.error(f"Error retrieving certificate for {hostname}: {e}")
        raise e

def verify_certificate(cert):
    """
    Parses and extracts relevant information from the certificate.
    """
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
        logger.warning(f"Date parsing error: {e}")

    # Extract issuer info
    issuer_info = {}
    for item in cert.get('issuer', []):
        for sub_item in item:
            issuer_info[sub_item[0]] = sub_item[1]
    result['issuer'] = issuer_info.get('organizationName') or \
                       issuer_info.get('organizationalUnitName') or \
                       issuer_info.get('commonName') or \
                       'Unknown'

    # Extract subject (common name)
    subject_info = {}
    for item in cert.get('subject', []):
        for sub_item in item:
            subject_info[sub_item[0]] = sub_item[1]
    result['common_name'] = subject_info.get('commonName', 'Unknown')

    return result

def generate_feedback_with_gemini(cert_data):
    """
    Generates human-readable feedback using Gemini AI.
    """
    prompt = (
        f"Analyze this SSL certificate:\n\n"
        f"Issuer: {cert_data['issuer']}\n"
        f"Common Name (Domain): {cert_data['common_name']}\n"
        f"Valid From: {cert_data['valid_from']}\n"
        f"Valid Until: {cert_data['valid_until']}\n"
        f"Validity: {'Valid' if cert_data['valid'] else 'Invalid'}\n\n"
        f"Is this certificate secure or suspicious? Provide a simple explanation focusing on the issuer and domain. "
        f"Keep the response concise and under 150 words."
    )

    try:
        model = genai.GenerativeModel("gemini-2.0-flash")
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        logger.error(f"Gemini feedback error: {e}")
        return "Could not generate AI feedback due to internal error."

@app.route('/api/check-ssl', methods=['POST'])
def check_ssl():
    """
    API endpoint to check SSL certificate for a given hostname.
    """
    data = request.get_json()
    hostname = data.get('hostname')

    if not hostname:
        return jsonify({"error": "Hostname is required."}), 400

    # Remove trailing slash
    hostname = hostname.rstrip('/')

    # Validate format
    if not is_valid_hostname(hostname):
        return jsonify({"error": "Invalid hostname format."}), 400

    try:
        cert = get_certificate_info(hostname)
        cert_data = verify_certificate(cert)
        feedback = generate_feedback_with_gemini(cert_data)
        return jsonify({
            "hostname": hostname,
            "certificate": cert_data,
            "feedback": feedback
        })
    except Exception as e:
        logger.error(f"Unhandled error for hostname {hostname}: {e}")
        return jsonify({"error": "Failed to analyze SSL certificate. Please check the domain and try again."}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
