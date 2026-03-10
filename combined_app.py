import streamlit as st
import pickle
import socket
from urllib.parse import urlparse
import numpy as np
import requests

# -------------------------------
# Page Config
# -------------------------------
st.set_page_config(page_title="CyberShield App", layout="centered")

# -------------------------------
# Load phishing detection model
# -------------------------------
try:
    with open("phishing_model.pkl", "rb") as f:
        model = pickle.load(f)
except FileNotFoundError:
    st.error("⚠️ Model file not found: phishing_model.pkl")
    st.stop()

# -------------------------------
# Feature Extraction for Phishing
# -------------------------------
def extract_phishing_features(url):
    features = []
    try:
        socket.gethostbyname(urlparse(url).netloc)
        features.append(1)
    except:
        features.append(-1)

    features.append(1 if len(url) > 75 else -1)
    features.append(1 if len(url) < 54 else -1)
    features.append(1 if '@' in url else -1)
    features.append(1 if url.count('//') > 1 else -1)
    features.append(1 if '-' in urlparse(url).netloc else -1)

    dot_count = urlparse(url).netloc.count('.')
    features.append(1 if dot_count > 2 else (-1 if dot_count == 1 else 0))

    while len(features) < 30:
        features.append(0)

    return np.array(features)

# -------------------------------
# Vulnerability Scanner
# -------------------------------
def check_headers(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        csp = "content-security-policy" in headers
        hsts = "strict-transport-security" in headers

        return {
            "CSP Header": csp,
            "HSTS Header": hsts,
        }
    except Exception:
        return None

def scan_url_for_vulnerabilities(url):
    results = check_headers(url)
    if results is None:
        return "URL unreachable or invalid.", {}

    report = {}
    report["CSP Header"] = "✅ Present" if results["CSP Header"] else "❌ Missing - Helps prevent XSS"
    report["HSTS Header"] = "✅ Present" if results["HSTS Header"] else "❌ Missing - Protects HTTPS"
    return "Scan complete.", report

# -------------------------------
# Sidebar Navigation
# -------------------------------
st.sidebar.title("🔐 CyberShield App")
page = st.sidebar.radio("Choose Tool", ["Phishing Link Detector", "Website Vulnerability Scanner"])

# -------------------------------
# Phishing Detector Page
# -------------------------------
if page == "Phishing Link Detector":
    st.title("🎯 Phishing Link Detector")
    input_url = st.text_input("Enter a URL to check for phishing:")

    if st.button("Analyze"):
        if input_url:
            features = extract_phishing_features(input_url)
            result = model.predict([features])[0]
            if result == 1:
                st.error("🚨 Phishing Detected! Be careful.")
            else:
                st.success("✅ Looks safe.")
        else:
            st.warning("Please enter a URL.")

# -------------------------------
# Vulnerability Scanner Page
# -------------------------------
elif page == "Website Vulnerability Scanner":
    st.title("🛡️ Website Vulnerability Scanner")
    scan_url = st.text_input("Enter a website URL (e.g. https://example.com):")

    if st.button("Start Scan"):
        if scan_url:
            status, results = scan_url_for_vulnerabilities(scan_url)
            st.info(status)
            for key, val in results.items():
                st.write(f"**{key}**: {val}")
        else:
            st.warning("Please enter a valid URL.")
