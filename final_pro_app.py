import streamlit as st
import socket
import requests
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import pickle
import numpy as np
from fpdf import FPDF
import datetime
import os

# -------------- Config --------------
st.set_page_config(page_title="🔐 Final Pro Cybersecurity Scanner", layout="centered")

# -------------- Load Model --------------
@st.cache_resource
def load_model():
    with open("phishing_model.pkl", "rb") as f:
        return pickle.load(f)

model = load_model()

# -------------- Feature Extractor --------------
def extract_features(url):
    features = []
    try:
        ip = socket.gethostbyname(urlparse(url).netloc)
        features.append(1)
    except:
        features.append(-1)

    features.append(1 if len(url) > 75 else -1)
    features.append(1 if len(url) < 54 else -1)
    features.append(1 if '@' in url else -1)
    features.append(1 if url.count('//') > 1 else -1)
    features.append(1 if '-' in urlparse(url).netloc else -1)

    dot_count = urlparse(url).netloc.count('.')
    features.append(-1 if dot_count == 1 else (0 if dot_count == 2 else 1))

    while len(features) < 30:
        features.append(0)

    return np.array(features)

# -------------- Vulnerability Checks --------------
def check_csp_header(headers):
    return 'content-security-policy' in headers

def check_hsts_header(headers):
    return 'strict-transport-security' in headers

def check_open_redirect(url):
    try:
        resp = requests.get(url, allow_redirects=False, timeout=5)
        if 'Location' in resp.headers:
            location = resp.headers['Location']
            return location.startswith('http')
    except:
        return False
    return False

def detect_js_libraries(html):
    soup = BeautifulSoup(html, "html.parser")
    scripts = soup.find_all("script", src=True)
    libraries = []
    for script in scripts:
        src = script['src']
        match = re.search(r'/([^/]+)\.js', src)
        if match:
            libraries.append(match.group(1))
    return libraries

# -------------- PDF Report --------------
def generate_pdf_report(report_lines):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Cybersecurity Scan Report", ln=True, align='C')
    pdf.ln(10)

    for line in report_lines:
        clean_line = line.encode('latin-1', 'replace').decode('latin-1')
        pdf.multi_cell(0, 10, clean_line)

    filename = f"scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    path = os.path.join(".", filename)
    pdf.output(path)
    return path

# -------------- Sidebar Navigation --------------
st.sidebar.title("🛡️ Final Pro Toolkit")
page = st.sidebar.radio("Choose Tool", ["Phishing Link Detector", "Website Vulnerability Scanner"])

# -------------- PHISHING SECTION --------------
if page == "Phishing Link Detector":
    st.title("🎯 Phishing Link Detector")
    url = st.text_input("Enter URL to check")

    with st.expander("⚙️ Optional Features"):
        use_ml_model = st.checkbox("Enable ML Model Check", value=True)

    if st.button("Scan URL"):
        if url:
            if use_ml_model:
                features = extract_features(url)
                prediction = model.predict([features])[0]
                if prediction == 1:
                    st.error("⚠️ Warning: This URL might be a phishing site!")
                else:
                    st.success("✅ This URL looks safe.")
            else:
                st.info("🔎 ML model was disabled.")
        else:
            st.warning("Please enter a URL.")

# -------------- VULNERABILITY SECTION --------------
else:
    st.title("🕷️ Website Vulnerability Scanner")
    url = st.text_input("Enter full website URL (with http/https)")

    with st.expander("⚙️ Choose Features to Scan"):
        check_csp = st.checkbox("Check CSP Header", value=True)
        check_hsts = st.checkbox("Check HSTS Header", value=True)
        check_redirect = st.checkbox("Check Open Redirect", value=True)
        check_js = st.checkbox("Detect JavaScript Libraries", value=True)
        generate_pdf = st.checkbox("Generate PDF Report", value=True)

    if st.button("Scan Website"):
        if not url.startswith("http"):
            st.error("Please enter a valid URL with http/https.")
        else:
            report = []
            try:
                resp = requests.get(url, timeout=10)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                html = resp.text

                st.subheader("🔍 Scan Results")
                st.write("✅ = Secure, ❌ = Vulnerable")

                # Scan features
                if check_csp:
                    if check_csp_header(headers):
                        st.success("✅ CSP Header: Present - Protects against XSS")
                        report.append("CSP Header: Secure")
                    else:
                        st.error("❌ CSP Header: Missing - Protection against XSS lacking")
                        report.append("CSP Header: Vulnerable")

                if check_hsts:
                    if check_hsts_header(headers):
                        st.success("✅ HSTS Header: Present - Prevents downgrade attacks")
                        report.append("HSTS Header: Secure")
                    else:
                        st.error("❌ HSTS Header: Missing - Vulnerable to downgrade attacks")
                        report.append("HSTS Header: Vulnerable")

                if check_redirect:
                    if check_open_redirect(url):
                        st.error("❌ Open Redirect: Vulnerable - Redirection manipulation possible")
                        report.append("Open Redirect: Vulnerable")
                    else:
                        st.success("✅ Open Redirect: Secure")
                        report.append("Open Redirect: Secure")

                if check_js:
                    js_libs = detect_js_libraries(html)
                    if js_libs:
                        st.error(f"❌ JavaScript Libraries Detected: {', '.join(js_libs)}")
                        report.append(f"JavaScript Libraries: {', '.join(js_libs)}")
                    else:
                        st.success("✅ JavaScript Libraries: None found")
                        report.append("JavaScript Libraries: None")

                if generate_pdf and report:
                    pdf_path = generate_pdf_report(report)
                    with open(pdf_path, "rb") as f:
                        st.download_button("📄 Download PDF Report", f, file_name=pdf_path.split('/')[-1])

            except Exception as e:
                st.error(f"❌ Error while scanning: {e}")
