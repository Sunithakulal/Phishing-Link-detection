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

# --- Streamlit Setup ---
st.set_page_config(page_title="🔐 Cybersecurity Pro Scanner", layout="centered")
st.title("🔐 Cybersecurity Pro Scanner")

# --- Load ML Model ---
@st.cache_resource
def load_model():
    with open("phishing_model.pkl", "rb") as f:
        return pickle.load(f)

model = load_model()

# --- Suspicious Keywords and URL Shorteners ---
suspicious_keywords = ['secure', 'account', 'update', 'login', 'free', 'verify', 'password', 'banking']
shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']

# --- Feature Extraction for Phishing Detection ---
def extract_features(url):
    parsed = urlparse(url)
    features = []

    try:
        ip = socket.gethostbyname(parsed.netloc)
        features.append(1)
    except:
        features.append(-1)

    features.append(1 if len(url) > 75 else -1)
    features.append(1 if len(url) < 54 else -1)
    features.append(1 if '@' in url else -1)
    features.append(1 if url.count('//') > 1 else -1)
    features.append(1 if '-' in parsed.netloc else -1)

    dot_count = parsed.netloc.count('.')
    if dot_count == 1:
        features.append(-1)
    elif dot_count == 2:
        features.append(0)
    else:
        features.append(1)

    # Suspicious keywords
    keyword_flag = any(keyword in url.lower() for keyword in suspicious_keywords)
    features.append(1 if keyword_flag else -1)

    # Shortened URLs
    shortener_flag = any(short in parsed.netloc for short in shorteners)
    features.append(1 if shortener_flag else -1)

    while len(features) < 30:
        features.append(0)

    return np.array(features)

# --- URL Validation ---
def is_valid_url(url):
    regex = re.compile(
        r'^(https?:\/\/)?'              # optional http or https
        r'([\da-z\.-]+)\.([a-z\.]{2,6})' # domain name
        r'([\/\w \.-]*)*\/?$'           # optional path
    )
    return re.match(regex, url)

# --- Security Checks ---
def check_csp_header(headers):
    return 'content-security-policy' in headers

def check_hsts_header(headers):
    return 'strict-transport-security' in headers

def check_open_redirect(url):
    try:
        resp = requests.get(url, allow_redirects=False, timeout=5)
        return 'Location' in resp.headers and resp.headers['Location'].startswith('http')
    except:
        return False

def detect_js_libraries(html):
    soup = BeautifulSoup(html, "html.parser")
    scripts = soup.find_all("script", src=True)
    libraries = []
    for script in scripts:
        src = script['src']
        match = re.search(r'/([^/]+)\.js', src)
        if match:
            lib = match.group(1).split("?")[0]
            libraries.append(lib)
    return libraries

# --- PDF Report Generator ---
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
    path = f"./{filename}"
    pdf.output(path)
    return path

# --- Sidebar Configuration ---
st.sidebar.title("🔧 Features")
tool = st.sidebar.radio("Choose Tool", ["Phishing Link Detector", "Website Vulnerability Scanner"])

# Feature Toggles
st.sidebar.markdown("### 🔍 Enable Features:")
enable_phishing = st.sidebar.checkbox("🔗 Phishing Link Detection", value=True)
enable_csp = st.sidebar.checkbox("🛡️ CSP Header Check", value=True)
enable_hsts = st.sidebar.checkbox("📦 HSTS Header Check", value=True)
enable_redirect = st.sidebar.checkbox("🔀 Open Redirect Check", value=True)
enable_js = st.sidebar.checkbox("🧠 JavaScript Library Detection", value=True)
enable_pdf = st.sidebar.checkbox("📄 PDF Report Download", value=True)

# --- Phishing Detector ---
if tool == "Phishing Link Detector" and enable_phishing:
    st.subheader("🎯 Phishing Link Detector")
    url = st.text_input("Enter URL to scan for phishing:")

    if st.button("🔍 Scan"):
        if not url or not is_valid_url(url):
            st.warning("❌ Please enter a valid and complete URL (e.g., https://example.com)")
        else:
            try:
                features = extract_features(url)
                result = model.predict([features])[0]
                if result == 1:
                    st.error("⚠️ This URL may be a phishing site!")
                else:
                    st.success("✅ This URL appears safe.")

                # Additional Warnings
                if any(kw in url.lower() for kw in suspicious_keywords):
                    st.warning("⚠️ Suspicious keyword(s) detected in the URL.")
                if any(short in urlparse(url).netloc for short in shorteners):
                    st.warning("⚠️ This appears to be a shortened URL.")

            except Exception as e:
                st.error(f"Error while scanning: {e}")

# --- Vulnerability Scanner ---
if tool == "Website Vulnerability Scanner":
    st.subheader("🕷️ Website Vulnerability Scanner")
    target_url = st.text_input("Enter full website URL (include http/https):")

    if st.button("🔎 Start Scan"):
        if not target_url.startswith("http"):
            st.error("❌ URL must start with http:// or https://")
        else:
            report = []
            try:
                resp = requests.get(target_url, timeout=10)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                html = resp.text

                st.markdown("### 🔬 Scan Results")
                st.write("✅ = Secure, ❌ = Vulnerable")

                # CSP
                if enable_csp:
                    if check_csp_header(headers):
                        st.success("✅ CSP Header: Present")
                        report.append("CSP Header: ✅ Present")
                    else:
                        st.error("❌ CSP Header: Missing")
                        report.append("CSP Header: ❌ Missing")

                # HSTS
                if enable_hsts:
                    if check_hsts_header(headers):
                        st.success("✅ HSTS Header: Present")
                        report.append("HSTS Header: ✅ Present")
                    else:
                        st.error("❌ HSTS Header: Missing")
                        report.append("HSTS Header: ❌ Missing")

                # Open Redirect
                if enable_redirect:
                    if check_open_redirect(target_url):
                        st.error("❌ Open Redirect: Vulnerable")
                        report.append("Open Redirect: ❌ Vulnerable")
                    else:
                        st.success("✅ Open Redirect: Secure")
                        report.append("Open Redirect: ✅ Secure")

                # JS Libraries
                if enable_js:
                    js_libs = detect_js_libraries(html)
                    if js_libs:
                        st.error("❌ JavaScript Libraries Detected:")
                        for lib in js_libs:
                            st.write(f"- {lib}")
                            report.append(f"- {lib}")
                    else:
                        st.success("✅ No JS Libraries Detected")
                        report.append("JS Libraries: ✅ None")

                # PDF Report
                if enable_pdf:
                    pdf_path = generate_pdf_report(report)
                    with open(pdf_path, "rb") as f:
                        st.download_button("📄 Download PDF Report", f, file_name=pdf_path.split('/')[-1])

            except Exception as e:
                st.error(f"❌ Error: {e}")
