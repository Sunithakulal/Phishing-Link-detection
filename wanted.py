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
import whois
import base64

# --- Streamlit Setup ---
st.set_page_config(page_title="🔐 Cybersecurity Pro Scanner", layout="centered")
st.title("🔐 Cybersecurity Pro Scanner")

# --- Appearance & Theme Info (no radio switch) ---
st.sidebar.header("🎨 Appearance & Theme")
st.sidebar.info(
    "**To change the app theme:**\n"
    "- Click the menu ☰ (top right) → Settings → Theme\n"
    "- Or, edit `.streamlit/config.toml` and restart the app\n\n"
    "Theme switching from within the app UI is not supported."
)

# --- Load ML Model ---
@st.cache_resource
def load_model():
    with open("phishing_model.pkl", "rb") as f:
        return pickle.load(f)

model = load_model()

# --- VirusTotal API Key ---
VT_API_KEY = "52b65c6452b574ffdc3555e3bc67de6d91b3ae4c9de321b669e499127671f24c"

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
    features.append(-1 if dot_count == 1 else 0 if dot_count == 2 else 1)
    keyword_flag = any(keyword in url.lower() for keyword in suspicious_keywords)
    features.append(1 if keyword_flag else -1)
    shortener_flag = any(short in parsed.netloc for short in shorteners)
    features.append(1 if shortener_flag else -1)
    while len(features) < 30:
        features.append(0)
    return np.array(features)

# --- URL Validation ---
def is_valid_url(url):
    regex = re.compile(
        r'^(https?:\/\/)?'               # optional http or https
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

# --- WHOIS Info ---
def get_whois_info(domain):
    try:
        info = whois.whois(domain)
        return {
            "Domain": info.domain_name,
            "Registrar": info.registrar,
            "Created": str(info.creation_date),
            "Expires": str(info.expiration_date)
        }
    except Exception as e:
        return {"WHOIS Error": str(e)}

# --- VirusTotal Scan ---
def scan_virustotal(url):
    try:
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{encoded_url}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return stats['malicious'], sum(stats.values())
        else:
            return None, None
    except:
        return None, None

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

st.sidebar.markdown("### 🔍 Enable Features:")
enable_phishing = st.sidebar.checkbox("🔗 Phishing Link Detection", value=True)
enable_csp = st.sidebar.checkbox("🛡️ CSP Header Check", value=True)
enable_hsts = st.sidebar.checkbox("📦 HSTS Header Check", value=True)
enable_redirect = st.sidebar.checkbox("🔀 Open Redirect Check", value=True)
enable_js = st.sidebar.checkbox("🧠 JavaScript Library Detection", value=True)
enable_pdf = st.sidebar.checkbox("📄 PDF Report Download", value=True)
enable_virustotal = st.sidebar.checkbox("🔁 VirusTotal Scan", value=True)

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
                if any(kw in url.lower() for kw in suspicious_keywords):
                    st.warning("⚠️ Suspicious keyword(s) detected in the URL.")
                if any(short in urlparse(url).netloc for short in shorteners):
                    st.warning("⚠️ This appears to be a shortened URL.")
                domain = urlparse(url).netloc.replace("www.", "")
                st.markdown("### 🌐 WHOIS Info")
                whois_info = get_whois_info(domain)
                for k, v in whois_info.items():
                    st.write(f"**{k}:** {v}")
                if enable_virustotal:
                    st.markdown("### 🔁 VirusTotal Scan")
                    vt_malicious, vt_total = scan_virustotal(url)
                    if vt_malicious is not None:
                        if vt_malicious > 0:
                            st.error(f"❌ Detected by {vt_malicious}/{vt_total} VirusTotal engines")
                        else:
                            st.success("✅ No detections on VirusTotal")
                    else:
                        st.warning("⚠️ VirusTotal scan failed or not available")
            except Exception as e:
                st.error(f"Error while scanning: {e}")

# --- Vulnerability Scanner ---
if tool == "Website Vulnerability Scanner":
    st.subheader("🕷️ Website Vulnerability Scanner")
    target_url = st.text_input("Enter full website URL (include http/https):")
    target_url = target_url.strip()
    if st.button("🔎 Start Scan"):
        if not target_url.lower().startswith(("http://", "https://")):
            st.error("❌ URL must start with http:// or https://")
        else:
            report = []
            try:
                resp = requests.get(target_url, timeout=10)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                html = resp.text
                try:
                    ip = socket.gethostbyname(urlparse(target_url).netloc)
                    geo = requests.get(f"http://ip-api.com/json/{ip}").json()
                    st.markdown("### 🌐 IP & Location Info")
                    st.write(f"**IP Address:** {ip}")
                    st.write(f"**Country:** {geo.get('country')}, {geo.get('regionName')}, {geo.get('city')}")
                    st.write(f"**ISP:** {geo.get('isp')}")
                    report.append(f"IP: {ip}, Country: {geo.get('country')}, ISP: {geo.get('isp')}")
                except:
                    st.warning("⚠️ Could not fetch IP/location info")
                st.markdown("### 🔬 Scan Results")
                st.write("✅ = Secure, ❌ = Vulnerable")
                issues = 0
                if enable_csp:
                    if check_csp_header(headers):
                        st.success("✅ CSP Header: Present")
                        report.append("CSP Header: ✅ Present")
                    else:
                        st.error("❌ CSP Header: Missing")
                        report.append("CSP Header: ❌ Missing")
                        issues += 1
                if enable_hsts:
                    if check_hsts_header(headers):
                        st.success("✅ HSTS Header: Present")
                        report.append("HSTS Header: ✅ Present")
                    else:
                        st.error("❌ HSTS Header: Missing")
                        report.append("HSTS Header: ❌ Missing")
                        issues += 1
                if enable_redirect:
                    if check_open_redirect(target_url):
                        st.error("❌ Open Redirect: Vulnerable")
                        report.append("Open Redirect: ❌ Vulnerable")
                        issues += 1
                    else:
                        st.success("✅ Open Redirect: Secure")
                        report.append("Open Redirect: ✅ Secure")
                if enable_js:
                    js_libs = detect_js_libraries(html)
                    if js_libs:
                        st.error("❌ JavaScript Libraries Detected:")
                        for lib in js_libs:
                            st.write(f"- {lib}")
                            report.append(f"JS Library: {lib}")
                        issues += 1
                    else:
                        st.success("✅ No JS Libraries Detected")
                        report.append("JS Libraries: ✅ None")
                domain = urlparse(target_url).netloc.replace("www.", "")
                st.markdown("### 🌐 WHOIS Info")
                whois_info = get_whois_info(domain)
                for k, v in whois_info.items():
                    st.write(f"**{k}:** {v}")
                    report.append(f"{k}: {v}")
                st.markdown("### 🛡️ Risk Assessment")
                if issues >= 3:
                    st.error("🟥 HIGH RISK - Multiple critical vulnerabilities found.")
                    report.append("Risk Level: HIGH")
                elif issues >= 1:
                    st.warning("🟧 MEDIUM RISK - One or more vulnerabilities detected.")
                    report.append("Risk Level: MEDIUM")
                else:
                    st.success("🟩 LOW RISK - Website appears secure.")
                    report.append("Risk Level: LOW")
                if enable_pdf:
                    pdf_path = generate_pdf_report(report)
                    with open(pdf_path, "rb") as f:
                        st.download_button("📄 Download PDF Report", f, file_name=pdf_path.split('/')[-1])
            except Exception as e:
                st.error(f"❌ Error: {e}")
