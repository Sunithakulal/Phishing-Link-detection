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
import streamlit.components.v1 as components

# --- Streamlit Setup ---
st.set_page_config(page_title="🔐 Cybersecurity Pro Scanner", layout="centered")
st.title("🔐 Cybersecurity Pro Scanner")

# --- Dynamic Theme Switching ---
theme_choice = st.sidebar.radio("🎨 Preferred Theme", ["System Default", "Light", "Dark"])
custom_css = ""
if theme_choice == "Dark":
    custom_css = """
    <style>
    body, .stApp { background-color: #0e1117 !important; color: #fafafa !important; }
    </style>
    """
elif theme_choice == "Light":
    custom_css = """
    <style>
    body, .stApp { background-color: #FFFFFF !important; color: #000000 !important; }
    </style>
    """
components.html(custom_css, height=0)

st.sidebar.info("⚙️ Theme applied instantly using injected CSS. Reload not required.")

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
