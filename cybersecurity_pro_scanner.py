# Cybersecurity Pro Scanner with Login, WHOIS, PDF, Risk Levels, Phishing & Vulnerability Scanner (SQLite)

import streamlit as st
import sqlite3, datetime, requests, re, socket, json, pickle, numpy as np
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import whois
from fpdf import FPDF
from streamlit_lottie import st_lottie
from urllib.request import urlopen

# MUST BE FIRST STREAMLIT COMMAND
st.set_page_config(page_title="Cybersecurity Pro Scanner", layout="centered")

# --- Initialize DB ---
def init_db():
    conn = sqlite3.connect("scanner_data.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS scans (
                username TEXT,
                url TEXT,
                result TEXT,
                scan_type TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    conn.commit()
    conn.close()

# --- User Auth ---
def register_user(username, password):
    conn = sqlite3.connect("scanner_data.db")
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO users VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()

def login_user(username, password):
    conn = sqlite3.connect("scanner_data.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = c.fetchone()
    conn.close()
    return user

# --- Scan Storage ---
def store_scan(username, url, result, scan_type):
    conn = sqlite3.connect("scanner_data.db")
    c = conn.cursor()
    c.execute("INSERT INTO scans (username, url, result, scan_type) VALUES (?, ?, ?, ?)",
              (username, url, result, scan_type))
    conn.commit()
    conn.close()

def get_user_scans(username):
    conn = sqlite3.connect("scanner_data.db")
    c = conn.cursor()
    c.execute("SELECT url, result, scan_type, timestamp FROM scans WHERE username = ? ORDER BY timestamp DESC", (username,))
    data = c.fetchall()
    conn.close()
    return data

# --- Load Model ---
@st.cache_resource
def load_model():
    with open("phishing_model.pkl", "rb") as f:
        return pickle.load(f)
model = load_model()

# --- Utility Functions ---
def extract_features(url):
    parsed = urlparse(url)
    features = []
    try:
        socket.gethostbyname(parsed.netloc)
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
    keywords = ["secure", "login", "ebayisapi", "banking", "confirm", "account", "update"]
    features.append(1 if any(k in url.lower() for k in keywords) else -1)
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co']
    features.append(1 if any(s in url for s in shorteners) else -1)
    while len(features) < 30:
        features.append(0)
    return np.array(features)

def is_valid_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ['http', 'https'] and bool(parsed.netloc)

def check_csp(headers): return 'content-security-policy' in headers

def check_hsts(headers): return 'strict-transport-security' in headers

def check_redirect(url):
    try:
        r = requests.get(url, allow_redirects=False, timeout=5)
        return 'Location' in r.headers and r.headers['Location'].startswith('http')
    except: return False

def detect_js(html):
    soup = BeautifulSoup(html, "html.parser")
    scripts = soup.find_all("script", src=True)
    return [re.search(r'/([^/]+)\.js', s['src']).group(1).split("?")[0] for s in scripts if re.search(r'/([^/]+)\.js', s['src'])]

def get_whois_info(url):
    try:
        domain = urlparse(url).netloc.replace("www.", "")
        w = whois.whois(domain)
        return {
            "Domain": w.domain_name,
            "Registrar": w.registrar,
            "Created": str(w.creation_date),
            "Expires": str(w.expiration_date)
        }
    except Exception as e:
        return {"WHOIS Error": str(e)}

def generate_pdf_report(lines, filename):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, "Cybersecurity Scan Report", ln=True, align='C')
    pdf.ln(10)
    for line in lines:
        clean = line.encode('latin-1', 'replace').decode('latin-1')
        pdf.multi_cell(0, 10, clean)
    pdf.output(filename)
    return filename

# --- UI and Risk Level Logic would continue below this line ---
# Add your phishing and vulnerability scanner UI sections here, followed by:
# - WHOIS domain age parsing
# - Risk scoring (HIGH/MEDIUM/LOW)
# - Markdown st.markdown() blocks for output
# See earlier message for exact code block to include in phishing + vuln sections
