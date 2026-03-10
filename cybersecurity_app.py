# Cybersecurity Pro Scanner with Login, WHOIS, PDF, Phishing & Vulnerability Scanner (SQLite)

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

# --- UI ---
st.title("🔐 Cybersecurity Pro Scanner")

try:
    anim = json.load(urlopen("https://lottie.host/8fef0596-32dc-4a3d-97a2-c4b8b3e22db5/FiR5gGeZLo.json"))
    st_lottie(anim, height=150)
except:
    pass

init_db()

st.sidebar.subheader("🔐 Account")
auth_action = st.sidebar.radio("Action", ["Login", "Register"])
username = st.sidebar.text_input("Username")
password = st.sidebar.text_input("Password", type="password")

enable_pdf = st.sidebar.checkbox("📄 Enable PDF Download", value=True)

if auth_action == "Register":
    if st.sidebar.button("Register"):
        register_user(username, password)
        st.sidebar.success("Account created. Please login.")

if auth_action == "Login":
    if st.sidebar.button("Login"):
        if login_user(username, password):
            st.session_state.logged_user = username
            st.sidebar.success(f"Logged in as {username}")
        else:
            st.sidebar.error("Invalid credentials")

if "logged_user" in st.session_state:
    user = st.session_state.logged_user
    st.success(f"Welcome, {user}!")
    tool = st.radio("Choose Tool", ["Phishing Detector", "Vulnerability Scanner", "🔁 Scan History"])

    if tool == "Phishing Detector":
        url = st.text_input("Enter URL to scan:")
        if st.button("🔍 Scan Phishing"):
            if not is_valid_url(url):
                st.warning("❌ Invalid URL")
            else:
                features = extract_features(url)
                result = model.predict([features])[0]
                verdict = "Phishing Detected" if result == 1 else "Safe"
                st.write(f"Result: **{verdict}**")
                store_scan(user, url, verdict, "Phishing Scan")

                report = [f"Phishing Detection Result for: {url}", f"Result: {verdict}"]
                st.markdown("### 🌐 WHOIS Info")
                whois_info = get_whois_info(url)
                for k, v in whois_info.items():
                    st.write(f"**{k}:** {v}")
                    report.append(f"{k}: {v}")

                if enable_pdf:
                    fname = f"phishing_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                    path = generate_pdf_report(report, fname)
                    with open(path, "rb") as f:
                        st.download_button("📄 Download Phishing PDF Report", f, file_name=fname)

    elif tool == "Vulnerability Scanner":
        target_url = st.text_input("Enter website URL (http/https):")
        if st.button("🔎 Start Scan"):
            if not is_valid_url(target_url):
                st.error("❌ Invalid URL format")
            else:
                report = [f"Vulnerability Scan Report for: {target_url}"]
                try:
                    r = requests.get(target_url, timeout=10)
                    headers = {k.lower(): v for k, v in r.headers.items()}
                    html = r.text

                    if check_csp(headers):
                        st.success("✅ CSP Header Present")
                        report.append("CSP: ✅ Present")
                    else:
                        st.error("❌ CSP Header Missing")
                        report.append("CSP: ❌ Missing")

                    if check_hsts(headers):
                        st.success("✅ HSTS Header Present")
                        report.append("HSTS: ✅ Present")
                    else:
                        st.error("❌ HSTS Header Missing")
                        report.append("HSTS: ❌ Missing")

                    if check_redirect(target_url):
                        st.error("❌ Open Redirect Found")
                        report.append("Open Redirect: ❌ Vulnerable")
                    else:
                        st.success("✅ No Open Redirect")
                        report.append("Open Redirect: ✅ Secure")

                    js_libs = detect_js(html)
                    if js_libs:
                        st.error("❌ JavaScript Libraries Detected:")
                        for lib in js_libs:
                            st.write(f"- {lib}")
                            report.append(f"JS Library: {lib}")
                    else:
                        st.success("✅ No External JS Libraries Found")
                        report.append("JS Libraries: ✅ None")

                    st.markdown("### 🌐 WHOIS Info")
                    whois_info = get_whois_info(target_url)
                    for k, v in whois_info.items():
                        st.write(f"**{k}:** {v}")
                        report.append(f"{k}: {v}")

                    verdict = "; ".join(report)
                    store_scan(user, target_url, verdict, "Vulnerability Scan")

                    if enable_pdf:
                        fname = f"vulnerability_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                        path = generate_pdf_report(report, fname)
                        with open(path, "rb") as f:
                            st.download_button("📄 Download Vulnerability PDF Report", f, file_name=fname)

                except Exception as e:
                    st.error(f"Scan error: {e}")

    elif tool == "🔁 Scan History":
        st.subheader("📂 Your Scan History")
        history = get_user_scans(user)
        if history:
            for url, result, scan_type, ts in history:
                st.markdown(f"**{scan_type}** | [{url}](http://{url})")
                st.markdown(f"🗒️ {result} | 🕒 {ts}")
                st.markdown("---")
        else:
            st.info("No scans yet.")
