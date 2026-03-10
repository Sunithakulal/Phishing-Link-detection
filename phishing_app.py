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
import os

# --- Streamlit Config ---
st.set_page_config(page_title="🔐 Cybersecurity Pro Scanner", layout="centered")

# --- Title and Branding ---
st.title("🔐 Cybersecurity Pro Scanner")
st.markdown("Scan websites and links for **phishing risks** and **vulnerabilities** 🔍")

# --- Load Model ---
with open("phishing_model.pkl", "rb") as f:
    model = pickle.load(f)

# --- Helper: Feature Extraction ---
def extract_features(url):
    features = [
        1 if url.startswith("https") else 0,
        len(url),
        url.count('.'),
        url.count('@'),
        url.count('-'),
        url.count('='),
        url.count('&'),
        1 if "login" in url.lower() else 0,
        1 if "verify" in url.lower() else 0,
        1 if "update" in url.lower() else 0,
        1 if len(re.findall(r'(http|https):\/\/[^\/]+\/', url)) > 1 else 0,
        1 if "bit.ly" in url or "tinyurl" in url else 0,
        url.count('%'),
        url.count('?'),
        url.count('//'),
        1 if len(urlparse(url).path.split('/')) > 5 else 0,
        1 if "secure" in url.lower() else 0,
        1 if re.search(r"[0-9]", url) else 0,
        1 if "account" in url.lower() else 0,
        1 if url.endswith(".exe") else 0,
    ]
    while len(features) < 30:
        features.append(0)
    return features

# --- Helper: Vulnerability Checks ---
def check_vulnerabilities(url):
    try:
        parsed = urlparse(url)
        base_url = parsed.scheme + "://" + parsed.netloc
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        issues = []

        if parsed.scheme != "https":
            issues.append(("❌ Uses HTTP", "Website does not use HTTPS."))

        if "<script>" in response.text.lower():
            issues.append(("⚠️ Contains Scripts", "Inline scripts detected."))

        if not response.text.lower().__contains__("content-security-policy"):
            issues.append(("⚠️ No CSP Header", "Missing Content Security Policy."))

        if not response.text.lower().__contains__("strict-transport-security"):
            issues.append(("⚠️ No HSTS Header", "Missing HSTS policy."))

        if soup.find("input", {"type": "password"}) and parsed.scheme != "https":
            issues.append(("❌ Insecure Password Form", "Password form not secured with HTTPS."))

        return issues
    except Exception as e:
        return [("⚠️ Error", f"Could not complete vulnerability scan: {str(e)}")]

# --- Helper: WHOIS Info ---
def get_domain_info(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        return w.domain_name, w.registrar, w.creation_date
    except:
        return "N/A", "N/A", "N/A"

# --- Helper: IP & Location ---
def get_ip_info(url):
    try:
        ip = socket.gethostbyname(urlparse(url).netloc)
        geo = requests.get(f"http://ip-api.com/json/{ip}").json()
        return ip, geo.get("country", "Unknown")
    except:
        return "N/A", "N/A"

# --- Helper: VirusTotal ---
def scan_virustotal(url):
    try:
        api_key = st.secrets["VT_API_KEY"]
        headers = {"x-apikey": api_key}
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
        scan_id = response.json()["data"]["id"]
        report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
        stats = report.json()["data"]["attributes"]["stats"]
        return stats
    except:
        return None

# --- PDF Report Generator ---
def generate_pdf(url, result, vulnerabilities, domain_info, ip_info, vt_result):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, "Cybersecurity Pro Scanner Report", ln=True, align="C")
    pdf.set_font("Arial", size=12)
    pdf.ln(10)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report_lines = [
        f"Scanned URL: {url}",
        f"Date/Time: {now}",
        f"Phishing Detection: {'❌ Phishing' if result == 1 else '✅ Safe'}",
        f"Registrar: {domain_info[1]}",
        f"Creation Date: {domain_info[2]}",
        f"IP Address: {ip_info[0]}",
        f"Country: {ip_info[1]}",
    ]

    if vt_result:
        report_lines.append(f"VirusTotal: {vt_result.get('malicious', 0)} malicious / {sum(vt_result.values())} total")

    report_lines.append("Vulnerabilities:")
    if vulnerabilities:
        for issue in vulnerabilities:
            report_lines.append(f"- {issue[0]}: {issue[1]}")
    else:
        report_lines.append("- ✅ No major issues found")

    for line in report_lines:
        clean_line = line.encode("latin-1", "replace").decode("latin-1")
        pdf.cell(200, 10, clean_line, ln=True)

    filepath = f"report_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
    pdf.output(filepath)
    return filepath

# --- Main UI ---
url = st.text_input("🔗 Enter a URL to scan", placeholder="https://example.com")

if st.button("🚀 Start Scan"):
    if not url.startswith("http"):
        st.warning("Please enter a valid URL (starting with http or https).")
    else:
        with st.spinner("Scanning in progress..."):
            features = extract_features(url)
            prediction = model.predict(np.array(features).reshape(1, -1))[0]

            result_text = "✅ This link appears to be safe."
            if prediction == 1:
                result_text = "❌ Warning: This link may be a phishing attempt!"

            domain_info = get_domain_info(url)
            ip_info = get_ip_info(url)
            vulnerabilities = check_vulnerabilities(url)
            vt_result = scan_virustotal(url)

            st.success(result_text)

            # --- Details in Expanders ---
            with st.expander("📌 Domain & IP Info"):
                st.write(f"**Registrar:** {domain_info[1]}")
                st.write(f"**Creation Date:** {domain_info[2]}")
                st.write(f"**IP Address:** {ip_info[0]}")
                st.write(f"**Country:** {ip_info[1]}")

            with st.expander("🧪 Vulnerability Report"):
                if vulnerabilities:
                    for issue in vulnerabilities:
                        st.error(f"{issue[0]} — {issue[1]}")
                else:
                    st.success("✅ No major vulnerabilities detected.")

            with st.expander("🛡️ VirusTotal Scan"):
                if vt_result:
                    st.write(f"**Malicious:** {vt_result.get('malicious', 0)}")
                    st.write(f"**Suspicious:** {vt_result.get('suspicious', 0)}")
                    st.write(f"**Undetected:** {vt_result.get('undetected', 0)}")
                else:
                    st.warning("VirusTotal scan failed or quota exceeded.")

            # --- PDF Download Button ---
            pdf_path = generate_pdf(url, prediction, vulnerabilities, domain_info, ip_info, vt_result)
            with open(pdf_path, "rb") as f:
                st.download_button("📄 Download Report (PDF)", f, file_name="cybersecurity_report.pdf")

            os.remove(pdf_path)
