[Your full script above, with the following improvements injected:]

--- Enhancements to Make It More Powerful ---

✅ **Add IP Address + Geo Lookup for Vulnerability Scan:**
After `html = resp.text`, insert:
```python
# IP & Geo Info
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
```

✅ **Add Risk Level Estimation:**
After all checks (CSP, HSTS, Redirect, JS), add:
```python
issues = 0
if not check_csp_header(headers): issues += 1
if not check_hsts_header(headers): issues += 1
if check_open_redirect(target_url): issues += 1
if js_libs: issues += 1

st.markdown("### 🛡️ Risk Assessment")
if issues >= 3:
    st.error("🟥 HIGH RISK - Multiple critical vulnerabilities found.")
elif issues >= 1:
    st.warning("🟧 MEDIUM RISK - One or more vulnerabilities detected.")
else:
    st.success("🟩 LOW RISK - Website appears secure.")
```

✅ **Add Summary Verdict at End of PDF:**
After building `report`, add before PDF generation:
```python
report.append("---")
report.append(f"Risk Level: {'HIGH' if issues >= 3 else 'MEDIUM' if issues >= 1 else 'LOW'}")
```

---
Let me know if you want these updates merged into the actual file or output as a new copyable `.py` script.
Say: **"Yes, generate final enhanced script"** 💻
