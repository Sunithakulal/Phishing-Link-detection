import streamlit as st
import pickle
import socket
from urllib.parse import urlparse
import numpy as np

# Load trained model
try:
    with open("phishing_model.pkl", "rb") as f:
        model = pickle.load(f)
except FileNotFoundError:
    st.error("Model file not found! Make sure phishing_model.pkl is in the same folder.")
    st.stop()

# Feature extractor
def extract_features(url):
    features = []

    # Feature 1: IP address present
    try:
        ip = socket.gethostbyname(urlparse(url).netloc)
        features.append(1)
    except:
        features.append(-1)

    # Feature 2: Long URL
    features.append(1 if len(url) > 75 else -1)

    # Feature 3: Short URL
    features.append(1 if len(url) < 54 else -1)

    # Feature 4: "@" in URL
    features.append(1 if '@' in url else -1)

    # Feature 5: "//" in path (more than once)
    features.append(1 if url.count('//') > 1 else -1)

    # Feature 6: "-" in domain
    features.append(1 if '-' in urlparse(url).netloc else -1)

    # Feature 7: Subdomains count
    dot_count = urlparse(url).netloc.count('.')
    if dot_count == 1:
        features.append(-1)
    elif dot_count == 2:
        features.append(0)
    else:
        features.append(1)

    # Padding to make it 30 features
    while len(features) < 30:
        features.append(0)

    return np.array(features)

# Streamlit UI
st.title("🔍 Phishing Link Detector")

url = st.text_input("Enter a URL to check")

if st.button("Check"):
    if url:
        features = extract_features(url)
        prediction = model.predict([features])[0]

        if prediction == 1:
            st.error("⚠️ Warning: This URL might be a phishing site!")
        else:
            st.success("✅ This URL looks safe.")
    else:
        st.warning("Please enter a URL first.")
