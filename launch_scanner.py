import subprocess
import sys
import os

base_dir = os.path.dirname(os.path.abspath(__file__))
target_path = os.path.join(base_dir, 'cybersecurity_pro_scanner_risk_ip.py')

# Silent launch
subprocess.Popen(
    [sys.executable, "-m", "streamlit", "run", target_path],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)
