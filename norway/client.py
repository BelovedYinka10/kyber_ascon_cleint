import wfdb
import pandas as pd
import numpy as np
import requests
from pyascon import ascon
from smaj_kyber import encapsulate, set_mode
from pyascon.ascon import ascon_encrypt
from datetime import datetime


base_url="http://192.168.223.105:5000"

# === Kyber Setup ===
set_mode("512")

# === Step 1: Download Server Public Key ===
try:
    resp = requests.get(f"{base_url}/kyber-public-key", timeout=5)
    resp.raise_for_status()
    server_pk = resp.content
    print("[INFO] Received Kyber public key from server.")
except Exception as e:
    print("[ERROR] Failed to fetch Kyber public key:", e)
    exit(1)

# === Step 2: Load ECG Sample ===
record = "/Users/mac/Desktop/secure by design/norway/norwegian-endurance-athlete-ecg-database-1.0.0/ath_001"
signals, fields = wfdb.rdsamp(record)

df = pd.DataFrame(signals, columns=fields['sig_name'])

# Fix casing
lead_case_fix = {
    'AVR': 'aVR', 'AVL': 'aVL', 'AVF': 'aVF',
    'I': 'I', 'II': 'II', 'III': 'III',
    'V1': 'V1', 'V2': 'V2', 'V3': 'V3',
    'V4': 'V4', 'V5': 'V5', 'V6': 'V6'
}
df.rename(columns=lambda col: lead_case_fix.get(col, col), inplace=True)
df.insert(0, "time", np.arange(signals.shape[0]) / fields['fs'])

json_data = df.to_json(orient='records')

# === Step 3: Kyber Encapsulation + Ascon Encryption ===
ct, shared_secret = encapsulate(server_pk)
key = shared_secret[:16]
nonce = b"12345678abcdef12"
ciphertext = ascon_encrypt(key=key, nonce=nonce, plaintext=json_data.encode(), associateddata=b"")
now = datetime.utcnow().strftime("%Y%m%d%H%M")


enc_filename = f"ecg_{now}.enc"
enc_path = f"/Users/mac/Desktop/secure by design/norway/cg/{enc_filename}"  # Make sure this folder exists

with open(enc_path, "wb") as f:
    f.write(ciphertext)

# URL to be sent in payload

client_url = "http://192.168.106.105:5000"
url_encrypted = f"{client_url}/ecg/{enc_filename}"


hl7 = (
    f"MSH|^~\\&|CLIENT_APP|REMOTE_SITE|HOSPITAL|SERVER|{now}||ORU^R01|MSG123|P|2.5\r"
    f"PID|1||555555^^^HOSPITAL^MR||DOE^JANE||19900101|F\r"
    f"OBR|1||ORDER123||ECG^Encrypted ECG Transmission|||{now}||||||||9999^DOCTOR^SERVER\r"
    f"OBX|1|TX|ECG_LINK^ECG File URL||{url_encrypted}||||||F\r"
    f"OBX|2|TX|NONCE^Encryption Nonce||{nonce.hex()}||||||F\r"
    f"OBX|3|TX|KYBER_CT^Kyber Ciphertext||{ct.hex()}||||||F\r"
)

headers = {
    "Content-Type": "application/json"
}

try:
    r = requests.post(f"{base_url}/secure-ecg", data=hl7, headers=headers)
    print("Status Code:", r.status_code)
    print("Server response:", r.text)
except requests.exceptions.RequestException as e:
    print("[CLIENT ERROR]", e)
