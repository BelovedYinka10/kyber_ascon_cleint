import os
import wfdb
import pandas as pd
import numpy as np
import requests
from pyascon import ascon
from smaj_kyber import encapsulate, set_mode
from pyascon.ascon import ascon_encrypt
from datetime import datetime
from hl7apy.core import Message
from datetime import datetime

SERVER_URL = "http://10.27.91.105:5000"

# === Kyber Setup ===
set_mode("512")

# === Step 1: Download Server Public Key ===
try:
    resp = requests.get(f"{SERVER_URL}/kyber-public-key", timeout=5)
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

# hl7 = (
#     f"MSH|^~\\&|CLIENT_APP|REMOTE_SITE|HOSPITAL|SERVER|{now}||ORU^R01|MSG123|P|2.5\r"
#     f"PID|1||555555^^^HOSPITAL^MR||DOE^JANE||19900101|F\r"
#     f"OBR|1||ORDER123||ECG^Encrypted ECG Transmission|||{now}||||||||9999^DOCTOR^SERVER\r"
#     f"OBX|1|TX|ECG_LINK^ECG File URL||{url_encrypted}||||||F\r"
#     f"OBX|2|TX|NONCE^Encryption Nonce||{nonce.hex()}||||||F\r"
#     f"OBX|3|TX|KYBER_CT^Kyber Ciphertext||{ct.hex()}||||||F\r"
# )


# Create ORU^R01 message
msg = Message("ORU_R01", version="2.5", validation_level=2)

# MSH Segment
msg.msh.msh_3 = "SendingApp"
msg.msh.msh_4 = "SendingFac"
msg.msh.msh_5 = "ReceivingApp"
msg.msh.msh_6 = "ReceivingFac"
msg.msh.msh_7 = datetime.now().strftime('%Y%m%d%H%M%S')
msg.msh.msh_9 = "ORU^R01"
msg.msh.msh_10 = "123456"  # Message Control ID
msg.msh.msh_11 = "P"
msg.msh.msh_12 = "2.5"

# PID Segment
pid = msg.add_segment("PID")
pid.pid_3 = "123456"
pid.pid_5 = "Doe^John"
pid.pid_7 = "19800101"
pid.pid_8 = "M"

# OBR Segment (Observation Request)
obr = msg.add_segment("OBR")
obr.obr_1 = "1"
obr.obr_2 = "ECG123"  # Placer Order Number
obr.obr_4 = "ECG^Electrocardiogram"
obr.obr_7 = datetime.now().strftime('%Y%m%d%H%M%S')  # Observation datetime

# OBX Segment (Observation Result)
obx = msg.add_segment("OBX")
obx.obx_1 = "1"
obx.obx_2 = "TX"  # Text data
obx.obx_3 = "ECGRESULT^ECG Report"
obx.obx_5 = "Normal sinus rhythm with no abnormalities"
obx.obx_11 = "F"  # Result status: Final

obx = msg.add_segment("OBX")
obx.obx_1 = "2"
obx.obx_2 = "RP"  # Reference Pointer
obx.obx_3 = "ECGLINK^Encrypted ECG Link"
obx.obx_5 = "https://ehr.local/files/ecg_encrypted.dat"
obx.obx_11 = "F"

headers = {
    "Content-Type": "application/json"
}

try:
    r = requests.post(f"{SERVER_URL}/hl_secure-ecg", data=msg.to_er7(), headers=headers)
    print("Status Code:", r.status_code)
    print("Server response:", r.text)
except requests.exceptions.RequestException as e:
    print("[CLIENT ERROR]", e)
