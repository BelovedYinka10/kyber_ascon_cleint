import wfdb
import pandas as pd
import numpy as np
import base64
from norway.python_only.pyascon import ascon_encrypt, ascon_decrypt
from hl7apy.core import Message, Segment
from hl7apy.parser import parse_message
from datetime import datetime

# === 1. ASCON Setup ===
# In practice use a securely‐generated random key and nonce,
# here we use fixed values for demonstration:
key = b"\x00" * 16  # 128-bit key
nonce = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"  # 128-bit nonce

# === 2. Load & serialize ECG sample ===
record = "/Users/mac/Desktop/secure by design/norway/norwegian-endurance-athlete-ecg-database-1.0.0/ath_001"
signals, fields = wfdb.rdsamp(record)
df = pd.DataFrame(signals, columns=fields['sig_name'])
df.insert(0, "time", np.arange(signals.shape[0]) / fields['fs'])
json_data = df.to_json(orient="records").encode()

# === 3. Encrypt the ECG JSON with ASCON ===
# (optional – you might embed this in OBX, but here we'll just demonstrate full HL7)
ecg_cipher = ascon_encrypt(
    key=key,
    nonce=nonce,
    plaintext=json_data,
    associateddata=b""
)
b64_ecg = base64.b64encode(ecg_cipher).decode()

# === 4. Build clear-text HL7 ORU^R01 message ===
msg = Message("ORU_R01", version="2.3")
msg.msh.msh_3 = "ECG-CLIENT"
msg.msh.msh_4 = "FPGA-APP"
msg.msh.msh_5 = "ECG-SERVER"
msg.msh.msh_6 = "HOSPITAL"
msg.msh.msh_7 = datetime.utcnow().strftime("%Y%m%d%H%M%S")
msg.msh.msh_9 = "ORU^R01"
msg.msh.msh_10 = "MSG0001"
msg.msh.msh_11 = "P"
msg.msh.msh_12 = "2.3"

pid = Segment("PID", version="2.3")
pid.pid_1 = "1"
pid.pid_3 = "ATH001^^^NOR^^MR"
pid.pid_5 = "Athlete^One"
msg.add(pid)

obr = Segment("OBR", version="2.3")
obr.obr_1 = "1"
obr.obr_4 = "ECG^Electrocardiogram"
msg.add(obr)

# OBX carries the ASCON-encrypted ECG payload
obx = Segment("OBX", version="2.3")
obx.obx_1 = "1"
obx.obx_2 = "ED"
obx.obx_3 = "ECG^EncryptedWaveform"
obx.obx_5 = b64_ecg
obx.obx_11 = "F"
msg.add(obx)

hl7_clear = msg.to_er7().encode()

# === 5. Encrypt the entire HL7 message with ASCON ===
full_cipher = ascon_encrypt(
    key=key,
    nonce=nonce,
    plaintext=hl7_clear,
    associateddata=b""
)
b64_full = base64.b64encode(full_cipher).decode()

print("=== Base64 of ASCON(full HL7) ===")
print(b64_full)

# === 6. Decrypt it back ===
cipher_bytes = base64.b64decode(b64_full)
plain_bytes = ascon_decrypt(
    key=key,
    nonce=nonce,
    ciphertext=cipher_bytes,
    associateddata=b""
)
hl7_decrypted = plain_bytes.decode()

# === 7. Parse & Verify ===
parsed = parse_message(hl7_decrypted, find_groups=False)
print("\nDecrypted HL7 Version:", parsed.msh.msh_12.to_er7())
print("Decrypted HL7 Type   :", parsed.msh.msh_9.to_er7())
print("Full decrypted ER7:\n", hl7_decrypted)
