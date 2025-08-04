#!/usr/bin/env python3
import os, base64, socket, numpy as np, pandas as pd, wfdb
from datetime import datetime
from hl7apy.core import Message
from hl7apy.parser import parse_message
from smaj_kyber import encapsulate
from pyascon.ascon import ascon_encrypt  # your wrapper

SERVER_IP = "192.168.1.50"   # <-- set to server LAN/Wi‑Fi IP
SERVER_PORT = 2575
BASE_ECG_DIR = "/Users/mac/Desktop/secure by design/norway/norwegian-endurance-athlete-ecg-database-1.0.0/"

MLLP_SB = b"\x0b"; MLLP_EB = b"\x1c"; MLLP_CR = b"\x0d"
def wrap_mllp(s: str) -> bytes: return MLLP_SB + s.encode("utf-8") + MLLP_EB + MLLP_CR
def unwrap_mllp(b: bytes) -> str:
    if b.startswith(MLLP_SB) and b.endswith(MLLP_EB + MLLP_CR):
        b = b[len(MLLP_SB):-len(MLLP_EB + MLLP_CR)]
    return b.decode("utf-8", errors="ignore")
def b64e(b: bytes) -> str: return base64.b64encode(b).decode("ascii")

def send_recv(hl7: str) -> str:
    with socket.create_connection((SERVER_IP, SERVER_PORT), timeout=10) as sock:
        sock.sendall(wrap_mllp(hl7))
        buf = bytearray()
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            buf.extend(chunk)
            if b"\x1c\x0d" in buf:
                break
    return unwrap_mllp(bytes(buf))

def build_pubkey_query() -> str:
    # Simple QRY asking for KYBER_PUBKEY
    msg = Message("QRY_A19", version="2.5", validation_level=2)
    msg.msh.msh_3 = "ClientApp"
    msg.msh.msh_4 = "Remote"
    msg.msh.msh_5 = "CryptoServer"
    msg.msh.msh_6 = "GW"
    msg.msh.msh_7 = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    msg.msh.msh_9 = "QRY^A19"
    msg.msh.msh_10 = msg.msh.msh_7
    msg.msh.msh_11 = "P"
    msg.msh.msh_12 = "2.5"
    # OBX marker to signal request type
    obx = msg.add_segment("OBX")
    obx.obx_1 = "1"; obx.obx_2 = "TX"
    obx.obx_3 = "KYBER_PUBKEY?^Request"
    obx.obx_5 = "please"
    obx.obx_11 = "F"
    return msg.to_er7()

def parse_pubkey_from_oru(hl7: str) -> bytes:
    msg = parse_message(hl7, find_groups=False)
    for obx in msg.obx:
        if str(obx.obx_3).startswith("KYBER_PUBKEY"):
            return base64.b64decode(str(obx.obx_5).encode("ascii"))
    raise RuntimeError("PubKey not found")

def build_secure_oru(nonce_b64: str, kyber_ct_b64: str, chunks_b64: list[str]) -> str:
    msg = Message("ORU_R01", version="2.5", validation_level=2)
    msg.msh.msh_3 = "ClientApp"; msg.msh.msh_4 = "Remote"
    msg.msh.msh_5 = "CryptoServer"; msg.msh.msh_6 = "GW"
    msg.msh.msh_7 = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    msg.msh.msh_9 = "ORU^R01"; msg.msh.msh_10 = msg.msh.msh_7
    msg.msh.msh_11 = "P"; msg.msh.msh_12 = "2.5"
    msg.add_segment("PID"); msg.add_segment("OBR")

    obx = msg.add_segment("OBX")
    obx.obx_1 = "1"; obx.obx_2 = "TX"
    obx.obx_3 = "NONCE^Ascon Nonce"; obx.obx_5 = nonce_b64; obx.obx_11 = "F"

    obx = msg.add_segment("OBX")
    obx.obx_1 = "2"; obx.obx_2 = "TX"
    obx.obx_3 = "KYBER_CT^Kyber Ciphertext"; obx.obx_5 = kyber_ct_b64; obx.obx_11 = "F"

    i = 3
    for c in chunks_b64:
        obx = msg.add_segment("OBX")
        obx.obx_1 = str(i); obx.obx_2 = "TX"
        obx.obx_3 = f"ECG_CHUNK^{i-2}"
        obx.obx_5 = c; obx.obx_11 = "F"
        i += 1

    return msg.to_er7()

def run(athlete_id: int = 1):
    # 1) Ask server for Kyber public key over MLLP
    qry = build_pubkey_query()
    reply = send_recv(qry)
    server_pk = parse_pubkey_from_oru(reply)
    print("[CLIENT] Got server pubkey (", len(server_pk), "bytes )")

    # 2) Load ECG -> JSON
    record = os.path.join(BASE_ECG_DIR, f"ath_{athlete_id:03d}")
    signals, fields = wfdb.rdsamp(record)
    import pandas as pd
    df = pd.DataFrame(signals, columns=fields['sig_name'])
    fix = {'AVR':'aVR','AVL':'aVL','AVF':'aVF'}
    df.rename(columns=lambda c: fix.get(c, c), inplace=True)
    df.insert(0, "time", np.arange(signals.shape[0]) / fields['fs'])
    json_data = df.to_json(orient="records")

    # 3) Kyber encapsulate -> shared secret; Ascon encrypt
    kyber_ct, shared_secret = encapsulate(server_pk)
    key = shared_secret[:16]
    nonce = os.urandom(16)
    aad = b"ECG_JSON_V1"
    ciphertext = ascon_encrypt(key=key, nonce=nonce,
                               plaintext=json_data.encode("utf-8"),
                               associateddata=aad)

    # 4) Chunk ciphertext (base64) for OBX TX fields
    # 4000 bytes -> ~5336 chars base64; safe for OBX/TX
    chunk_bytes = 4000
    chunks_b64 = [b64e(ciphertext[i:i+chunk_bytes]) for i in range(0, len(ciphertext), chunk_bytes)]

    # 5) Build ORU with NONCE + KYBER_CT + CHUNKs and send
    hl7_secure = build_secure_oru(
        nonce_b64=b64e(nonce),
        kyber_ct_b64=b64e(kyber_ct),
        chunks_b64=chunks_b64
    )
    ack = send_recv(hl7_secure)
    print("[CLIENT] Server responded:\n" + ack.replace("\r","\n"))

if __name__ == "__main__":
    run(athlete_id=1)
