#!/usr/bin/env python3
import argparse
import base64
import os
import socket
from datetime import datetime

import numpy as np
import pandas as pd
import wfdb
from hl7apy.core import Message
from hl7apy.parser import parse_message
from kyber_py.ml_kem import ML_KEM_512
from pyascon.ascon import ascon_encrypt  # Ascon-128

MLLP_SB = b"\x0b"  # <VT>
MLLP_EB = b"\x1c"  # <FS>
MLLP_CR = b"\x0d"  # <CR>

print("HI ME")
def wrap_mllp(hl7_text: str) -> bytes:
    return MLLP_SB + hl7_text.encode("utf-8") + MLLP_EB + MLLP_CR


def read_mllp(sock: socket.socket) -> str:
    buf = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        if b"\x1c\x0d" in buf:
            break
    if not buf:
        return ""
    if buf.startswith(MLLP_SB) and buf.endswith(MLLP_EB + MLLP_CR):
        buf = buf[len(MLLP_SB):-len(MLLP_EB + MLLP_CR)]
    return buf.decode("utf-8", errors="ignore")


def mllp_exchange(host: str, port: int, hl7_text: str, timeout: float = 10.0) -> str:
    framed = wrap_mllp(hl7_text)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(framed)
        return read_mllp(sock)


def build_qbp_for_pk():
    msg = Message("QBP_Q11", version="2.5", validation_level=2)
    # MSH
    msg.msh.msh_3 = "ClientApp"
    msg.msh.msh_4 = "ClientFac"
    msg.msh.msh_5 = "ServerApp"
    msg.msh.msh_6 = "ServerFac"
    msg.msh.msh_7 = datetime.now().strftime("%Y%m%d%H%M%S")
    msg.msh.msh_9 = "QBP^Q11"
    msg.msh.msh_10 = datetime.now().strftime("%H%M%S%f")
    msg.msh.msh_11 = "P"
    msg.msh.msh_12 = "2.5"

    # QPD
    qpd = msg.add_segment("QPD")
    qpd.qpd_1 = "KYBER_PK"
    qpd.qpd_2 = "QUERY"
    qpd.qpd_3 = "REQUEST"
    return msg


import base64


def extract_pk_from_rsp(rsp_text: str) -> bytes:
    """
    Parse the HL7 ER7 string, find OBX with KYBER_PK in OBX-3, return decoded base64 from OBX-5.
    Works regardless of grouping/nesting and without hl7apy helpers.
    """
    if not rsp_text:
        raise RuntimeError("Empty RSP text")

    # HL7 segments are \r-delimited (sometimes \n on some senders)
    for line in rsp_text.replace("\n", "\r").split("\r"):
        if not line:
            continue
        # Segments begin with 3-letter code
        if not line.startswith("OBX|"):
            continue

        fields = line.split("|")
        # OBX fields (1-based):
        # 1: set ID, 2: value type, 3: observation identifier, 5: observation value, 11: status
        # Ensure we have at least up to OBX-5
        if len(fields) < 6:
            continue

        obx3 = fields[3]  # e.g., "KYBER_PK^Kyber Public Key"
        if "KYBER_PK" in obx3:
            b64_val = fields[5]
            if not b64_val:
                raise RuntimeError("KYBER_PK OBX found but value (OBX-5) is empty")
            try:
                return base64.b64decode(b64_val)
            except Exception as e:
                raise RuntimeError(f"Failed to base64-decode KYBER_PK from OBX-5: {e}")

    # If we’re here, no suitable OBX was found
    # Optional: print raw message for quick debugging
    print("[DEBUG] RSP text (no KYBER_PK OBX found):\n", rsp_text.replace("\r", "\n"))
    raise RuntimeError("No KYBER_PK OBX found in response")


def load_ecg_json(record_path: str) -> str:
    signals, fields = wfdb.rdsamp(record_path)
    df = pd.DataFrame(signals, columns=fields["sig_name"])
    # Fix casing for aVR/aVL/aVF
    lead_case_fix = {
        "AVR": "aVR", "AVL": "aVL", "AVF": "aVF",
        "I": "I", "II": "II", "III": "III",
        "V1": "V1", "V2": "V2", "V3": "V3", "V4": "V4", "V5": "V5", "V6": "V6",
    }
    df.rename(columns=lambda c: lead_case_fix.get(c, c), inplace=True)
    df.insert(0, "time", np.arange(signals.shape[0]) / fields["fs"])
    return df.to_json(orient="records")


def build_oru_with_link(enc_url: str, nonce_hex: str, ct_hex: str):
    msg = Message("ORU_R01", version="2.5", validation_level=2)
    # MSH
    msg.msh.msh_3 = "ClientApp"
    msg.msh.msh_4 = "ClientFac"
    msg.msh.msh_5 = "ServerApp"
    msg.msh.msh_6 = "ServerFac"
    msg.msh.msh_7 = datetime.now().strftime("%Y%m%d%H%M%S")
    msg.msh.msh_9 = "ORU^R01"
    msg.msh.msh_10 = datetime.now().strftime("%H%M%S%f")
    msg.msh.msh_11 = "P"
    msg.msh.msh_12 = "2.5"

    # PID
    pid = msg.add_segment("PID")
    pid.pid_3 = "123456"
    pid.pid_5 = "Doe^John"
    pid.pid_7 = "19800101"
    pid.pid_8 = "M"

    # OBR
    obr = msg.add_segment("OBR")
    obr.obr_1 = "1"
    obr.obr_2 = "ECG123"
    obr.obr_4 = "ECG^Electrocardiogram"
    obr.obr_7 = datetime.now().strftime("%Y%m%d%H%M%S")

    # OBX: text summary
    obx = msg.add_segment("OBX")
    obx.obx_1 = "1"
    obx.obx_2 = "TX"
    obx.obx_3 = "ECGRESULT^ECG Report"
    obx.obx_5 = "Normal sinus rhythm with no abnormalities"
    obx.obx_11 = "F"

    # OBX: link (Reference Pointer)
    obx = msg.add_segment("OBX")
    obx.obx_1 = "2"
    obx.obx_2 = "RP"
    obx.obx_3 = "ECGLINK^Encrypted ECG Link"
    obx.obx_5 = enc_url
    obx.obx_11 = "F"

    # OBX: nonce (hex)
    obx = msg.add_segment("OBX")
    obx.obx_1 = "3"
    obx.obx_2 = "TX"
    obx.obx_3 = "NONCE^Encryption Nonce"
    obx.obx_5 = nonce_hex
    obx.obx_11 = "F"

    # OBX: Kyber ciphertext (hex)
    obx = msg.add_segment("OBX")
    obx.obx_1 = "4"
    obx.obx_2 = "TX"
    obx.obx_3 = "KYBER_CT^Kyber Ciphertext"
    obx.obx_5 = ct_hex
    obx.obx_11 = "F"

    return msg


def main():
    ap = argparse.ArgumentParser(description="HL7 MLLP Client (Kyber PK → ORU with encrypted ECG)")
    ap.add_argument("--server-ip", required=True, help="MLLP server IP")
    ap.add_argument("--server-port", type=int, default=2575, help="MLLP server port")
    ap.add_argument("--athlete-id", type=int, default=1, help="Norwegian athlete ID suffix (e.g., 1 → ath_001)")
    ap.add_argument("--dataset-root", required=True, help="Path containing ath_00X records")
    ap.add_argument("--outdir", default="./cg", help="Directory to save encrypted .enc files")
    ap.add_argument("--client-url", required=True,
                    help="Base URL where server can fetch the saved file (e.g., http://<client-ip>:5050/cg)")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    # === 1) Fetch Kyber public key via QBP^Q11 ===
    qbp = build_qbp_for_pk()
    print("\n[CLIENT] Sending QBP^Q11 for Kyber public key...\n")
    rsp_text = mllp_exchange(args.server_ip, args.server_port, qbp.to_er7(), timeout=10.0)
    if not rsp_text:
        raise RuntimeError("No response to QBP^Q11")
    print("[CLIENT] RSP^K11 received.")

    server_pk = extract_pk_from_rsp(rsp_text)
    print("[CLIENT] Server PK bytes:", len(server_pk))

    # === 2) Load ECG sample and prepare JSON ===
    record = os.path.join(args.dataset_root, f"ath_00{args.athlete_id}")
    ecg_json = load_ecg_json(record)
    print(f"[CLIENT] ECG loaded from {record} (JSON length {len(ecg_json)})")

    # === 3) ML-KEM-512 encapsulation + Ascon-128 encryption ===
    shared_key, kyber_ct = ML_KEM_512.encaps(server_pk)
    ascon_key = shared_key[:16]  # 128-bit
    nonce = os.urandom(16)  # 128-bit nonce for Ascon-128
    ciphertext = ascon_encrypt(key=ascon_key, nonce=nonce, plaintext=ecg_json.encode(), associateddata=b"")

    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    enc_filename = f"ecg_{ts}_{args.athlete_id}.enc"
    enc_path = os.path.join(args.outdir, enc_filename)
    with open(enc_path, "wb") as f:
        f.write(ciphertext)
    print(f"[CLIENT] Encrypted ECG saved: {enc_path} ({len(ciphertext)} bytes)")

    enc_url = f"{args.client_url.rstrip('/')}/{enc_filename}"

    # === 4) Build ORU^R01 and send over MLLP ===
    oru = build_oru_with_link(enc_url, nonce.hex(), kyber_ct.hex())
    print("\n[CLIENT] Sending ORU^R01...\n")
    ack_text = mllp_exchange(args.server_ip, args.server_port, oru.to_er7(), timeout=10.0)
    if not ack_text:
        raise RuntimeError("No ACK received for ORU^R01")

    print("[CLIENT] ACK received:\n")
    print(ack_text.replace("\r", "\n"))


if __name__ == "__main__":
    main()
# python3 client.py   --server-ip 10.85.131.105   --server-port 2575   --athlete-id 1   --dataset-root "/Users/mac/Desktop/secure by design/norway/norwegian-endurance-athlete-ecg-database-1.0.0"   --outdir "./cg"   --client-url "http://10.85.131.213:5050/cg"
