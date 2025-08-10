#!/usr/bin/env python3
import argparse
import base64
import os
import socket
import time
from datetime import datetime

import numpy as np
import pandas as pd
import wfdb
from hl7apy.core import Message
from kyber_py.ml_kem import ML_KEM_512
from pyascon.ascon import ascon_encrypt
from dotenv import load_dotenv

# === Load environment variables ===
load_dotenv()

BASE_ECG_DIR = os.getenv("BASE_ECG_DIR")
SERVER_IP = os.getenv("SERVER_IP")
SERVER_PORT = int(os.getenv("SERVER_PORT", 2575))
ATHLETE_ID = int(os.getenv("ATHLETE_ID", 1))
dt_format = os.getenv("DATA_FORMAT", "JSON")
TIMEOUT_SECONDS = int(os.getenv("TIMEOUT_SECONDS", 180 * 60))

# === MLLP framing constants ===
MLLP_SB = b"\x0b"
MLLP_EB = b"\x1c"
MLLP_CR = b"\x0d"


def wrap_mllp(hl7_text: str) -> bytes:
    return MLLP_SB + hl7_text.encode("utf-8") + MLLP_EB + MLLP_CR


def read_mllp(sock: socket.socket, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    buf = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("MLLP read timed out waiting for <FS><CR> trailer")
        sock.settimeout(remaining)
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


def mllp_exchange(host: str, port: int, hl7_text: str) -> str:
    framed = wrap_mllp(hl7_text)
    with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS) as sock:
        sock.settimeout(TIMEOUT_SECONDS)
        sock.sendall(framed)
        return read_mllp(sock, TIMEOUT_SECONDS)


def build_qbp_for_pk():
    msg = Message("QBP_Q11", version="2.5", validation_level=2)
    msg.msh.msh_3 = "ClientApp"
    msg.msh.msh_4 = "ClientFacility"
    msg.msh.msh_5 = "ServerApp"
    msg.msh.msh_6 = "ServerFacility"
    msg.msh.msh_7 = datetime.now().strftime("%Y%m%d%H%M%S")
    msg.msh.msh_9 = "QBP^Q11"
    msg.msh.msh_10 = datetime.now().strftime("%H%M%S%f")
    msg.msh.msh_11 = "P"
    msg.msh.msh_12 = "2.5"
    qpd = msg.add_segment("QPD")
    qpd.qpd_1 = "KYBER_PK"
    qpd.qpd_2 = "QUERY"
    qpd.qpd_3 = "REQUEST"
    return msg


def extract_pk_from_rsp(rsp_text: str) -> bytes:
    if not rsp_text:
        raise RuntimeError("Empty RSP text")
    for line in rsp_text.replace("\n", "\r").split("\r"):
        if not line or not line.startswith("OBX|"):
            continue
        fields = line.split("|")
        if len(fields) < 6:
            continue
        if "KYBER_PK" in fields[3]:
            b64_val = fields[5]
            if not b64_val:
                raise RuntimeError("KYBER_PK OBX found but OBX-5 is empty")
            return base64.b64decode(b64_val)
    raise RuntimeError("No KYBER_PK OBX found in response")


def load_ecg_data(record_path: str, format: str) -> str:
    signals, fields = wfdb.rdsamp(record_path)
    df = pd.DataFrame(signals, columns=fields["sig_name"])
    lead_case_fix = {
        "AVR": "aVR", "AVL": "aVL", "AVF": "aVF",
        "I": "I", "II": "II", "III": "III",
        "V1": "V1", "V2": "V2", "V3": "V3", "V4": "V4", "V5": "V5", "V6": "V6",
    }
    df.rename(columns=lambda c: lead_case_fix.get(c, c), inplace=True)
    df.insert(0, "time", np.arange(signals.shape[0]) / fields["fs"])

    if format.upper() == "XML":
        return df.to_xml(root_name="ECGData", row_name="Record", index=False)
    return df.to_json(orient="records")


def build_oru_with_ciphertext(ct_b64: str, nonce_b64: str, kyber_ct_b64: str, dt_format: str):
    msg = Message("ORU_R01", version="2.5", validation_level=2)
    msg.msh.msh_3 = "ClientApp"
    msg.msh.msh_4 = "ClientFacility"
    msg.msh.msh_5 = "ServerApp"
    msg.msh.msh_6 = "ServerFacility"
    msg.msh.msh_7 = datetime.now().strftime("%Y%m%d%H%M%S")
    msg.msh.msh_9 = "ORU^R01"
    msg.msh.msh_10 = datetime.now().strftime("%H%M%S%f")
    msg.msh.msh_11 = "P"
    msg.msh.msh_12 = "2.5"

    msg.add_segment("PID")
    msg.add_segment("OBR")

    obx = msg.add_segment("OBX")
    obx.obx_1 = "0"
    obx.obx_2 = "TX"
    obx.obx_3 = "ECG_FORMAT^Format"
    obx.obx_5 = dt_format.upper()
    obx.obx_11 = "F"

    obx = msg.add_segment("OBX")
    obx.obx_1 = "1"
    obx.obx_2 = "TX"
    obx.obx_3 = "ECG_CIPHERTEXT_B64^Encrypted ECG"
    obx.obx_5 = ct_b64
    obx.obx_11 = "F"

    obx = msg.add_segment("OBX")
    obx.obx_1 = "2"
    obx.obx_2 = "TX"
    obx.obx_3 = "NONCE_B64^Ascon Nonce"
    obx.obx_5 = nonce_b64
    obx.obx_11 = "F"

    obx = msg.add_segment("OBX")
    obx.obx_1 = "3"
    obx.obx_2 = "TX"
    obx.obx_3 = "KYBER_CT_B64^Kyber Ciphertext"
    obx.obx_5 = kyber_ct_b64
    obx.obx_11 = "F"

    return msg


def main():
    parser = argparse.ArgumentParser(description="HL7 MLLP Client for ECG Transmission")
    parser.add_argument("--athlete-id", type=int, default=ATHLETE_ID)
    args = parser.parse_args()

    qbp = build_qbp_for_pk()
    print("\n[CLIENT] Sending QBP^Q11 for Kyber public key...\n")
    rsp_text = mllp_exchange(SERVER_IP, SERVER_PORT, qbp.to_er7())
    print("[CLIENT] RSP^K11 received.")
    server_pk = extract_pk_from_rsp(rsp_text)

    record_path = os.path.join(BASE_ECG_DIR, f"ath_00{args.athlete_id}")
    ecg_data = load_ecg_data(record_path, dt_format)

    shared_key, kyber_ct = ML_KEM_512.encaps(server_pk)
    ascon_key = shared_key[:16]
    nonce = os.urandom(16)

    ciphertext = ascon_encrypt(
        key=ascon_key,
        nonce=nonce,
        plaintext=ecg_data.encode("utf-8"),
        associateddata=b""
    )

    ct_b64 = base64.b64encode(ciphertext).decode()
    nonce_b64 = base64.b64encode(nonce).decode()
    kyber_ct_b64 = base64.b64encode(kyber_ct).decode()

    oru = build_oru_with_ciphertext(ct_b64, nonce_b64, kyber_ct_b64, dt_format)

    print("\n[CLIENT] Sending ORU^R01 with embedded ciphertext...\n")
    ack_text = mllp_exchange(SERVER_IP, SERVER_PORT, oru.to_er7())
    print("[CLIENT] ACK received:\n")
    print(ack_text.replace("\r", "\n"))


if __name__ == "__main__":
    main()
