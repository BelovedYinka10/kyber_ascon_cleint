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
from pyascon.ascon import ascon_encrypt
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# MLLP framing constants
MLLP_SB = b"\x0b"  # <VT>
MLLP_EB = b"\x1c"  # <FS>
MLLP_CR = b"\x0d"  # <CR>

# Defaults from .env
BASE_ECG_DIR = os.getenv("BASE_ECG_DIR")
SERVER_IP = os.getenv("SERVER_IP")
SERVER_PORT = int(os.getenv("SERVER_PORT", 2575))
ATHLETE_ID = int(os.getenv("ATHLETE_ID", 1))
CLIENT_URL = os.getenv("CLIENT_URL", "http://127.0.0.1:5050/cg")
OUTDIR = os.getenv("OUTDIR", "./cg")
TIMEOUT_SECONDS = int(os.getenv("TIMEOUT_SECONDS", 180 * 60))


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
    print("HOST", host)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(framed)
        return read_mllp(sock)


def build_qbp_for_pk():
    msg = Message("QBP_Q11", version="2.5", validation_level=2)
    msg.msh.msh_3 = "ClientApp"
    msg.msh.msh_4 = "ClientFac"
    msg.msh.msh_5 = "ServerApp"
    msg.msh.msh_6 = "ServerFac"
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
        if not line:
            continue
        if not line.startswith("OBX|"):
            continue
        fields = line.split("|")
        if len(fields) < 6:
            continue
        obx3 = fields[3]
        if "KYBER_PK" in obx3:
            b64_val = fields[5]
            if not b64_val:
                raise RuntimeError("KYBER_PK OBX found but value (OBX-5) is empty")
            return base64.b64decode(b64_val)
    raise RuntimeError("No KYBER_PK OBX found in response")


def load_ecg_json(record_path: str) -> str:
    signals, fields = wfdb.rdsamp(record_path)
    df = pd.DataFrame(signals, columns=fields["sig_name"])
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
    msg.msh.msh_3 = "ClientApp"
    msg.msh.msh_4 = "ClientFac"
    msg.msh.msh_5 = "ServerApp"
    msg.msh.msh_6 = "ServerFac"
    msg.msh.msh_7 = datetime.now().strftime("%Y%m%d%H%M%S")
    msg.msh.msh_9 = "ORU^R01"
    msg.msh.msh_10 = datetime.now().strftime("%H%M%S%f")
    msg.msh.msh_11 = "P"
    msg.msh.msh_12 = "2.5"

    pid = msg.add_segment("PID")
    pid.pid_3 = "123456"
    pid.pid_5 = "Doe^John"
    pid.pid_7 = "19800101"
    pid.pid_8 = "M"

    obr = msg.add_segment("OBR")
    obr.obr_1 = "1"
    obr.obr_2 = "ECG123"
    obr.obr_4 = "ECG^Electrocardiogram"
    obr.obr_7 = datetime.now().strftime("%Y%m%d%H%M%S")

    obx = msg.add_segment("OBX")
    obx.obx_1 = "1"
    obx.obx_2 = "TX"
    obx.obx_3 = "ECGRESULT^ECG Report"
    obx.obx_5 = "Normal sinus rhythm with no abnormalities"
    obx.obx_11 = "F"

    obx = msg.add_segment("OBX")
    obx.obx_1 = "2"
    obx.obx_2 = "RP"
    obx.obx_3 = "ECGLINK^Encrypted ECG Link"
    obx.obx_5 = enc_url
    obx.obx_11 = "F"

    obx = msg.add_segment("OBX")
    obx.obx_1 = "3"
    obx.obx_2 = "TX"
    obx.obx_3 = "NONCE^Encryption Nonce"
    obx.obx_5 = nonce_hex
    obx.obx_11 = "F"

    obx = msg.add_segment("OBX")
    obx.obx_1 = "4"
    obx.obx_2 = "TX"
    obx.obx_3 = "KYBER_CT^Kyber Ciphertext"
    obx.obx_5 = ct_hex
    obx.obx_11 = "F"

    return msg


def main():
    # CLI args override .env values
    ap = argparse.ArgumentParser()
    ap.add_argument("--server-ip", default=SERVER_IP)
    ap.add_argument("--server-port", type=int, default=SERVER_PORT)
    ap.add_argument("--athlete-id", type=int, default=ATHLETE_ID)
    ap.add_argument("--dataset-root", default=BASE_ECG_DIR)
    ap.add_argument("--outdir", default=OUTDIR)
    ap.add_argument("--client-url", default=CLIENT_URL)
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    qbp = build_qbp_for_pk()
    print("[CLIENT] Sending QBP^Q11 for Kyber public key...")
    rsp_text = mllp_exchange(args.server_ip, args.server_port, qbp.to_er7(), timeout=10.0)
    if not rsp_text:
        raise RuntimeError("No response to QBP^Q11")
    server_pk = extract_pk_from_rsp(rsp_text)

    record = os.path.join(args.dataset_root, f"ath_00{args.athlete_id}")
    ecg_json = load_ecg_json(record)

    shared_key, kyber_ct = ML_KEM_512.encaps(server_pk)
    ascon_key = shared_key[:16]
    nonce = os.urandom(16)
    ciphertext = ascon_encrypt(key=ascon_key, nonce=nonce, plaintext=ecg_json.encode(), associateddata=b"")

    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    enc_filename = f"ecg_{ts}_{args.athlete_id}.enc"
    enc_path = os.path.join(args.outdir, enc_filename)
    with open(enc_path, "wb") as f:
        f.write(ciphertext)

    enc_url = f"{args.client_url.rstrip('/')}/{enc_filename}"
    oru = build_oru_with_link(enc_url, nonce.hex(), kyber_ct.hex())
    ack_text = mllp_exchange(args.server_ip, args.server_port, oru.to_er7(), timeout=10.0)
    if not ack_text:
        raise RuntimeError("No ACK received for ORU^R01")
    print("[CLIENT] ACK received:\n", ack_text.replace("\r", "\n"))


if __name__ == "__main__":
    main()
