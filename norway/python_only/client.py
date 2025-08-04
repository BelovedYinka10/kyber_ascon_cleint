#!/usr/bin/env python3
import socket
from datetime import datetime
from hl7apy.core import Message

# -----------------------------
# Build HL7 ORU^R01 with hl7apy
# -----------------------------
msg = Message("ORU_R01", version="2.5", validation_level=2)

# MSH
msg.msh.msh_3 = "SendingApp"
msg.msh.msh_4 = "SendingFac"
msg.msh.msh_5 = "ReceivingApp"
msg.msh.msh_6 = "ReceivingFac"
msg.msh.msh_7 = datetime.now().strftime("%Y%m%d%H%M%S")
msg.msh.msh_9 = "ORU^R01"
msg.msh.msh_10 = "123456"  # Message Control ID
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
obr.obr_2 = "ECG123"  # Placer Order Number
obr.obr_4 = "ECG^Electrocardiogram"
obr.obr_7 = datetime.now().strftime("%Y%m%d%H%M%S")

# OBX (text result)
obx = msg.add_segment("OBX")
obx.obx_1 = "1"
obx.obx_2 = "TX"
obx.obx_3 = "ECGRESULT^ECG Report"
obx.obx_5 = "Normal sinus rhythm with no abnormalities"
obx.obx_11 = "F"

# OBX (reference pointer)
obx = msg.add_segment("OBX")
obx.obx_1 = "2"
obx.obx_2 = "RP"
obx.obx_3 = "ECGLINK^Encrypted ECG Link"
obx.obx_5 = "http://10.85.131.213:5050/cg/ecg_202508041241_1.enc"
obx.obx_11 = "F"

hl7_str = msg.to_er7()  # raw HL7 with \r separators

print("\nGenerated HL7 ORU^R01 Message:\n")
print(hl7_str.replace("\r", "\n"))

# -----------------------------
# MLLP framing + send over TCP
# -----------------------------
MLLP_SB = b"\x0b"  # <VT>
MLLP_EB = b"\x1c"  # <FS>
MLLP_CR = b"\x0d"  # <CR>


def wrap_mllp(hl7_text: str) -> bytes:
    return MLLP_SB + hl7_text.encode("utf-8") + MLLP_EB + MLLP_CR


def unwrap_mllp(data: bytes) -> str:
    if data.startswith(MLLP_SB) and data.endswith(MLLP_EB + MLLP_CR):
        data = data[len(MLLP_SB):-len(MLLP_EB + MLLP_CR)]
    return data.decode("utf-8", errors="ignore")


def send_hl7_mllp(host: str, port: int, hl7_text: str, timeout: float = 10.0) -> str:
    framed = wrap_mllp(hl7_text)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(framed)

        # Read until MLLP trailer appears
        buf = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
            if b"\x1c\x0d" in buf:
                break

    return unwrap_mllp(bytes(buf))


# ---- Change these to your receiver's IP/port ----
SERVER_IP = "10.85.131.105"  # receiver system's LAN/Wi‑Fi IP
SERVER_PORT = 2575  # receiver's MLLP port
# -------------------------------------------------

try:
    ack = send_hl7_mllp(SERVER_IP, SERVER_PORT, hl7_str)
    print("\n--- ACK from server ---\n")
    print(ack.replace("\r", "\n"))
except Exception as e:
    print("[ERROR] MLLP send failed:", e)
