from datetime import datetime

from flask import Flask, render_template, request, jsonify
import wfdb
import numpy as np
import os
import pandas as pd
import plotly.graph_objects as go
import requests
from pyascon.ascon import ascon_encrypt
from smaj_kyber import encapsulate, set_mode
from hl7apy.core import Message

app = Flask(__name__)

# === Path & Crypto Setup ===
BASE_ECG_DIR = "/Users/mac/Desktop/secure by design/norway/norwegian-endurance-athlete-ecg-database-1.0.0/"
SERVER_URL = os.getenv("SERVER_URL")
CLIENT_URL = os.getenv("CLIENT_URL")

set_mode("512")


@app.route('/')
def redirect_to_first():
    return ecg_viewer(athlete_id=1)


@app.route('/athlete/<int:athlete_id>')
def ecg_viewer(athlete_id):
    try:
        record_path = os.path.join(BASE_ECG_DIR, f"ath_{athlete_id:03d}")
        signals, _ = wfdb.rdsamp(record_path)
    except Exception as e:
        return f"Error loading athlete {athlete_id}: {e}"

    sampling_rate = 500

    duration_sec = signals.shape[0] / sampling_rate

    time_axis = np.arange(0, duration_sec, 1 / sampling_rate)

    lead_names = ['V6', 'V5', 'V4', 'V3', 'V2', 'V1', 'aVF', 'aVL', 'aVR', 'III', 'II', 'I']

    vertical_offsets = np.arange(len(lead_names)) * 2
    lead_names = lead_names[::-1]
    vertical_offsets = vertical_offsets[::-1]

    fig = go.Figure()
    for i in range(12):
        y = (signals[:, i] + vertical_offsets[i]).tolist()
        fig.add_trace(go.Scatter(
            x=time_axis.tolist(),
            y=y,
            mode='lines',
            name=lead_names[i],
            line=dict(color='black', width=1),
            showlegend=False
        ))

    # ECG-style grid
    shapes = []
    grid_color = 'rgba(255, 0, 0, 0.5)'
    for t in np.arange(0, duration_sec + 0.2, 0.2):
        shapes.append(dict(type='line', x0=t, x1=t, y0=vertical_offsets[-1] - 2, y1=vertical_offsets[0] + 2,
                           line=dict(color=grid_color, width=0.8)))
    for y in np.arange(vertical_offsets[-1] - 2, vertical_offsets[0] + 2, 0.5):
        shapes.append(dict(type='line', x0=0, x1=duration_sec, y0=y, y1=y, line=dict(color=grid_color, width=0.8)))

    fig.update_layout(
        title="12-Lead ECG Viewer (Clinical Layout)",
        xaxis=dict(title="Time (seconds)", showgrid=False),
        yaxis=dict(
            tickmode='array',
            tickvals=vertical_offsets,
            ticktext=lead_names,
            showgrid=False
        ),
        shapes=shapes,
        template="simple_white",
        height=800,
        margin=dict(l=60, r=30, t=60, b=40)
    )

    plot_div = fig.to_html(full_html=False)
    return render_template("ecg_viewer.html", graph_html=plot_div, athlete_id=athlete_id)


@app.route('/upload-ecg/<int:athlete_id>', methods=['POST'])
def upload_ecg(athlete_id):
    print("AAAA", athlete_id)
    try:
        # === Step 1: Get Server Public Key ===
        resp = requests.get(f"{SERVER_URL}/kyber-public-key", timeout=5)
        resp.raise_for_status()
        server_pk = resp.content
        print("[INFO] Received Kyber public key from server.")
    except Exception as e:
        return jsonify({"status": "error", "message": "Kyber key fetch failed", "error": str(e)}), 500

    # === Step 2: Load ECG ===
    try:
        record_path = os.path.join(BASE_ECG_DIR, f"ath_{athlete_id:03d}")
        signals, fields = wfdb.rdsamp(record_path)
    except Exception as e:
        return jsonify(
            {"status": "error", "message": f"ECG record not found for athlete {athlete_id}", "error": str(e)}), 404

    # === Step 3: Prepare JSON Payload ===
    df = pd.DataFrame(signals, columns=fields['sig_name'])

    lead_case_fix = {
        'AVR': 'aVR', 'AVL': 'aVL', 'AVF': 'aVF',
        'I': 'I', 'II': 'II', 'III': 'III',
        'V1': 'V1', 'V2': 'V2', 'V3': 'V3',
        'V4': 'V4', 'V5': 'V5', 'V6': 'V6'
    }
    df.rename(columns=lambda col: lead_case_fix.get(col, col), inplace=True)
    df.insert(0, "time", np.arange(signals.shape[0]) / fields['fs'])

    json_data = df.to_json(orient='records')

    # === Step 4: Kyber + Ascon ===
    ct, shared_secret = encapsulate(server_pk)
    key = shared_secret[:16]
    nonce = b"12345678abcdef12"
    ciphertext = ascon_encrypt(key=key, nonce=nonce, plaintext=json_data.encode(), associateddata=b"")

    payload = {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "kyber_ciphertext": ct.hex(),
        "id": athlete_id
    }

    print("hi")

    try:
        r = requests.post(f"{SERVER_URL}/secure-ecg", json=payload, headers={"Content-Type": "application/json"})
        return jsonify({"status": "success", "response": r.text})
    except requests.exceptions.RequestException as e:
        return jsonify({"status": "error", "message": "Upload failed", "error": str(e)}), 500


@app.route('/send_ecg/<int:athlete_id>', methods=['POST'])
def send_ecg_ecg(athlete_id):
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
    record = f"/Users/mac/Desktop/secure by design/norway/norwegian-endurance-athlete-ecg-database-1.0.0/ath_00{athlete_id}"
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

    print("bbb")
    key = shared_secret[:16]
    nonce = b"12345678abcdef12"
    ciphertext = ascon_encrypt(key=key, nonce=nonce, plaintext=json_data.encode(), associateddata=b"")
    now = datetime.utcnow().strftime("%Y%m%d%H%M")

    enc_filename = f"ecg_{now}.enc"
    enc_path = f"./cg/{enc_filename}"  # Make sure this folder exists

    with open(enc_path, "wb") as f:
        f.write(ciphertext)

    # URL to be sent in payload

    url_encrypted = f"{CLIENT_URL}/ecg/{enc_filename}"

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
    obx.obx_5 = url_encrypted
    obx.obx_11 = "F"

    print(msg.to_er7().replace("\r", "\n"))

    headers = {
        "Content-Type": "application/json"
    }

    try:
        r = requests.post(f"{SERVER_URL}/hl_secure-ecg", data=msg.to_er7(), headers=headers)
        print("Status Code:", r.status_code)
        print("Server response:", r.text)
    except requests.exceptions.RequestException as e:
        print("[CLIENT ERROR]", e)

    return "SENT"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
