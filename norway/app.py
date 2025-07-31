from flask import Flask, render_template, request, jsonify
import wfdb
import numpy as np
import os
import pandas as pd
import plotly.graph_objects as go
import requests
from pyascon.ascon import ascon_encrypt
from smaj_kyber import encapsulate, set_mode

app = Flask(__name__)

# === Path & Crypto Setup ===
BASE_ECG_DIR = "/Users/mac/Desktop/secure by design/norway/norwegian-endurance-athlete-ecg-database-1.0.0/"
SERVER_URL = os.getenv("SERVER_URL")

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


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)

