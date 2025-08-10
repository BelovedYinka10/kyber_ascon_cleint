import wfdb
import numpy as np
import os
import plotly.graph_objects as go

# Path to your ECG data
directory = "/Users/mac/Desktop/secure by design/norway/norwegian-endurance-athlete-ecg-database-1.0.0/"

# Load ECGs
ECGs = []
for filename in sorted(os.listdir(directory)):
    if filename.endswith(".dat"):
        record_name = filename.split(".")[0]
        signals, fields = wfdb.rdsamp(os.path.join(directory, record_name))
        ECGs.append(signals)

ECGs = np.array(ECGs)
print("Loaded ECGs shape:", ECGs.shape)

# Get first ECG sample
ecg_sample = ECGs[0]
sampling_rate = 500
duration_sec = ecg_sample.shape[0] / sampling_rate
time_axis = np.arange(0, duration_sec, 1 / sampling_rate)

# === Lead selection ===
# Change this index to choose a different lead (0 to 11)
lead_index = 0
lead_names = ['I', 'II', 'III', 'aVR', 'aVL', 'aVF', 'V1', 'V2', 'V3', 'V4', 'V5', 'V6']
lead_label = lead_names[lead_index]

# === ECG Signal ===
signal = ecg_sample[:, lead_index]

# === Create Plotly Figure ===
fig = go.Figure()

fig.add_trace(go.Scatter(
    x=time_axis,
    y=signal,
    mode='lines',
    name=lead_label,
    line=dict(color='black', width=1),
    showlegend=True
))

# === Add ECG-style grid ===
shapes = []
grid_color = 'rgba(255, 0, 0, 0.4)'  # softer red

# Vertical lines every 0.2 seconds
for t in np.arange(0, duration_sec + 0.2, 0.2):
    shapes.append(dict(
        type='line',
        x0=t, x1=t,
        y0=min(signal) - 0.2,
        y1=max(signal) + 0.2,
        line=dict(color=grid_color, width=0.5)
    ))

# Horizontal lines every 0.5 mV
for y in np.arange(np.floor(min(signal)) - 0.5, np.ceil(max(signal)) + 0.5, 0.5):
    shapes.append(dict(
        type='line',
        x0=0,
        x1=duration_sec,
        y0=y,
        y1=y,
        line=dict(color=grid_color, width=0.5)
    ))

# === Layout Settings ===
fig.update_layout(
    title=f"ECG Viewer - Lead {lead_label}",
    xaxis=dict(title="Time (seconds)", showgrid=False),
    yaxis=dict(title="Voltage (mV)", showgrid=False),
    shapes=shapes,
    template="simple_white",
    height=400,
    margin=dict(l=60, r=30, t=60, b=40)
)

# === Show & Export ===
fig.show()
# fig.write_html(f"ecg_lead_{lead_label}.html")
