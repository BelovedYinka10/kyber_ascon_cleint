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

# Lead names and reverse order to match clinical layout (V6 at top, Lead I at bottom)
lead_names = ['V6', 'V5', 'V4', 'V3', 'V2', 'V1', 'aVF', 'aVL', 'aVR', 'III', 'II', 'I']
vertical_offsets = np.arange(len(lead_names)) * 2

# Reverse for top-down layout
lead_names = lead_names[::-1]
vertical_offsets = vertical_offsets[::-1]

# Create Plotly figure
fig = go.Figure()

for i in range(12):
    fig.add_trace(go.Scatter(
        x=time_axis,
        y=ecg_sample[:, i] + vertical_offsets[i],
        mode='lines',
        name=lead_names[i],
        line=dict(color='black', width=1),
        showlegend=False
    ))

# Add custom ECG paper-style grid (every 0.2 sec and 0.5 mV)
shapes = []
grid_color = 'rgba(255, 0, 0, 0.5)'  # stronger grid

# Vertical red lines every 0.2 seconds
for t in np.arange(0, duration_sec + 0.2, 0.2):
    shapes.append(dict(
        type='line',
        x0=t, x1=t,
        y0=vertical_offsets[-1] - 2,
        y1=vertical_offsets[0] + 2,
        line=dict(color=grid_color, width=0.8)
    ))

# Horizontal red lines every 0.5 mV
for y in np.arange(vertical_offsets[-1] - 2, vertical_offsets[0] + 2, 0.5):
    shapes.append(dict(
        type='line',
        x0=0,
        x1=duration_sec,
        y0=y,
        y1=y,
        line=dict(color=grid_color, width=0.8)
    ))

# Layout styling
fig.update_layout(
    title="12-Lead ECG Viewer (Clinical Layout)",
    xaxis=dict(
        title="Time (seconds)",
        showgrid=False,
        zeroline=False
    ),
    yaxis=dict(
        tickmode='array',
        tickvals=vertical_offsets,
        ticktext=lead_names,
        showgrid=False,
        zeroline=False
    ),
    shapes=shapes,
    template="simple_white",
    height=800,
    margin=dict(l=60, r=30, t=60, b=40)
)

# Show and export
fig.show()
fig.write_html("ecg_clinical_viewer.html")
