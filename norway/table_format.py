import wfdb
import numpy as np
import os
import pandas as pd

# === Path to your ECG data ===
directory = "/Users/mac/Desktop/secure by design/norway/norwegian-endurance-athlete-ecg-database-1.0.0/"

# === Load the first .dat ECG file from the directory ===
records = []
signals = None
fields = None

for filename in sorted(os.listdir(directory)):
    if filename.endswith(".dat"):
        record_name = filename.split(".")[0]
        signals, fields = wfdb.rdsamp(os.path.join(directory, record_name))
        records.append(record_name)
        break  # Only take the first file

# === Process to pandas ===
if signals is not None:
    lead_names = fields['sig_name']
    sampling_rate = fields['fs']
    time_axis = np.arange(signals.shape[0]) / sampling_rate

    # Create DataFrame
    df_ecg = pd.DataFrame(signals, columns=lead_names)
    df_ecg.insert(0, "Time (s)", time_axis)

    # Display preview
    print(df_ecg.head())

    # === Save to files ===
    df_ecg.to_csv("ecg_output.csv", index=False)
    df_ecg.to_excel("ecg_output.xlsx", index=False)
    df_ecg.to_json("ecg_output.json", orient="records", lines=True)
    print("ECG saved as .csv, .xlsx, and .json")
else:
    print(".dat file found in the directory.")
