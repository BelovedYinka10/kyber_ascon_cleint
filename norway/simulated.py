import wfdb
import pandas as pd

# Set the directory path
directory = "/Users/mac/Desktop/secure by design/norway/norwegian-endurance-athlete-ecg-database-1.0.0/"
record_name = "ath_001"

# Load the ECG record
record = wfdb.rdrecord(directory + record_name)

# Create DataFrame from signal data
df = pd.DataFrame(record.p_signal, columns=record.sig_name)

# Construct output base path
base_path = f"{directory}{record_name}"

# Export to CSV
df.to_csv(f"{base_path}.csv", index=False)

# Export to JSON
df.to_json(f"{base_path}.json", orient="records", lines=False)

# Export to XML
# We'll create a very basic XML structure manually
# with open(f"{base_path}.xml", "w") as xml_file:
#     xml_file.write('<?xml version="1.0" encoding="UTF-8"?>\n')
#     xml_file.write(f"<ECGRecord name='{record_name}'>\n")
#     for i, row in df.iterrows():
#         xml_file.write("  <Sample>\n")
#         for lead, value in row.items():
#             xml_file.write(f"    <{lead}>{value}</{lead}>\n")
#         xml_file.write("  </Sample>\n")
#     xml_file.write("</ECGRecord>\n")

print(f"Exported to: {base_path}.csv, .json, .xml")

# Optional: Plot the waveform
wfdb.plot_wfdb(record=record, title='ECG from Norwegian Athlete Dataset')
