from hl7apy.core import Message
from datetime import datetime

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
obx.obx_5 = "https://ehr.local/files/ecg_encrypted.dat"
obx.obx_11 = "F"

# Print output
print("\nGenerated HL7 ORU^R01 Message:\n")
print(msg.to_er7().replace("\r", "\n"))
