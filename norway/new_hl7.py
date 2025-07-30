from hl7apy.core import Message
from datetime import datetime

# Create message (force MSH to be first)
msg = Message("ADT_A01", version="2.5", validation_level=2)  # Enable validation

# MSH Segment (MUST be first)
msg.msh.msh_3 = "SendingApp"
msg.msh.msh_4 = "SendingFac"
msg.msh.msh_5 = "ReceivingApp"
msg.msh.msh_6 = "ReceivingFac"
msg.msh.msh_7 = datetime.now().strftime('%Y%m%d%HM%S')
msg.msh.msh_9 = "ADT^A01"
msg.msh.msh_10 = "123456"
msg.msh.msh_11 = "P"
msg.msh.msh_12 = "2.5"

# PID Segment (add explicitly)
pid = msg.add_segment("PID")
pid.pid_3 = "123456"
pid.pid_5 = "Doe^John"
pid.pid_7 = "19800101"
pid.pid_8 = "M"

# PV1 Segment (add explicitly)
pv1 = msg.add_segment("PV1")
pv1.pv1_1 = "1"  # Required
pv1.pv1_2 = "I"
pv1.pv1_3 = "WARD1^ROOM2^BED1"

# Access individual PID fields
print("Patient ID:", pid.pid_3.value)  # 123456
print("Patient Name:", pid.pid_5.value)  # Doe^John
print("Date of Birth:", pid.pid_7.value)  # 19800101
# Print the message
print(msg.to_er7().replace("\r", "\n"))
