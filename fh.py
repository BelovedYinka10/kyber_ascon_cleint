import hl7

# Correctly formatted HL7 message using carriage return (\r)
raw_message = (
    "MSH|^~\\&|ADT|HOSPITAL|EHR|EHRFACILITY|202506241000||ADT^A01|MSG00001|P|2.3\r"
    "PID|1||123456^^^HOSPITAL^MR||DOE^JOHN||19800101|M|||123 MAIN ST^^LAGOS^^100001|08012345678\r"
)

# Parse the message
h = hl7.parse(raw_message)

# Loop through and print PID name fields
for segment in h.segments:
    if segment[0][0] == 'PID':
        name = segment[5]
        print("Last Name:", name[0][0])
        print("First Name:", name[0][1])
