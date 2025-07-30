import os
from flask import Flask
from flask_restx import Api, Resource, fields
import requests
from hl7apy.core import Message
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
api = Api(
    app,
    version="1.0",
    title="HL7 Sender API",
    description="API for sending HL7 ADT^A01 messages",
    doc="/swagger"  # Enable Swagger UI at /swagger
)

# Namespace for HL7 operations
ns = api.namespace("hl7", description="HL7 message operations")

# Response model for Swagger
hl7_response_model = api.model("HL7Response", {
    "status": fields.String(description="Operation status"),
    "hl7": fields.String(description="Generated HL7 message"),
    "receiver_response": fields.String(description="Receiver's response")
})

# Receiver configuration (update with your receiver URL)

SERVER_URL = os.getenv("SERVER_URL")
RECEIVER_URL = f"{SERVER_URL}/receive-hl7"



def create_hl7_message():
    """Generate an HL7 ADT^A01 message"""
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

    return msg.to_er7()


@ns.route("/send")
class HL7Sender(Resource):
    @api.doc(description="Send an HL7 message to the receiver")
    @api.marshal_with(hl7_response_model)
    def get(self):
        """Send HL7 Message"""
        hl7_msg = create_hl7_message()

        print("hl7_msg", hl7_msg)

        # Send to receiver
        headers = {"Content-Type": "text/plain"}
        response = requests.post(RECEIVER_URL, data=hl7_msg, headers=headers)

        return {
                   "status": "Message sent successfully",
                   "hl7": hl7_msg,
                   "receiver_response": response.text
               }, 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
