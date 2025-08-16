Thank you — here's a properly structured `README.md` file describing exactly what your script does, in plain terms and
with clarity for any collaborator or future reader.

---

###   

📄 `README.md`

```markdown
# 🩺 Secure ECG Transmission using Kyber and Ascon

This project demonstrates how to securely transmit ECG data using post-quantum and lightweight cryptography, structured
in an HL7 medical message format.

It uses:

- **Kyber512** for post-quantum secure key encapsulation
- **Ascon-128** for authenticated encryption of ECG data
- **HL7** to format the encrypted message for clinical systems

---

## 🚀 Workflow Overview

### ✅ 1. Kyber Key Exchange

The script initiates a **secure session** by retrieving the **Kyber public key** from the server endpoint:

```

How to run this code

```markdown
# 🩺 Secure ECG Transmission using Kyber and Ascon from the client

1) git clone repo


2) cd kyber_ascon_client

3) git checkout arms

4) python -m venv venv

5) activate the virtualenv

6) pip install -r requirements

7) cd norway

8) Edit the .env file with server Ip

9) cd python_only

## for http protocol

10) python app.py

## for mllp protocol

11) python mllp_hl7_client_app.py

--

```

GET /kyber-public-key

```

This public key is used to perform **Kyber key encapsulation**, generating:
- A ciphertext (`ct`)
- A shared secret (`ss`)

The shared secret is truncated and used as the **encryption key** for Ascon.

---

### ✅ 2. ECG Data Acquisition
The script loads ECG waveform data using **WFDB** from a local PhysioNet dataset:
```

norwegian-endurance-athlete-ecg-database-1.0.0

```

Steps:
- Read ECG leads using `wfdb.rdsamp(...)`
- Normalize lead names (e.g., `AVR` ➝ `aVR`)
- Add timestamp column
- Convert data to JSON (record-wise)

---

### ✅ 3. Encryption with Ascon
Using the shared secret from Kyber, the ECG data is encrypted with **Ascon-128** using:
- A 16-byte key derived from the shared secret
- A static 16-byte nonce (`12345678abcdef12`)
- Associated data set to `"MacBook"`

The ciphertext is saved to:
```

/Desktop/secure by design/norway/cg/ecg\_<timestamp>.enc

```
---

### ✅ 4. HL7 Message Construction
The script constructs an **HL7 v2.5 ORU^R01 message**, including:

| HL7 Segment | Field                            | Description                        |
|-------------|----------------------------------|------------------------------------|
| `OBX|1`     | ECG File URL                     | HTTP path to encrypted `.enc` file |
| `OBX|2`     | Nonce                            | Nonce used for Ascon encryption    |
| `OBX|3`     | Kyber Ciphertext                 | Needed for server to derive key    |

---

### ✅ 5. Secure Transmission
The HL7 message is sent to:
```

POST /secure-ecg

```

On the Flask server at:
```

[http://192.168.223.105:5000](http://192.168.223.105:5000)

````

The content-type is set as `application/json`, although HL7 is embedded as raw text.

---

## 📁 Folder Assumptions

The script assumes these paths exist:
- Raw ECG data:  
  `/Users/mac/Desktop/secure by design/norway/norwegian-endurance-athlete-ecg-database-1.0.0/`
- Encrypted output:  
  `/Users/mac/Desktop/secure by design/norway/cg/`

---

## 🔐 Crypto Libraries Used

- [`pyascon`](https://github.com/IAIK/pyascon): Ascon-128 encryption
- `smaj_kyber`: Custom Kyber encapsulation module (must implement `encapsulate(...)`)

---

## ⚙️ Requirements

```bash
pip install wfdb pandas numpy requests pyascon
````

You must also have:

* `smaj_kyber.py` in the Python path
* A Flask server running and listening at the IP in `base_url`

---

## 🧪 Example Output

```bash
[INFO] Received Kyber public key from server.
Status Code: 200
Server response: ECG message successfully received and processed.
```

---

## 📌 Notes

* This is a prototype for secure transmission of clinical waveform data using hybrid post-quantum and lightweight
  cryptography.
* Designed for Medical Internet of Things (MIoT) and edge-device testing.

```

