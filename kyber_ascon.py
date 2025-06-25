import os
from kyber_py import Kyber512
from pyascon import encrypt, decrypt

# # Step 1: Kyber key generation (Alice)
# kyber = Kyber512()
# public_key, secret_key = kyber.keygen()

# # Step 2: Kyber encapsulation (Bob sends a shared secret + ciphertext)
# ciphertext, shared_secret_bob = kyber.encapsulate(public_key)

# # Step 3: Kyber decapsulation (Alice recovers the shared secret)
# shared_secret_alice = kyber.decapsulate(ciphertext, secret_key)

# assert shared_secret_bob == shared_secret_alice
# print("✅ Shared secret established!")

# # Step 4: Derive ASCON-128 key (use first 16 bytes of shared secret)
# key = shared_secret_alice[:16]  # ASCON-128 expects 128-bit key
# nonce = os.urandom(16)          # 128-bit nonce
# ad = b"header"                  # Associated data
# plaintext = b"My secret message over post-quantum secure channel"

# # Step 5: Encrypt with ASCON
# ciphertext, tag = encrypt(key, nonce, ad, plaintext, variant="Ascon-128")
# print("🔐 Ciphertext:", ciphertext.hex())
# print("🔖 Tag:", tag.hex())

# # Step 6: Decrypt with ASCON
# decrypted = decrypt(key, nonce, ad, ciphertext, tag, variant="Ascon-128")
# assert decrypted == plaintext
# print("✅ Decryption successful. Message:", decrypted.decode())



import os
from kyber_py import Kyber512
from pyascon import encrypt, decrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Step 1: Kyber key generation (Alice)
kyber = Kyber512()
public_key, secret_key = kyber.keygen()

# Step 2: Kyber encapsulation (Bob sends a shared secret + ciphertext)
ciphertext, shared_secret_bob = kyber.encapsulate(public_key)

# Step 3: Kyber decapsulation (Alice recovers the shared secret)
shared_secret_alice = kyber.decapsulate(ciphertext, secret_key)

assert shared_secret_bob == shared_secret_alice
print("✅ Shared secret established!")

# Step 4: Use HKDF to derive a 128-bit key for ASCON
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=16,  # 128 bits = 16 bytes
    salt=None,
    info=b'ascon-key-derivation',
    backend=default_backend()
)

key = hkdf.derive(shared_secret_alice)

# Step 5: Encrypt using ASCON-128
nonce = os.urandom(16)  # 128-bit nonce
ad = b"header"          # Associated data
plaintext = b"My secret message over post-quantum secure channel"

ciphertext, tag = encrypt(key, nonce, ad, plaintext, variant="Ascon-128")
print("🔐 Ciphertext:", ciphertext.hex())
print("🔖 Tag:", tag.hex())

# Step 6: Decrypt and verify
decrypted = decrypt(key, nonce, ad, ciphertext, tag, variant="Ascon-128")
assert decrypted == plaintext
print("✅ Decryption successful. Message:", decrypted.decode())
