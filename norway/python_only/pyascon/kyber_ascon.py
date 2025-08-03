import os
import ascon  # This is the ascon.py from the pyascon GitHub repo

# Step 1: Simulate a shared secret (as if from Kyber)
shared_secret = os.urandom(32)  # 256-bit random shared secret



# # Step 2: Derive a 128-bit ASCON key using HKDF
# hkdf = HKDF(
#     algorithm=hashes.SHA256(),
#     length=16,  # ASCON-128 key size = 16 bytes
#     salt=None,
#     info=b'ascon-key',
#     backend=default_backend()
# )
# key = hkdf.derive(shared_secret)


key = shared_secret[:16]  # Take first 16 bytes (128 bits)


# Step 3: Prepare ASCON encryption parameters
nonce = os.urandom(16)        # 16 bytes nonce
ad = b"header"                # Associated data
plaintext = b"Fake Kyber message test"

# Step 4: Encrypt (returns ciphertext + tag as one bytes object)
ciphertext_and_tag = ascon.ascon_encrypt(key, nonce, ad, plaintext)

# Split ciphertext and tag manually
ciphertext = ciphertext_and_tag[:-16]
tag = ciphertext_and_tag[-16:]

print("🔐 Ciphertext:", ciphertext.hex())
print("🔖 Tag:", tag.hex())

# Step 5: Decrypt (pass full ciphertext + tag)
decrypted = ascon.ascon_decrypt(key, nonce, ad, ciphertext_and_tag)
print("✅ Decrypted:", decrypted.decode())
