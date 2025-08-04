# import ctypes
# import os
#
# # Load the shared library
# lib = ctypes.CDLL(os.path.abspath("./libascon.dylib"))
#
# Uint8Array = ctypes.POINTER(ctypes.c_ubyte)
# ULongPtr = ctypes.POINTER(ctypes.c_ulonglong)
#
# # Define function prototypes
# lib.crypto_aead_encrypt.argtypes = [Uint8Array, ULongPtr, Uint8Array, ctypes.c_ulonglong,
#                                     Uint8Array, ctypes.c_ulonglong, Uint8Array,
#                                     Uint8Array, Uint8Array]
# lib.crypto_aead_encrypt.restype = ctypes.c_int
#
# lib.crypto_aead_decrypt.\
#
#     argtypes = [Uint8Array, ULongPtr, Uint8Array, Uint8Array,
#                                     ctypes.c_ulonglong, Uint8Array, ctypes.c_ulonglong,
#                                     Uint8Array, Uint8Array]
# lib.crypto_aead_decrypt.restype = ctypes.c_int
#
# # === Use a real Python string ===
# message = "Hello, ECG Server 👋🏽 Secure transmission in progress."
# msg_bytes = message.encode("utf-8")
# msg_len = len(msg_bytes)
# ad = b""  # No associated data
# key = b"\x00" * 16
# nonce = b"\x01" * 16
#
# # Prepare buffers
# msg_buf = (ctypes.c_ubyte * msg_len).from_buffer_copy(msg_bytes)
# ad_buf = (ctypes.c_ubyte * len(ad))(*ad) if ad else None
# key_buf = (ctypes.c_ubyte * 16).from_buffer_copy(key)
# nonce_buf = (ctypes.c_ubyte * 16).from_buffer_copy(nonce)
#
# cipher_len = ctypes.c_ulonglong(msg_len + 16)
# cipher_buf = (ctypes.c_ubyte * cipher_len.value)()
#
# # === ENCRYPT ===
# enc_result = lib.crypto_aead_encrypt(cipher_buf, ctypes.byref(cipher_len),
#                                      msg_buf, msg_len,
#                                      ad_buf, len(ad) if ad else 0,
#                                      None, nonce_buf, key_buf)
#
# print(f"[Encryption] Success? {enc_result == 0}, Ciphertext length: {cipher_len.value} bytes")
#
# # === DECRYPT ===
# msg_out_buf = (ctypes.c_ubyte * msg_len)()
# msg_out_len = ctypes.c_ulonglong(0)
#
# dec_result = lib.crypto_aead_decrypt(msg_out_buf, ctypes.byref(msg_out_len),
#                                      None, cipher_buf, cipher_len.value,
#                                      ad_buf, len(ad) if ad else 0,
#                                      nonce_buf, key_buf)
#
# # Convert back to string
# decrypted = bytes(msg_out_buf[:msg_out_len.value]).decode("utf-8")
#
# print(f"[Decryption] Success? {dec_result == 0}, Plaintext length: {msg_out_len.value} bytes")
# print("[Decrypted Message]:", decrypted)
# print("[Match]:", decrypted == message)
#
#
#
