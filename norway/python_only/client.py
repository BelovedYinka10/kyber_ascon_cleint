from kyber_py.ml_kem import ML_KEM_512
ek, dk = ML_KEM_512.keygen()
key, ct = ML_KEM_512.encaps(ek)
_key = ML_KEM_512.decaps(dk, ct)
assert key == _key