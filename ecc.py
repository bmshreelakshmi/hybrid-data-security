from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

def generate_keypair():
    k=ECC.generate(curve="P-256")
    return k.export_key(format="PEM"), k.public_key().export_key(format="PEM")

def derive_shared_key(private_pem, peer_public_pem, salt):
    a=ECC.import_key(private_pem); b=ECC.import_key(peer_public_pem)
    shared=key_agreement(static_priv=a, static_pub=b, kdf=lambda x:x)
    return HKDF(shared,32,salt,SHA256,context=b"HybridDataSecurity-v1")
