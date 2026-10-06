import os
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils, dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

def check_transcript(trns):
    if (len(trns) != 8):
        raise ValueError("Malformed transcript")
    if (trns[0] != b"CSCE465-HS-v2"):
        raise ValueError("Invalid protocol version")
    if (trns[1] != b"ffdhe3072"):
        raise ValueError("Invalid group")
    if (trns[2] != b"Alice"):
        raise ValueError("Unexpected Alice identity")
    if (trns[3] != b"Bob"):
        raise ValueError("Unexpected Bob identity")
    if (len(trns[4]) != 384):
        raise ValueError("Unexpected Alice public value")
    if (len(trns[5]) != 384):
        raise ValueError("Unexpected Bob public value")
    if (len(trns[6]) != 16):
        raise ValueError("Unexpected Alice nonce")
    if (len(trns[7]) != 16):
        raise ValueError("Unexpected Bob nonce")

def trns_len_check(e_t):
    fields = []
    off = 0

    for i in range(8):
        if off + 4 > len(e_t):
            raise ValueError("Malformed transcript")

        curr_len = int.from_bytes(e_t[off:off+4], "big")
        off += 4

        if off + curr_len > len(e_t):
            raise ValueError("Incorrect field length")

        fields.append(e_t[off:off + curr_len])
        off += curr_len

    if off != len(e_t):
        raise ValueError("Malformed transcript")

    return fields

with open("ffdhe3072.pem", "rb") as f:
    parameters = serialization.load_pem_parameters(f.read())

def perform_hand_custom_trans(bad_sign_a, bad_sign_b):
    private_a = parameters.generate_private_key()
    public_a = private_a.public_key()

    private_b = parameters.generate_private_key()
    public_b = private_b.public_key()

    shared_a = private_a.exchange(public_b)
    shared_b = private_b.exchange(public_a)

    assert shared_a == shared_b, "Shared keys not the same"

    nonce_a = os.urandom(16)
    nonce_b = os.urandom(16)

    transcript = [b"CSCE465-HS-v2", b"ffdhe3072", b"Alice", b"Bob", public_a.public_numbers().y.to_bytes(384, "big"), public_b.public_numbers().y.to_bytes(384, "big"), nonce_a, nonce_b] 

    encoded_transcript = b"".join(len(t).to_bytes(4, "big") + t for t in transcript)

    signing_key_a = rsa.generate_private_key(public_exponent=65537,key_size=3072)
    signing_key_b = rsa.generate_private_key(public_exponent=65537,key_size=3072)

    verify_key_a = signing_key_a.public_key()
    verify_key_b = signing_key_b.public_key()

    try:
        check_transcript(trns_len_check(encoded_transcript))
        ht = hashes.Hash(hashes.SHA256())
        ht.update(encoded_transcript)
        hashed_trns = ht.finalize()
        sign_a = signing_key_a.sign(b"node" + hashed_trns, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

        sign_b = signing_key_b.sign(b"gateway" + hashed_trns, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        
        verify_key_a.verify(bad_sign_a, b"node" + hashed_trns, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

        verify_key_b.verify(bad_sign_b, b"gateway" + hashed_trns, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

        Z = shared_a
        h = hashes.Hash(hashes.SHA256())
        h.update(b"CSCE465-KDF-v1" + Z + hashed_trns)
        K_master = h.finalize()

        h2 = hmac.HMAC(K_master, hashes.SHA256())
        h2.update(b"gateway-to-node encryption" + hashed_trns)
        K_g2n_enc = h2.finalize()

        h3 = hmac.HMAC(K_master, hashes.SHA256())
        h3.update(b"gateway-to-node MAC" + hashed_trns)
        K_g2n_mac = h3.finalize()

        h4 = hmac.HMAC(K_master, hashes.SHA256())
        h4.update(b"node-to-gateway encryption"+ hashed_trns)
        K_n2g_enc = h4.finalize()

        h5 = hmac.HMAC(K_master, hashes.SHA256())
        h5.update(b"node-to-gateway MAC" + hashed_trns)
        K_n2g_mac = h5.finalize()

        h6 = hmac.HMAC(K_master, hashes.SHA256())
        h6.update(b"session identifier" + hashed_trns)
        session_id = (h6.finalize())[0:8]

        return (K_g2n_enc, K_g2n_mac, K_n2g_enc, K_n2g_mac, session_id) 
    except ValueError as err:
        print(f"Caught error: {err}")
    except InvalidSignature:
        print("Signature error")
def perform_handshake():
    private_a = parameters.generate_private_key()
    public_a = private_a.public_key()

    private_b = parameters.generate_private_key()
    public_b = private_b.public_key()

    shared_a = private_a.exchange(public_b)
    shared_b = private_b.exchange(public_a)

    assert shared_a == shared_b, "Shared keys not the same"

    nonce_a = os.urandom(16)
    nonce_b = os.urandom(16)

    transcript = [b"CSCE465-HS-v2", b"ffdhe3072", b"Alice", b"Bob", public_a.public_numbers().y.to_bytes(384, "big"), public_b.public_numbers().y.to_bytes(384, "big"), nonce_a, nonce_b]

    encoded_transcript = b"".join(len(t).to_bytes(4, "big") + t for t in transcript)

    signing_key_a = rsa.generate_private_key(public_exponent=65537,key_size=3072)
    signing_key_b = rsa.generate_private_key(public_exponent=65537,key_size=3072)

    verify_key_a = signing_key_a.public_key()
    verify_key_b = signing_key_b.public_key()

    try: 
        check_transcript(trns_len_check(encoded_transcript))
        ht = hashes.Hash(hashes.SHA256())
        ht.update(encoded_transcript)
        hashed_trns = ht.finalize()

        sign_a = signing_key_a.sign(b"node" + hashed_trns, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        
        sign_b = signing_key_b.sign(b"gateway" + hashed_trns, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

        verify_key_a.verify(sign_a, b"node" + hashed_trns, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

        verify_key_b.verify(sign_b, b"gateway" + hashed_trns, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

        Z = shared_a
        h = hashes.Hash(hashes.SHA256())
        h.update(b"CSCE465-KDF-v1" + Z + hashed_trns)
        K_master = h.finalize()

        h2 = hmac.HMAC(K_master, hashes.SHA256())
        h2.update(b"gateway-to-node encryption" + hashed_trns)
        K_g2n_enc = h2.finalize()

        h3 = hmac.HMAC(K_master, hashes.SHA256())
        h3.update(b"gateway-to-node MAC" + hashed_trns)
        K_g2n_mac = h3.finalize()

        h4 = hmac.HMAC(K_master, hashes.SHA256())
        h4.update(b"node-to-gateway encryption"+ hashed_trns)
        K_n2g_enc = h4.finalize()

        h5 = hmac.HMAC(K_master, hashes.SHA256())
        h5.update(b"node-to-gateway MAC" + hashed_trns)
        K_n2g_mac = h5.finalize()

        h6 = hmac.HMAC(K_master, hashes.SHA256())
        h6.update(b"session identifier" + hashed_trns)
        session_id = (h6.finalize())[0:8]
    
        return (K_g2n_enc, K_g2n_mac, K_n2g_enc, K_n2g_mac, session_id)
    except ValueError as err:
        print(f"Caught error: {err}")
    except InvalidSignature:
        print("Signature error")

if __name__=="__main__":
    perform_handshake()
