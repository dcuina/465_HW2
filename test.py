import os
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils, dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from handshake import perform_handshake, perform_hand_custom_trans
from secure_record import seal, open_record, set_vals

def new_session(): 
    (K_g2n_enc, K_g2n_mac, K_n2g_enc, K_n2g_mac, session_id) = perform_handshake()
    set_vals((K_g2n_enc, K_g2n_mac), (K_n2g_enc, K_n2g_mac), session_id)
    return (K_g2n_enc, K_g2n_mac), (K_n2g_enc, K_n2g_mac), session_id

# Looking for correct handshake and bidirectional messaging
def check_handshake():
    output = perform_handshake()
    assert output is not None

def check_record():
    k_g2n, k_n2g, session_id = new_session()
    n2g_rec = seal(k_n2g, session_id, 0, 0, 1, b"Message for gateway")

    n2g_plain = open_record(n2g_rec, k_n2g, session_id, 0, 0)

    g2n_rec = seal(k_g2n, session_id, 1, 0, 1, b"Message for node")

    g2n_plain = open_record(g2n_rec, k_g2n, session_id, 1, 0)

    assert n2g_plain == b"Message for gateway" and g2n_plain == b"Message for node"

# Modifying ciphertext
def mod_cipher():
    k_g2n, k_n2g, session_id = new_session()
    n2g_rec = bytearray(seal(k_n2g, session_id, 0, 0, 1, b"Message for gateway"))

    n2g_rec[20] ^= 0x01

    try:
        open_record(bytes(n2g_rec), k_n2g, session_id, 0, 0)
        assert False
    except Exception:
        print('Detected ciphertext modification')

# Modifying header
def mod_header():
    k_g2n, k_n2g, session_id = new_session()
    n2g_rec = bytearray(seal(k_n2g, session_id, 0, 0, 1, b"Message for gateway"))

    n2g_rec[10] ^= 0x01

    try:
        open_record(bytes(n2g_rec), k_n2g, session_id, 0, 0)
        assert False
    except Exception:
        print('Detected header modification')

# Replaying same open record
def test_replay():
    k_g2n, k_n2g, session_id = new_session()
    n2g_rec = seal(k_n2g, session_id, 0, 0, 1, b"Message for gateway")

    expected_seq = 0
    n2g_plain = open_record(n2g_rec, k_n2g, session_id, 0, expected_seq)
    expected_seq += 1

    assert n2g_plain == b"Message for gateway"

    try:
        open_record(n2g_rec, k_n2g, session_id, 0, expected_seq)
        assert False
    except Exception:
        print("Detected replay attempt")

# Modifying the direction
def mod_direction():
    k_g2n, k_n2g, session_id = new_session()
    try:
        n2g_rec = seal(k_n2g, session_id, 1, 0, 1, b"Message for gateway")
        assert False
    except Exception as err:
        print("Attempt to modify direction:", err)

# Try incorrect transcript
def mod_transcript():
    trns = [b"CSCE465-HS-v2", b"ffdhe3072", b"Bob", b"Alice", b'100', b'200', b'1', b'1']

    try:
        perform_hand_custom_trans(trns)
        assert False
    except Exception as err:
        print("Incorrect transcript")
if __name__ == "__main__":
    check_handshake()
    check_record()
    mod_cipher()
    mod_header()
    test_replay()
    mod_direction()
    mod_transcript()
