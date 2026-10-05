import os
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils, dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from handshake import perform_handshake
K_g2n_enc = None
K_g2n_mac = None
K_n2g_enc = None 
K_n2g_mac = None 
session_id = None

def set_vals(k_g2n, k_n2g, ssid):
    global K_g2n_enc, K_g2n_mac, K_n2g_enc, K_n2g_mac, session_id
    (K_g2n_enc, K_g2n_mac) = k_g2n 
    (K_n2g_enc, K_n2g_mac) = k_n2g
    session_id = ssid

def seal(keys, session_id, direction, seq_num, msg_type, plaintext):
    if (direction == 0):
        if (keys[0] != K_n2g_enc or keys[1] != K_n2g_mac):
            raise ValueError("Keys do not match direction")
    elif (direction == 1):
        if (keys[0] != K_g2n_enc or keys[1] != K_g2n_mac):
            raise ValueError("Keys do not match direction")
    else:
        raise ValueError("Invalid direction")
    seq_bytes = seq_num.to_bytes(8, "big")
    iv = session_id + seq_bytes
    encryptor = Cipher(algorithms.AES(keys[0]), modes.CTR(iv)).encryptor()
    cipher = encryptor.update(plaintext) + encryptor.finalize()
    header = bytes([1]) + bytes([direction]) + seq_bytes + bytes([msg_type]) + len(cipher).to_bytes(4, "big")
    mac_h = hmac.HMAC(keys[1], hashes.SHA256())
    mac_h.update(header + iv + cipher) 
    tag = mac_h.finalize()
    return header + cipher + tag

def open_record(record, keys, session_id, exp_dir, exp_seq):
    rec_offset = 0
    version = record[rec_offset]
    if (version != 1):
        raise ValueError("Incorrect version")
    rec_offset += 1
    if (record[rec_offset] != exp_dir):
        raise ValueError("Unexpected direction")
    rec_offset += 1
    seq_bytes = record[rec_offset:rec_offset+8]
    if (int.from_bytes(record[rec_offset:rec_offset+8], "big") != exp_seq):
        raise ValueError("Unexpected sequence")
    rec_offset += 8
    msg_type = record[rec_offset]
    if (msg_type != 1):
        raise ValueError("Unexpected message type")
    rec_offset += 1
    cipher_len = record[rec_offset:rec_offset+4]
    rec_offset += 4
    iv = session_id + seq_bytes
    if (len(iv) != 16):
        raise ValueError("Malformed IV")
    cipher = record[rec_offset:rec_offset + int.from_bytes(cipher_len, "big")]
    if (len(cipher) != int.from_bytes(cipher_len, "big")):
        raise ValueError("Malformed ciphertext")
    rec_offset += int.from_bytes(cipher_len, "big")
    tag = record[rec_offset:rec_offset+32]
    rec_offset += 32

    if (rec_offset != len(record)):
        print(rec_offset)
        print(len(record))
        raise ValueError("Malformed record")
    mac_h = hmac.HMAC(keys[1], hashes.SHA256())
    mac_h.update(bytes([version]) + bytes([exp_dir]) + seq_bytes + bytes([msg_type]) + cipher_len + iv + cipher)
    mac_h.verify(tag)

    decryptor = Cipher(algorithms.AES(keys[0]), modes.CTR(iv)).decryptor()
    plaintext = decryptor.update(cipher) + decryptor.finalize()

    return plaintext

msg_type = 1

node_dir = 0
node_send_num = 0
node_exp_num = 0

gt_dir = 1
gateway_send_num = 0
gateway_exp_num = 0

#n2g_rec = seal((K_n2g_enc, K_n2g_mac), session_id, node_dir, node_send_num, msg_type, b"Messaging gateway")
#node_send_num += 1

#g2n_rec = seal((K_g2n_enc, K_g2n_mac), session_id, gt_dir, gateway_send_num, msg_type, b"Messaging node")
#gateway_send_num += 1

#plain_from_node = open_record(n2g_rec, (K_n2g_enc, K_n2g_mac), session_id, node_dir, gateway_exp_num)
#gateway_exp_num += 1

#print(plain_from_node)

#plain_from_gt = open_record(g2n_rec, (K_g2n_enc, K_g2n_mac), session_id, gt_dir, node_exp_num)
#node_exp_num += 1

#print(plain_from_gt) 

if __name__ == "__main__":
    (K_g2n_enc, K_g2n_mac, K_n2g_enc, K_n2g_mac, session_id) = perform_handshake()
    n2g_rec = seal((K_n2g_enc, K_n2g_mac), session_id, node_dir, node_send_num, msg_type, b"Messaging gateway")
    node_send_num += 1

    g2n_rec = seal((K_g2n_enc, K_g2n_mac), session_id, gt_dir, gateway_send_num, msg_type, b"Messaging node")
    gateway_send_num += 1

    plain_from_node = open_record(n2g_rec, (K_n2g_enc, K_n2g_mac), session_id, node_dir, gateway_exp_num)
    gateway_exp_num += 1

    print(plain_from_node)

    plain_from_gt = open_record(g2n_rec, (K_g2n_enc, K_g2n_mac), session_id, gt_dir, node_exp_num)
    node_exp_num += 1

    print(plain_from_gt)
