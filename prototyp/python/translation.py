import hashlib
import os
import secrets
import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from python.fragmentation import fragment_data, parse_packet as frag_parse_packet
from python.header import build_packet, parse_packet as header_parse_packet, PacketType, Priority, HEADER_SIZE

_buffer: dict[int, dict] = {}

NONCE_SIZE = 12


def encrypt_fragment(raw_packet: bytes, key: bytes) -> bytes:
    header  = raw_packet[:HEADER_SIZE]
    payload = raw_packet[HEADER_SIZE:]
    
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = ChaCha20Poly1305(key).encrypt(nonce, payload, header)
    return header + nonce + ct


def decrypt_fragment(data: bytes, key: bytes) -> bytes | None:
    if len(data) < HEADER_SIZE + NONCE_SIZE:
        return None
    header = data[:HEADER_SIZE]
    nonce  = data[HEADER_SIZE : HEADER_SIZE + NONCE_SIZE]
    ct     = data[HEADER_SIZE + NONCE_SIZE:]
    try:
        payload = ChaCha20Poly1305(key).decrypt(nonce, ct, header)
        return header + payload
    except Exception:
        return None

def derive_path_order(session_key: bytes, n_paths: int, seq: int) -> int:
    h = hashlib.sha256(session_key + seq.to_bytes(4, "big")).digest()
    return int.from_bytes(h[:4], "big") % n_paths


def translate_outbound(data: bytes, src: str, dst: str,
                       key: bytes, src_addresses: list[str], conn_id: int) -> list[tuple[bytes, str]]:
    packets  = fragment_data(data, src, dst, conn_id=conn_id)
    n_paths  = len(src_addresses)
    outbound = []

    for pkt in packets:
        parsed   = frag_parse_packet(pkt)
        seq      = parsed["seq"]
        path_idx = derive_path_order(key, n_paths, seq)
        src_addr = src_addresses[path_idx]
        
        encrypted = encrypt_fragment(pkt, key)
        outbound.append((encrypted, src_addr))

    return outbound

def receive(data: bytes, addr: tuple, key: bytes, conn_id: int) -> bytes | None:
    decrypted = decrypt_fragment(data, key)
    if not decrypted:
        print(f"[!] Entschlüsselung fehlgeschlagen von {addr[0]}")
        return None

    parsed = frag_parse_packet(decrypted)
    if not parsed or not parsed["auth_ok"]:
        print(f"[!] Auth fehlgeschlagen — verworfen")
        return None

    seq     = parsed["seq"]
    is_last = bool(parsed["flags"] & 0x08)

    if conn_id not in _buffer:
        _buffer[conn_id] = {}
    _buffer[conn_id][seq] = parsed["payload"]

    print(f"[<] seq={seq} conn={conn_id} von {addr[0]} {'(LAST)' if is_last else ''}")

    if is_last:
        frags = _buffer.pop(conn_id)
        return b"".join(frags[i] for i in sorted(frags))
    return None

def peek_conn_id(data: bytes) -> int | None:
    from header import MAGIC
    if len(data) >= HEADER_SIZE:
        try:
            magic, conn_id = struct.unpack("!I36xQ", data[:48])
            if magic == MAGIC:
                return conn_id
        except Exception:
            pass
    return None

