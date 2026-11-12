"""Faux équipement SNMP pour tester ciel-scan (implémentation BER indépendante du code Rust).

Usage : python3 -I faux_equipement.py  (écoute en UDP sur 127.0.0.1:161, répond à un GET
avec sysName et sysDescr, après avoir vérifié que la requête est bien formée).
"""
import socket
import sys


def tlv(tag, content):
    n = len(content)
    if n < 128:
        head = bytes([tag, n])
    elif n < 256:
        head = bytes([tag, 0x81, n])
    else:
        head = bytes([tag, 0x82, n >> 8, n & 0xFF])
    return head + content


def parse(buf):
    """Retourne (tag, contenu, reste)."""
    tag = buf[0]
    if buf[1] < 0x80:
        n, off = buf[1], 2
    else:
        k = buf[1] & 0x7F
        n, off = int.from_bytes(buf[2:2 + k], "big"), 2 + k
    return tag, buf[off:off + n], buf[off + n:]


OID_DESCR = bytes([0x2B, 6, 1, 2, 1, 1, 1, 0])
OID_NOM = bytes([0x2B, 6, 1, 2, 1, 1, 5, 0])

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 161))
print("prêt", flush=True)
data, addr = s.recvfrom(2000)

# Vérification de la requête reçue
_, msg, _ = parse(data)
_, version, rest = parse(msg)
_, comm, rest = parse(rest)
tag, pdu, _ = parse(rest)
assert version == b"\x01", version  # SNMP v2c
assert tag == 0xA0, hex(tag)  # GetRequest
_, reqid, rest = parse(pdu)
_, _, rest = parse(rest)
_, _, rest = parse(rest)
_, vbl, _ = parse(rest)
oids = []
while vbl:
    _, vb, vbl = parse(vbl)
    _, oid, vb = parse(vb)
    t, val, _ = parse(vb)
    assert t == 0x05, "valeur NULL attendue"
    oids.append(oid)
assert oids == [OID_DESCR, OID_NOM], oids
print("requête valide, communauté =", comm.decode(), flush=True)

valeurs = {OID_DESCR: b"Switch de test CIEL v1.0", OID_NOM: b"sw-lab"}
vbs = b"".join(tlv(0x30, tlv(0x06, o) + tlv(0x04, valeurs[o])) for o in oids)
reponse_pdu = tlv(0x02, reqid) + tlv(0x02, b"\x00") + tlv(0x02, b"\x00") + tlv(0x30, vbs)
paquet = tlv(0x30, tlv(0x02, version) + tlv(0x04, comm) + tlv(0xA2, reponse_pdu))
s.sendto(paquet, addr)
print("réponse envoyée", flush=True)
sys.exit(0)
