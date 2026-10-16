"""JA4X from the switch's certificate digests, written as FoxIO's ja4x crate does (lib.rs): for the issuer, the
subject and the extensions, the OIDs' DER content in hex, joined by ',', SHA-256, first 12 hex digits."""
import hashlib
import ipaddress
from dataclasses import dataclass

# field order of x509_digest_t in p4/x509.p4
FIELDS = ("ipVersion", "src", "dst", "srcPort", "dstPort", "index", "issuer", "issuerLen", "subject", "subjectLen",
          "exts", "extsLen", "overflow", "connId")


@dataclass
class X509Digest:
    ipVersion: int
    src: int
    dst: int
    srcPort: int
    dstPort: int
    index: int
    issuer: int
    issuerLen: int
    subject: int
    subjectLen: int
    exts: int
    extsLen: int
    overflow: int
    connId: int

    @classmethod
    def from_fields(cls, values):
        return cls(**dict(zip(FIELDS, values)))

    def address(self, value):
        return str(ipaddress.IPv4Address(value) if self.ipVersion == 4 else ipaddress.IPv6Address(value))

    @property
    def endpoints(self):
        return self.address(self.src), self.srcPort, self.address(self.dst), self.dstPort


def oids(packed, length):
    """The OIDs of a list the switch filled as <length><content bytes>, in order."""
    data = packed.to_bytes(length, "big") if length else b""
    out, pos = [], 0
    while pos < len(data):
        n = data[pos]
        out.append(data[pos + 1:pos + 1 + n])
        pos += 1 + n
    return out


def hash12(text):
    return hashlib.sha256(text.encode()).hexdigest()[:12] if text else "000000000000"


def ja4x(d: X509Digest):
    parts = [oids(d.issuer, d.issuerLen), oids(d.subject, d.subjectLen), oids(d.exts, d.extsLen)]
    return "_".join(hash12(",".join(o.hex() for o in part)) for part in parts)
