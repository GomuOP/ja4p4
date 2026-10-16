"""JA4 and JA4S from the switch's TLS digests.

The switch has read every value (versions, cipher suites, extension types, signature algorithms, SNI, ALPN) and
left GREASE out. This module does what P4 cannot: sort the lists, compute SHA-256 and write FoxIO's text, following
FoxIO's Rust code (tls.rs).
"""
import hashlib
import ipaddress
from dataclasses import dataclass

CLIENT_HELLO, SERVER_HELLO = 1, 2
EXT_SNI, EXT_ALPN = 0x0000, 0x0010
OVERFLOW_NAMES = {1: "cipher suites", 2: "extensions", 4: "signature algorithms"}

# field order of tls_digest_t in p4/tls.p4
FIELDS = ("hsType", "reassembled", "ipVersion", "src", "dst", "srcPort", "dstPort", "legacyVersion", "hasSupportedVersions",
          "maxVersion", "sni", "cipher", "cipherCount", "ciphers", "extCount", "exts", "sigCount", "sigs",
          "alpnLen", "alpnFirst", "alpnLast", "overflow", "connId")

VERSIONS = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2"}


def unpack16(packed, count):
    """The switch shifted each 16-bit value in from the right: the first value is in the highest used bits."""
    return [(packed >> (16 * (count - 1 - i))) & 0xFFFF for i in range(count)]


def hash12(text):
    return hashlib.sha256(text.encode()).hexdigest()[:12] if text else "000000000000"


def utf8_length(lead):
    """Bytes in the UTF-8 character that starts with byte `lead`."""
    if lead < 0x80:
        return 1
    if 0xC0 <= lead < 0xE0:
        return 2
    if 0xE0 <= lead < 0xF0:
        return 3
    if 0xF0 <= lead < 0xF8:
        return 4
    return 1


def alpn_chars(length, first, last):
    """FoxIO's two ALPN characters: the first and last character of the first protocol name, '9' for a non-ASCII
    character, '0' for a missing one (no ALPN: "00"; a name of one character: that character and '0')."""
    if length == 0:
        return "00"
    c0 = chr(first) if first < 0x80 else "9"
    if length == utf8_length(first):            # the name is a single character
        return c0 + "0"
    c1 = chr(last) if last < 0x80 else "9"
    return c0 + c1


@dataclass
class TlsDigest:
    hsType: int
    reassembled: int
    ipVersion: int
    src: int
    dst: int
    srcPort: int
    dstPort: int
    legacyVersion: int
    hasSupportedVersions: int
    maxVersion: int
    sni: int
    cipher: int
    cipherCount: int
    ciphers: int
    extCount: int
    exts: int
    sigCount: int
    sigs: int
    alpnLen: int
    alpnFirst: int
    alpnLast: int
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

    def version(self):
        v = self.maxVersion if self.hasSupportedVersions else self.legacyVersion
        return VERSIONS.get(v, "00")

    def incomplete_reason(self):
        lists = [name for bit, name in OVERFLOW_NAMES.items() if self.overflow & bit]
        return f"more {' and '.join(lists)} than the switch keeps" if lists else None


def ja4(d: TlsDigest) -> str:
    ciphers = unpack16(d.ciphers, d.cipherCount)
    exts = unpack16(d.exts, d.extCount)
    sigs = unpack16(d.sigs, d.sigCount)
    first = (f"t{d.version()}{'d' if d.sni else 'i'}{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}"
             f"{alpn_chars(d.alpnLen, d.alpnFirst, d.alpnLast)}")
    cipher_text = ",".join(f"{c:04x}" for c in sorted(ciphers))
    ext_text = ",".join(f"{e:04x}" for e in sorted(e for e in exts if e not in (EXT_SNI, EXT_ALPN)))
    sig_text = ",".join(f"{s:04x}" for s in sigs)
    exts_sigs = f"{ext_text}_{sig_text}" if sig_text else ext_text
    return f"{first}_{hash12(cipher_text)}_{hash12(exts_sigs)}"


def ja4s(d: TlsDigest) -> str:
    exts = unpack16(d.exts, d.extCount)
    first = f"t{d.version()}{min(len(exts), 99):02d}{alpn_chars(d.alpnLen, d.alpnFirst, d.alpnLast)}"
    return f"{first}_{d.cipher:04x}_{hash12(','.join(f'{e:04x}' for e in exts))}"
