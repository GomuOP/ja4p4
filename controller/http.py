"""JA4H from the switch's HTTP digests.

The switch has read the request: method and version bytes, Cookie / Referer present, the number of other headers,
Accept-Language's first characters, the header names in order and the first Cookie header's pairs. This module
does what P4 cannot: sort the cookie pairs, compute SHA-256 and write FoxIO's text (FoxIO's Rust code, http.rs).
"""
import hashlib
import ipaddress
from dataclasses import dataclass

# field order of http_digest_t in p4/http.p4
FIELDS = ("reassembled", "ipVersion", "src", "dst", "srcPort", "dstPort", "method", "methodLen", "version",
          "hasCookie", "hasReferer", "headerCount", "lang", "langLen", "names1", "names0", "namesLen",
          "cookies3", "cookies2", "cookies1", "cookies0", "cookiesLen", "overflow", "serial", "connId", "seq")

METHODS = {b"CONNECT": "co", b"DELETE": "de", b"GET": "ge", b"HEAD": "he", b"OPTIONS": "op", b"PATCH": "pa",
           b"POST": "po", b"PUT": "pu", b"TRACE": "tr"}
VERSIONS = {b"HTTP/1.0": "10", b"HTTP/1.1": "11"}
OVERFLOW_NAMES = {1: "header names", 2: "cookies"}


def hash12(data: bytes):
    return hashlib.sha256(data).hexdigest()[:12] if data else "000000000000"


def as_bytes(value, length):
    return value.to_bytes(length, "big") if length else b""


@dataclass
class HttpDigest:
    reassembled: int
    ipVersion: int
    src: int
    dst: int
    srcPort: int
    dstPort: int
    method: int
    methodLen: int
    version: int
    hasCookie: int
    hasReferer: int
    headerCount: int
    lang: int
    langLen: int
    names1: int
    names0: int
    namesLen: int
    cookies3: int
    cookies2: int
    cookies1: int
    cookies0: int
    cookiesLen: int
    overflow: int
    serial: int
    connId: int
    seq: int

    @classmethod
    def from_fields(cls, values):
        return cls(**dict(zip(FIELDS, values)))

    def address(self, value):
        return str(ipaddress.IPv4Address(value) if self.ipVersion == 4 else ipaddress.IPv6Address(value))

    @property
    def endpoints(self):
        return self.address(self.src), self.srcPort, self.address(self.dst), self.dstPort

    def incomplete_reason(self):
        parts = [name for bit, name in OVERFLOW_NAMES.items() if self.overflow & bit]
        return f"more {' and '.join(parts)} than the switch keeps" if parts else None


def ja4h(d: HttpDigest):
    """FoxIO's JA4H, or None when FoxIO would not compute one (an unknown method or version)."""
    method = METHODS.get(as_bytes(d.method, d.methodLen))
    version = VERSIONS.get(as_bytes(d.version, 8))
    if method is None or version is None:
        return None
    names_all = (d.names1 << 2048) | d.names0
    cookies_all = (d.cookies3 << 6144) | (d.cookies2 << 4096) | (d.cookies1 << 2048) | d.cookies0
    names = [n for n in as_bytes(names_all, d.namesLen).split(b"\0") if n]
    lang = as_bytes(d.lang, d.langLen).decode("latin-1").lower()
    lang = (lang + "0000")[:4]
    first = (f"{method}{version}{'c' if d.hasCookie else 'n'}{'r' if d.hasReferer else 'n'}"
             f"{min(d.headerCount, 99):02d}{lang}")
    pairs = [p for p in as_bytes(cookies_all, d.cookiesLen).split(b"\0") if p]
    split = [(p.split(b"=", 1)[0], p.split(b"=", 1)[1] if b"=" in p else None) for p in pairs]
    split.sort(key=lambda nv: (nv[0], nv[1] is not None, nv[1] or b""))   # as Rust orders (name, Option<value>)
    cookie_names = b",".join(name for name, _ in split)
    cookie_pairs = b",".join(name if value is None else name + b"=" + value for name, value in split)
    return f"{first}_{hash12(b','.join(names))}_{hash12(cookie_names)}_{hash12(cookie_pairs)}"
