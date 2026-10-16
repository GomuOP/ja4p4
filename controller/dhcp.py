"""JA4D and JA4D6 from the switch's DHCP digests, written as FoxIO's Wireshark plugin does (packet-ja4.c)."""
import ipaddress
from dataclasses import dataclass

# field order of dhcp_digest_t in p4/dhcp.p4
FIELDS = ("version", "src", "dst", "srcPort", "dstPort", "msgType", "hasType", "maxSize", "hasMaxSize", "duidLen",
          "hasDuid", "requestedIp", "domain", "optCount", "opts", "reqCount", "req", "overflow", "serial")

DHCP4_TYPES = [None, "disco", "offer", "reqst", "decln", "dpack", "dpnak", "relse", "infor", "frenw", "lqery",
               "lunas", "lunkn", "lactv", "blklq", "lqdon", "actlq", "lqsta", "dhtls"]
DHCP6_TYPES = [None, "solct", "advrt", "reqst", "confm", "renew", "rebnd", "reply", "relse", "decln", "recon",
               "inreq", "rlayf", "rlayr", "query", "qrply", "qdone", "qdata", "rereq", "rrply", "v4qry", "v4res",
               "acqry", "sttls", "bdudp", "brply", "poreq", "pores", "urqst", "ureqa", "udone", "conne", "connr",
               "dconn", "state", "conta", "arinf", "arrep"]
OVERFLOW_NAMES = {1: "option codes", 2: "requested codes"}


@dataclass
class DhcpDigest:
    version: int
    src: int
    dst: int
    srcPort: int
    dstPort: int
    msgType: int
    hasType: int
    maxSize: int
    hasMaxSize: int
    duidLen: int
    hasDuid: int
    requestedIp: int
    domain: int
    optCount: int
    opts: int
    reqCount: int
    req: int
    overflow: int
    serial: int

    @classmethod
    def from_fields(cls, values):
        return cls(**dict(zip(FIELDS, values)))

    def address(self, value):
        return str(ipaddress.IPv4Address(value) if self.version == 4 else ipaddress.IPv6Address(value))

    @property
    def endpoints(self):
        return self.address(self.src), self.srcPort, self.address(self.dst), self.dstPort

    def incomplete_reason(self):
        parts = [name for bit, name in OVERFLOW_NAMES.items() if self.overflow & bit]
        return f"more {' and '.join(parts)} than the switch keeps" if parts else None


def unpack16(packed, count):
    return [(packed >> (16 * (count - 1 - i))) & 0xFFFF for i in range(count)]


def ja4d(d: DhcpDigest):
    names = DHCP4_TYPES if d.version == 4 else DHCP6_TYPES
    if not d.hasType:
        kind = "00000"
    elif d.msgType < len(names) and names[d.msgType]:
        kind = names[d.msgType]
    else:
        kind = f"{d.msgType:05d}"
    has, size = (d.hasMaxSize, d.maxSize) if d.version == 4 else (d.hasDuid, d.duidLen)
    size = "0000" if not has else f"{size:04d}" if size < 9999 else "9999"
    opts = "-".join(str(c) for c in unpack16(d.opts, d.optCount)) or "00"
    req = "-".join(str(c) for c in unpack16(d.req, d.reqCount)) or "00"
    return f"{kind}{size}{'i' if d.requestedIp else 'n'}{'d' if d.domain else 'n'}_{opts}_{req}"
