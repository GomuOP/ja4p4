"""JA4T, JA4TS and JA4L records from the switch's handshake digests.

The switch has already extracted every value (window, option kinds, MSS, window scale) and, for JA4L, computed
both latencies. This module only writes them in FoxIO's text format.
"""
import ipaddress
from dataclasses import dataclass

FP_JA4T, FP_JA4TS, FP_JA4L = 1, 2, 3

# field order of hs_digest_t in p4/handshake.p4
FIELDS = ("kind", "ipVersion", "src", "dst", "srcPort", "dstPort", "window", "optCount", "optKinds", "mss",
          "wscale", "optFlags", "latencyC", "latencyS", "ttlC", "ttlS", "connId")


@dataclass
class HandshakeDigest:
    kind: int
    ipVersion: int
    src: int
    dst: int
    srcPort: int
    dstPort: int
    window: int
    optCount: int
    optKinds: int
    mss: int
    wscale: int
    optFlags: int
    latencyC: int
    latencyS: int
    ttlC: int
    ttlS: int
    connId: int

    @classmethod
    def from_fields(cls, values):
        return cls(**dict(zip(FIELDS, values)))

    def address(self, value):
        return str(ipaddress.IPv4Address(value) if self.ipVersion == 4 else ipaddress.IPv6Address(value))

    @property
    def endpoints(self):
        return self.address(self.src), self.srcPort, self.address(self.dst), self.dstPort

    def option_kinds(self):
        """The kinds in the order seen: the switch shifted each one in from the right."""
        return [(self.optKinds >> (8 * (self.optCount - 1 - i))) & 0xFF for i in range(self.optCount)]


def tcp_fingerprint(d: HandshakeDigest) -> str:
    """<window>_<option kinds joined by ->_<mss>_<window scale>, as FoxIO's tcp.rs writes it."""
    opts = "-".join(str(k) for k in d.option_kinds()) or "00"
    mss = d.mss if d.optFlags & 1 else 0
    wscale = d.wscale if d.optFlags & 2 else 0
    ws = f"{wscale:02d}" if wscale == 0 else f"{wscale}"
    return f"{d.window}_{opts}_{mss:02d}_{ws}"


def latency_fingerprints(d: HandshakeDigest):
    """(JA4L-C, JA4L-S): <half round trip in microseconds>_<TTL>."""
    return f"{d.latencyC}_{d.ttlC}", f"{d.latencyS}_{d.ttlS}"
