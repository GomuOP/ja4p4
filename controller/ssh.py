"""JA4SSH from the switch's SSH digests.

The switch counts, per connection and window of 200 SSH packets, the SSH packets and bare ACKs in each direction,
and sends the payload lengths in batches (p4/ssh.p4). This module keeps each window's lengths, computes the two
modes (the most frequent length, the smallest on a tie, as FoxIO's ssh.rs does) and writes the text. The last,
partial window of a connection is read from the switch's registers when the controller finishes.
"""
import ipaddress
from collections import Counter
from dataclasses import dataclass

SSH_BATCH_FULL, SSH_WINDOW_END, SSH_FINAL, SSH_START = 2, 3, 4, 5

# field order of ssh_digest_t in p4/ssh.p4
FIELDS = ("kind", "ipVersion", "src", "dst", "srcPort", "dstPort", "batch", "batchCount",
          "sshClient", "sshServer", "ackClient", "ackServer", "serial", "connId", "fromClient")


@dataclass
class SshDigest:
    kind: int
    ipVersion: int
    src: int
    dst: int
    srcPort: int
    dstPort: int
    batch: int
    batchCount: int
    sshClient: int
    sshServer: int
    ackClient: int
    ackServer: int
    serial: int
    connId: int
    fromClient: int

    @classmethod
    def from_fields(cls, values):
        return cls(**dict(zip(FIELDS, values)))

    def address(self, value):
        return str(ipaddress.IPv4Address(value) if self.ipVersion == 4 else ipaddress.IPv6Address(value))

    @property
    def endpoints(self):
        return self.address(self.src), self.srcPort, self.address(self.dst), self.dstPort


def unpack_batch(batch, count):
    """[(from_client, length)] of a batch, oldest first."""
    out = []
    for i in range(count):
        entry = (batch >> (16 * (count - 1 - i))) & 0xFFFF
        out.append((bool(entry & 0x8000), entry & 0x7FFF))
    return out


def mode(lengths: Counter):
    if not lengths:
        return 0
    top = max(lengths.values())
    return min(k for k, v in lengths.items() if v == top)


class SshWindows:
    """The lengths of each SSH connection's current window."""

    def __init__(self):
        self.lengths = {}       # connection key -> (client Counter, server Counter)
        self.connections = {}   # (endpoints, connection number) -> (ip version, client, client port, server,
                                # server port); None once its last window was reported
        self.latest = {}        # endpoints -> the number of the newest connection on them

    def add_batch(self, key, batch, count):
        client, server = self.lengths.setdefault(key, (Counter(), Counter()))
        for from_client, length in unpack_batch(batch, count):
            (client if from_client else server)[length] += 1

    def close(self, key, ssh_c, ssh_s, ack_c, ack_s):
        """The window's JA4SSH (None if it holds no SSH packet), and a fresh window."""
        client, server = self.lengths.pop(key, (Counter(), Counter()))
        if not client and not server:
            return None
        return f"c{mode(client)}s{mode(server)}_c{ssh_c}s{ssh_s}_c{ack_c}s{ack_s}"
