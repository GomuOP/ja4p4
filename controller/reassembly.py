"""Putting a split message (TLS hello, HTTP request header block) back together, for the switch to read.

The switch copies to the controller the segments that may hold a message which did not fit in one packet, each with
its offset in its direction's byte stream, and a flag and type (TLS / HTTP) on a segment where a message starts
(p4/stream.p4). Per connection and direction this module

1. keeps the bytes by offset: duplicates and retransmissions are harmless, and when two segments overlap with
   different bytes the bytes received first are kept;
2. for every message start, once the bytes from it onward are contiguous far enough, cuts out the message by its
   framing only:
     TLS:  the handshake message is taken out of its TLS records (a hello may span several records: their headers
           are removed and the fragments joined) and wrapped in a single record;
     HTTP: the bytes up to and including the empty line that ends the header block (CR LF or bare LF);
     SERVER_FLIGHT (TLS 1.2, from the ServerHello on): the handshake messages are taken out of their records until
           the Certificate message is complete; it is cut into its certificates (each one length-prefixed), which
           are returned as a list, to be sent back one by one;
3. returns each complete message once, with its offset, for the controller to send back into the switch;
4. stays bounded: at most 2 x 16 KB are kept per direction, the lowest offsets dropped first (the switch copies at
   most 16 KB from a message's start or a gap, so older bytes belong to messages already joined or never to be);
   a direction not added to for `idle` seconds is dropped (its connection ended, or its pieces never became a
   message); at most `limit` directions are kept (the least recently added to are dropped first).
   The bytes of a joined message are not dropped at once: a short segment that merely began like a message can be
   "joined" from the middle of a real one whose first segment comes later, and the real one still needs them.

It never reads a field of a message: that is the switch's job. A start flagged on a segment that turns out not to
be a message (a short segment that merely began like one) never completes and is ignored.
"""
import re
import time
from dataclasses import dataclass, field

TLS, HTTP, SERVER_FLIGHT = 1, 2, 3
HEADER_END = re.compile(rb"\r?\n\r?\n")
MAX_MESSAGE = 16384 + 9     # the switch copies at most 16 KB from a message's start
MAX_KEPT = 2 * 16384        # bytes kept per direction


@dataclass
class Direction:
    pieces: dict = field(default_factory=dict)   # offset -> bytes
    starts: dict = field(default_factory=dict)   # offset of a message start -> TLS / HTTP
    done: set = field(default_factory=set)       # message starts already returned
    base: int = None                             # sequence number of offset 0
    kept: int = 0                                # bytes in pieces
    last: float = 0.0                            # when a piece was last added


class Reassembler:
    def __init__(self, idle=60.0, limit=100_000, clock=time.monotonic):
        self.directions = {}
        self.idle = idle
        self.limit = limit
        self.clock = clock
        self.swept = clock()

    def add(self, key, seq, offset, msg_start, msg_type, payload):
        """Add one copied segment. key: (endpoints, connection number, direction). Returns [(sequence number of the
        message's first byte, type, message)] for every message this segment completed (for SERVER_FLIGHT the
        message is the list of certificates, possibly empty)."""
        now = self.clock()
        self.sweep(now)
        d = self.directions.setdefault(key, Direction())
        d.last = now
        d.base = (seq - offset) & 0xFFFFFFFF
        if payload:
            known = d.pieces.get(offset, b"")
            if len(payload) > len(known):
                d.pieces[offset] = known + bytes(payload[len(known):])   # the bytes received first are kept
                d.kept += len(payload) - len(known)
        if msg_start and offset not in d.starts:
            d.starts[offset] = msg_type
        out = []
        for start, kind in sorted(d.starts.items()):
            if start in d.done:
                continue
            message = complete_message(kind, contiguous(d.pieces, start))
            if message is not None:
                d.done.add(start)
                out.append(((d.base + start) & 0xFFFFFFFF, kind, message))
        self.bound(d)
        return out

    @staticmethod
    def bound(d):
        """At most MAX_KEPT bytes per direction: the lowest offsets go first (further from the newest copies)."""
        if d.kept <= MAX_KEPT:
            return
        for off in sorted(d.pieces):
            if d.kept <= MAX_KEPT:
                break
            d.kept -= len(d.pieces.pop(off))
        lowest = min(d.pieces, default=None)
        d.starts = {s: k for s, k in d.starts.items() if lowest is not None and s >= lowest}
        d.done = {s for s in d.done if s in d.starts}

    def sweep(self, now):
        """Drop directions not added to for `idle` seconds (once a second), and the oldest beyond `limit`."""
        if now - self.swept >= 1.0:
            self.swept = now
            for key in [k for k, d in self.directions.items() if now - d.last > self.idle]:
                del self.directions[key]
        if len(self.directions) >= self.limit:
            oldest = sorted(self.directions, key=lambda k: self.directions[k].last)
            for key in oldest[:len(self.directions) - self.limit + 1 + self.limit // 10]:
                del self.directions[key]


def contiguous(pieces, start):
    """The bytes from `start` up to the first gap; for overlapping bytes, the ones received first."""
    out = bytearray()
    end = start
    for off in sorted(pieces):
        data = pieces[off]
        if off + len(data) <= end:
            continue                # entirely before what we have
        if off > end:
            break                   # a gap: the bytes in between have not arrived yet
        out += data[end - off:]
        end = off + len(data)
        if len(out) >= MAX_MESSAGE:
            break
    return bytes(out)


def complete_message(kind, data):
    if kind == TLS:
        return hello_record(data)
    if kind == SERVER_FLIGHT:
        return certificates(data)
    if kind == HTTP:
        end = HEADER_END.search(data)          # an empty line: CR LF CR LF, or with bare LFs
        return data[:end.end()] if end else None
    return None


def hello_record(data):
    """If `data` (TLS records from the hello's first byte) holds a complete handshake message, return it as one TLS
    record; otherwise None."""
    msg = bytearray()
    pos = 0
    while pos + 5 <= len(data):
        if data[pos] != 0x16:
            return None             # not a handshake record: nothing to join
        rec_len = int.from_bytes(data[pos + 3:pos + 5], "big")
        msg += data[pos + 5:min(pos + 5 + rec_len, len(data))]
        if len(msg) >= 4:
            hs_len = int.from_bytes(msg[1:4], "big")
            if len(msg) >= 4 + hs_len:
                hello = bytes(msg[:4 + hs_len])
                return data[0:3] + len(hello).to_bytes(2, "big") + hello
        if pos + 5 + rec_len > len(data):
            return None             # this record continues beyond the bytes received so far
        pos += 5 + rec_len
    return None


def handshake_messages(data):
    """The handshake messages (type, body) found in the TLS records at the start of `data`, as far as they are
    complete; and whether the records stopped being handshake records (nothing more can follow)."""
    stream = bytearray()
    pos = 0
    ended = False
    while pos + 5 <= len(data):
        if data[pos] != 0x16:
            ended = True                # ChangeCipherSpec, alert, application data: the handshake part is over
            break
        rec_len = int.from_bytes(data[pos + 3:pos + 5], "big")
        stream += data[pos + 5:min(pos + 5 + rec_len, len(data))]
        if pos + 5 + rec_len > len(data):
            break
        pos += 5 + rec_len
    msgs = []
    i = 0
    while i + 4 <= len(stream):
        n = int.from_bytes(stream[i + 1:i + 4], "big")
        if i + 4 + n > len(stream):
            break
        msgs.append((stream[i], bytes(stream[i + 4:i + 4 + n])))
        i += 4 + n
    return msgs, ended


def certificates(data):
    """The DER certificates of the TLS 1.2 Certificate message (type 11) in the server flight `data`, once it is
    complete: [] if the flight has none (it reached ServerHelloDone or left the handshake records without one),
    None while it may still come."""
    msgs, ended = handshake_messages(data)
    for kind, body in msgs:
        if kind == 11:
            certs = []
            pos = 3                     # the list's 3-byte length
            while pos + 3 <= len(body):
                n = int.from_bytes(body[pos:pos + 3], "big")
                certs.append(body[pos + 3:pos + 3 + n])
                pos += 3 + n
            return certs
        if kind == 14:                  # ServerHelloDone before any Certificate
            return []
    return [] if ended else None
