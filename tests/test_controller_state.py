"""The controller's buffers for split messages stay bounded (controller/reassembly.py).

Without limits a long run keeps every copied piece forever: pieces of messages already joined, pieces of
connections that ended, pieces that never become a message (a gap in a connection with nothing to read). Here a
clock is passed in, so time can be moved without waiting.

    python3 -m unittest tests.test_controller_state -v
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from controller.reassembly import HTTP, Reassembler  # noqa: E402

REQUEST = b"GET / HTTP/1.1\r\nHost: a\r\nX-Pad: " + b"p" * 200 + b"\r\n\r\n"


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def send_split(r, key, base_offset, seq0=5000):
    """REQUEST in two pieces, second first; returns what the reassembler completed."""
    cut = 100
    out = r.add(key, seq0 + base_offset + cut, base_offset + cut, 0, 0, REQUEST[cut:])
    out += r.add(key, seq0 + base_offset, base_offset, 1, HTTP, REQUEST[:cut])
    return out


class TestControllerState(unittest.TestCase):
    def test_many_split_requests_stay_bounded(self):
        """A long keep-alive connection with 300 split requests (about 70 KB): every request still joins, and at
        most 32 KB are kept."""
        r = Reassembler(clock=Clock())
        key = (("a", 1), 7, 1)
        for i in range(300):
            done = send_split(r, key, i * len(REQUEST))
            self.assertEqual([m for _, _, m in done], [REQUEST])
        self.assertLessEqual(sum(len(p) for p in r.directions[key].pieces.values()), 2 * 16384)

    def test_false_start_inside_a_message(self):
        """A one-byte segment in the middle of a request that begins like one ("G") is joined as a "message" first;
        the real request, whose first segment arrives last, must still be joined from the same bytes."""
        r = Reassembler(clock=Clock())
        key = (("a", 1), 7, 1)
        fake = REQUEST.index(b"\r\n") - 2      # inside the request line
        request = REQUEST[:fake] + b"G" + REQUEST[fake + 1:]
        out = r.add(key, 5000 + fake + 1, fake + 1, 0, 0, request[fake + 1:])
        out += r.add(key, 5000 + fake, fake, 1, HTTP, request[fake:fake + 1])
        out += r.add(key, 5000, 0, 1, HTTP, request[:fake])
        self.assertIn(request, [m for _, _, m in out])

    def test_idle_directions_are_dropped(self):
        clock = Clock()
        r = Reassembler(idle=30.0, clock=clock)
        r.add((("a", 1), 1, 1), 5100, 100, 0, 0, b"x" * 50)        # a piece that never becomes a message
        clock.now += 31.0
        r.add((("b", 2), 2, 1), 9000, 0, 0, 0, b"y")                # any later copy sweeps
        self.assertNotIn((("a", 1), 1, 1), r.directions)
        self.assertIn((("b", 2), 2, 1), r.directions)

    def test_number_of_directions_is_bounded(self):
        clock = Clock()
        r = Reassembler(limit=100, clock=clock)
        for i in range(1000):
            clock.now += 0.001
            r.add((("a", i), i, 1), 5100, 100, 0, 0, b"x")
        self.assertLessEqual(len(r.directions), 100)
        self.assertIn((("a", 999), 999, 1), r.directions)            # the newest are kept

    def test_bytes_per_direction_are_bounded(self):
        """Pieces far beyond any message start are not kept (the switch copies at most 16 KB from a start)."""
        r = Reassembler(clock=Clock())
        key = (("a", 1), 1, 1)
        for i in range(100):
            r.add(key, 5000 + 1000 * i, 1000 * i, 0, 0, b"z" * 1000)
        self.assertLessEqual(sum(len(p) for p in r.directions[key].pieces.values()), 2 * 16384)


if __name__ == "__main__":
    unittest.main()
