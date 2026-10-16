"""BMv2 ports without root: simple_switch --packet-in ipc://<path> treats one nanomsg PAIR socket as all its ports.

Each message is a 12-byte header (three native-endian ints: type, port, length) followed by the frame:
    type 3 (PACKET_IN)   a frame we send into the switch on `port`
    type 4 (PACKET_OUT)  a frame the switch sends out of `port`
"""
import ctypes
import ctypes.util
import struct

AF_SP, NN_PAIR, NN_SOL_SOCKET, NN_SNDTIMEO, NN_RCVTIMEO = 1, 16, 0, 4, 5
NN_MSG = ctypes.c_size_t(-1).value
MSG_PACKET_IN, MSG_PACKET_OUT = 3, 4
HDR = struct.Struct("=iii")


def _lib():
    name = ctypes.util.find_library("nanomsg")
    if not name:
        raise SystemExit("libnanomsg not found (it is installed with BMv2)")
    nn = ctypes.CDLL(name, use_errno=True)
    nn.nn_recv.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    nn.nn_send.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
    nn.nn_freemsg.argtypes = [ctypes.c_void_p]
    return nn


class NanoPort:
    def __init__(self, addr, timeout_ms=100):
        self.nn = nn = _lib()
        self.sock = nn.nn_socket(AF_SP, NN_PAIR)
        for opt, ms in ((NN_RCVTIMEO, timeout_ms), (NN_SNDTIMEO, 2000)):
            v = ctypes.c_int(ms)
            nn.nn_setsockopt(self.sock, NN_SOL_SOCKET, opt, ctypes.byref(v), ctypes.sizeof(v))
        if nn.nn_connect(self.sock, addr.encode()) < 0:
            raise OSError(ctypes.get_errno(), f"cannot connect to {addr}")

    def send(self, port, frame):
        msg = HDR.pack(MSG_PACKET_IN, port, len(frame)) + bytes(frame)
        if self.nn.nn_send(self.sock, msg, len(msg), 0) < 0:
            raise OSError(ctypes.get_errno(), "nn_send failed (is the switch running with --packet-in?)")

    def recv(self):
        """(port, frame) of the next frame the switch sent out, or None after the timeout."""
        buf = ctypes.c_void_p()
        n = self.nn.nn_recv(self.sock, ctypes.byref(buf), NN_MSG, 0)
        if n < 0:
            return None
        try:
            raw = ctypes.string_at(buf, n)
        finally:
            self.nn.nn_freemsg(buf)
        kind, port, _ = HDR.unpack_from(raw)
        return (port, raw[HDR.size:]) if kind == MSG_PACKET_OUT else None

    def close(self):
        self.nn.nn_close(self.sock)
