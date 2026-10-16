"""A minimal P4Runtime client for one BMv2 switch (simple_switch_grpc).

It does only what this project needs: become the primary controller, load the compiled P4 program, write
table entries, enable a digest, and hand every digest message to a callback (acknowledging each list).
"""
import queue
import threading

import grpc
from google.protobuf import text_format
from p4.config.v1 import p4info_pb2
from p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc


class P4Info:
    """Name -> id lookups in the P4Info file p4c writes next to the program."""

    def __init__(self, path):
        self.info = p4info_pb2.P4Info()
        with open(path) as f:
            text_format.Merge(f.read(), self.info)

    def _find(self, items, name):
        for item in items:
            if item.preamble.name == name or item.preamble.name.endswith("." + name):
                return item
        raise KeyError(name)

    def table(self, name):
        return self._find(self.info.tables, name)

    def action(self, name):
        return self._find(self.info.actions, name)

    def digest(self, name):
        return self._find(self.info.digests, name)

    def register(self, name):
        return self._find(self.info.registers, name)

    def packet_metadata(self, name):
        """{field name: (id, bitwidth)} of the controller header `name` (packet_in / packet_out)."""
        for h in self.info.controller_packet_metadata:
            if h.preamble.name == name:
                return {m.name: (m.id, m.bitwidth) for m in h.metadata}
        raise KeyError(name)

    def digest_name(self, digest_id):
        for d in self.info.digests:
            if d.preamble.id == digest_id:
                return d.preamble.name
        return None


def _bytes(value, bitwidth):
    return value.to_bytes((bitwidth + 7) // 8, "big")


class SwitchConnection:
    def __init__(self, address, p4info_path, device_id=0, election_id=1, timeout=10):
        self.p4info = P4Info(p4info_path)
        self.device_id = device_id
        self.election_id = election_id
        self.channel = grpc.insecure_channel(address)
        self.stub = p4runtime_pb2_grpc.P4RuntimeStub(self.channel)
        self._requests = queue.Queue()
        self._stream = self.stub.StreamChannel(iter(self._requests.get, None))
        self._digest_handlers = {}
        self._packet_handler = None
        self._arbitrated = threading.Event()
        self._reader = threading.Thread(target=self._read_stream, daemon=True)
        self._reader.start()
        self._become_primary(timeout)

    # ---- stream channel ----

    def _become_primary(self, timeout):
        req = p4runtime_pb2.StreamMessageRequest()
        req.arbitration.device_id = self.device_id
        req.arbitration.election_id.low = self.election_id
        self._requests.put(req)
        if not self._arbitrated.wait(timeout=timeout):
            self.close()
            raise RuntimeError("no arbitration reply from the switch")

    def _read_stream(self):
        try:
            for msg in self._stream:
                kind = msg.WhichOneof("update")
                if kind == "arbitration":
                    self._arbitrated.set()
                elif kind == "digest":
                    self._on_digest(msg.digest)
                elif kind == "packet" and self._packet_handler:
                    fields = {m.metadata_id: int.from_bytes(m.value, "big") for m in msg.packet.metadata}
                    self._packet_handler(fields, msg.packet.payload)
        except grpc.RpcError:
            pass  # the channel was closed

    def _on_digest(self, digest_list):
        name = self.p4info.digest_name(digest_list.digest_id)
        handler = self._digest_handlers.get(name)
        for data in digest_list.data:
            if handler:
                handler([int.from_bytes(m.bitstring, "big") for m in data.struct.members])
        ack = p4runtime_pb2.StreamMessageRequest()
        ack.digest_ack.digest_id = digest_list.digest_id
        ack.digest_ack.list_id = digest_list.list_id
        self._requests.put(ack)

    # ---- pipeline and entries ----

    def load_program(self, bmv2_json_path):
        req = p4runtime_pb2.SetForwardingPipelineConfigRequest()
        req.device_id = self.device_id
        req.election_id.low = self.election_id
        req.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT
        req.config.p4info.CopyFrom(self.p4info.info)
        with open(bmv2_json_path, "rb") as f:
            req.config.p4_device_config = f.read()
        self.stub.SetForwardingPipelineConfig(req)

    def _write(self, update):
        req = p4runtime_pb2.WriteRequest()
        req.device_id = self.device_id
        req.election_id.low = self.election_id
        req.updates.append(update)
        self.stub.Write(req)

    def add_exact_entry(self, table, key_value, action, params):
        """One exact-match entry: key_value for the table's only key field, params = {name: int}."""
        t = self.p4info.table(table)
        a = self.p4info.action(action)
        update = p4runtime_pb2.Update(type=p4runtime_pb2.Update.INSERT)
        entry = update.entity.table_entry
        entry.table_id = t.preamble.id
        field = entry.match.add()
        field.field_id = t.match_fields[0].id
        field.exact.value = _bytes(key_value, t.match_fields[0].bitwidth)
        entry.action.action.action_id = a.preamble.id
        for p in a.params:
            param = entry.action.action.params.add()
            param.param_id = p.id
            param.value = _bytes(params[p.name], p.bitwidth)
        self._write(update)

    def enable_digest(self, name, handler):
        """Ask the switch to send digest `name` immediately, one message per digest, to handler(fields)."""
        d = self.p4info.digest(name)
        self._digest_handlers[d.preamble.name] = handler
        update = p4runtime_pb2.Update(type=p4runtime_pb2.Update.INSERT)
        entry = update.entity.digest_entry
        entry.digest_id = d.preamble.id
        entry.config.max_timeout_ns = 0
        entry.config.max_list_size = 1
        entry.config.ack_timeout_ns = 1_000_000_000
        self._write(update)

    def read_register(self, name, index):
        """The value of register `name` at `index`."""
        req = p4runtime_pb2.ReadRequest()
        req.device_id = self.device_id
        entry = req.entities.add().register_entry
        entry.register_id = self.p4info.register(name).preamble.id
        entry.index.index = index
        for resp in self.stub.Read(req):
            for e in resp.entities:
                return int.from_bytes(e.register_entry.data.bitstring, "big")
        return None

    def add_clone_session(self, session_id, port):
        """Copies made with this clone session go to `port` (for the CPU port: to this controller, as packet-in)."""
        update = p4runtime_pb2.Update(type=p4runtime_pb2.Update.INSERT)
        entry = update.entity.packet_replication_engine_entry.clone_session_entry
        entry.session_id = session_id
        replica = entry.replicas.add()
        replica.egress_port = port
        replica.instance = 1
        self._write(update)

    def on_packet_in(self, handler):
        """handler({metadata name: value}, frame) for every packet the switch sends to the controller."""
        ids = {mid: name for name, (mid, _) in self.p4info.packet_metadata("packet_in").items()}
        self._packet_handler = lambda fields, payload: handler(
            {ids[i]: v for i, v in fields.items()}, payload)

    def packet_out(self, frame, **metadata):
        """Send `frame` into the switch with the packet_out header fields given as keywords (others are 0)."""
        meta = self.p4info.packet_metadata("packet_out")
        req = p4runtime_pb2.StreamMessageRequest()
        req.packet.payload = bytes(frame)
        for name, (mid, width) in meta.items():
            value = metadata.get(name, 0)
            m = req.packet.metadata.add()
            m.metadata_id = mid
            m.value = _bytes(value, width)
        self._requests.put(req)

    def close(self):
        self._requests.put(None)
        self.channel.close()
