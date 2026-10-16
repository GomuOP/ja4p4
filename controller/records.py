"""One record per connection, holding every fingerprint found for it.

A connection is its endpoints and its number from the switch (ConnId in p4/main.p4): a new connection that reuses an
earlier one's addresses and ports (port reuse) gets a record of its own. DHCP messages have no connection number;
they are kept per endpoints."""
import json
import threading


def connection_key(a_addr, a_port, b_addr, b_port):
    """The same key from either direction."""
    return tuple(sorted([(a_addr, a_port), (b_addr, b_port)]))


class Records:
    def __init__(self, echo=print):
        self.lock = threading.Lock()
        self.by_conn = {}
        self.order = []
        self.echo = echo
        self.messages = []      # per-message fingerprints (JA4D, JA4D6) in arrival order

    def get(self, a_addr, a_port, b_addr, b_port, conn_id=None):
        key = (connection_key(a_addr, a_port, b_addr, b_port), conn_id)
        rec = self.by_conn.get(key)
        if rec is None:
            rec = {} if conn_id is None else {"conn_id": conn_id}
            self.by_conn[key] = rec
            self.order.append(key)
        return rec

    def set_endpoints(self, rec, client, client_port, server, server_port):
        if "client" not in rec:
            rec.update(client=client, client_port=client_port, server=server, server_port=server_port)

    def add(self, rec, name, value):
        """Record a fingerprint; the first value of each name is kept."""
        if name not in rec:
            rec[name] = value
            who = f"{rec.get('client', '?')}:{rec.get('client_port', '?')} -> " \
                  f"{rec.get('server', '?')}:{rec.get('server_port', '?')}"
            self.echo(f"{name:<8} {value:<50} {who}")

    def append(self, rec, name, value):
        """Record one more value of a fingerprint that occurs several times per connection (JA4H: per request)."""
        rec.setdefault(name, []).append(value)
        who = f"{rec.get('client', '?')}:{rec.get('client_port', '?')} -> " \
              f"{rec.get('server', '?')}:{rec.get('server_port', '?')}"
        self.echo(f"{name:<8} {value:<50} {who}")

    def all(self):
        with self.lock:
            return [dict(self.by_conn[k]) for k in self.order]

    def write_json(self, path):
        with open(path, "w") as f:
            json.dump(self.all(), f, indent=1)
