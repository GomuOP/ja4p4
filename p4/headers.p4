/* Packet headers and per-packet metadata. */
#ifndef HEADERS_P4
#define HEADERS_P4

#define TCP_OPT_MAX_BYTES 40      // a TCP header holds at most 40 bytes of options

typedef bit<9> port_t;

const port_t CPU_PORT = 255;              // simple_switch_grpc --cpu-port 255: packet-in / packet-out

/* Prepended to a frame the switch copies to the controller (P4Runtime packet-in). */
@controller_header("packet_in")
header packet_in_t {
    bit<32> offset;         // where this segment's payload starts in its direction's byte stream (0 = first byte)
    bit<8>  fromClient;     // 1: client -> server, 0: server -> client
    bit<8>  msgStart;       // 1: this segment starts a message that continues beyond it
    bit<8>  msgType;        // with msgStart: 1 TLS hello, 2 HTTP request
    bit<32> connId;         // the connection's number (ConnId in main.p4): tells a reused port's connections apart
}

/* Prepended by the controller to a frame it sends into the switch (P4Runtime packet-out). */
@controller_header("packet_out")
header packet_out_t {
    bit<8> kind;            // OUT_JOINED, OUT_FLUSH or OUT_CERT
    bit<8> index;           // OUT_CERT: the certificate's position in its chain (1 = the server's own)
}

const bit<8> OUT_JOINED = 1;    // a joined message, to be fingerprinted and dropped
const bit<8> OUT_FLUSH  = 2;    // report a connection's partial JA4SSH window (ssh.p4), then drop
const bit<8> OUT_CERT   = 3;    // one X.509 certificate (DER) from a TLS 1.2 Certificate message (x509.p4)

header ethernet_t {
    bit<48> dst;
    bit<48> src;
    bit<16> etherType;
}

/* An 802.1Q (0x8100) or 802.1ad (0x88a8) tag: priority, drop eligible, VLAN id; then the next EtherType. */
header vlan_t {
    bit<16> tci;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  tos;
    bit<16> totalLen;
    bit<16> id;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> checksum;
    bit<32> src;
    bit<32> dst;
}

/* IPv4 options, if any (ihl > 5); kept so the packet leaves unchanged. */
header ipv4_options_t {
    varbit<320> data;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   trafficClass;
    bit<20>  flowLabel;
    bit<16>  payloadLen;
    bit<8>   nextHeader;
    bit<8>   hopLimit;
    bit<128> src;
    bit<128> dst;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seq;
    bit<32> ack;
    bit<4>  dataOffset;
    bit<4>  reserved;
    bit<8>  flags;          // CWR ECE URG ACK PSH RST SYN FIN
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

/* One byte of the TCP options. The options are parsed one byte at a time into a stack of these, so that every byte
   is kept and re-emitted unchanged while the parser reads the option kinds, MSS and window scale on the way. */
header byte_t {
    bit<8> v;
}

struct headers_t {
    packet_in_t            packet_in;
    packet_out_t           packet_out;
    ethernet_t             ethernet;
    vlan_t                 vlanOuter;
    vlan_t                 vlanInner;
    ipv4_t                 ipv4;
    ipv4_options_t         ipv4_options;
    ipv6_t                 ipv6;
    tcp_t                  tcp;
    byte_t[TCP_OPT_MAX_BYTES] tcp_opt;
    udp_t                  udp;
}

/* What the parser learned from the TCP options (JA4T / JA4TS). */
struct tcp_opts_meta_t {
    bit<8>   left;          // option bytes not parsed yet
    bit<8>   kind;          // kind of the option being parsed
    bit<8>   len;           // its length byte
    bit<8>   count;         // number of option kinds seen
    bit<320> kinds;         // the kinds in order, one byte each, the first kind in the highest used byte
    bit<16>  mss;
    bit<1>   hasMss;
    bit<8>   wscale;
    bit<1>   hasWscale;
}

#define TLS_CIPHER_CAP 128   // cipher suites kept per ClientHello (each 16 bits)
#define TLS_EXT_CAP     64   // extension types kept per hello
#define TLS_SIG_CAP     64   // signature algorithms kept per ClientHello

/* What the parser learned from a TLS ClientHello or ServerHello (JA4 / JA4S). GREASE values are left out of every
   list and count, except the ServerHello's extensions, which FoxIO's reference keeps as they are. Each list holds
   its values in order, the first value in the highest used 16 bits. A list longer than its capacity keeps counting
   (the count stays right) and sets an overflow bit: the record is then reported as incomplete, never guessed. */
struct tls_meta_t {
    bit<8>    hsType;           // 1 ClientHello, 2 ServerHello (0: none)
    bit<1>    walked;           // the parser consumed hello bytes (the packet must be resubmitted to be forwarded)
    bit<1>    parsed;           // the whole hello was in this packet and was walked to its end
    bit<1>    incomplete;       // a hello starts in this packet but continues beyond it
    bit<32>   hsLeft;           // bytes of the hello not read yet (up to the extension block)
    bit<16>   recLen;           // TLS record length
    bit<24>   hsLen;            // handshake message length
    bit<16>   legacyVersion;
    bit<1>    hasSupportedVersions;
    bit<16>   maxVersion;       // highest supported_versions value (ServerHello: the selected one)
    bit<1>    sni;
    bit<16>   cipher;           // ServerHello: the chosen cipher suite
    bit<16>   cipherLeft;       // bytes of the cipher list not read yet
    bit<8>    cipherCount;
    bit<2048> ciphers;
    bit<16>   extLeft;          // bytes of the extension block not read yet
    bit<16>   extType;
    bit<16>   extLen;
    bit<8>    extCount;
    bit<1024> exts;
    bit<1>    sigSeen;
    bit<8>    sigCount;
    bit<1024> sigs;
    bit<16>   listLeft;         // countdown inside one extension body
    bit<1>    alpnSeen;
    bit<8>    alpnLen;          // length of the first ALPN protocol name
    bit<8>    alpnFirst;
    bit<8>    alpnLast;
    bit<8>    overflow;         // bit 0 ciphers, bit 1 extensions, bit 2 signature algorithms
    bit<16>   value;            // the 16-bit value being read
    bit<16>   sessionIdLen;
}

/* What the parser learned from an HTTP/1.x request header block (JA4H), see parser_http.p4. */
struct http_meta_t {
    bit<1>     walked;
    bit<1>     parsed;
    bit<1>     incomplete;
    bit<16>    left;            // payload bytes not read yet
    bit<8>     b;               // the byte just read
    bit<64>    method;
    bit<8>     methodLen;
    bit<64>    version;
    bit<1>     hasCookie;
    bit<1>     hasReferer;
    bit<1>     cookieSeen;
    bit<1>     langSeen;
    bit<8>     headerCount;
    bit<8>     hdrKind;         // 0 other, 3 Accept-Language
    bit<128>   cur;             // the last 16 bytes of the header name being read
    bit<16>    curLen;
    /* p4c allows at most 2,048 bits per field, so each list is a chain of fields shifted as one register:
       names = names1:names0 (512 bytes), cookies = cookies3:cookies2:cookies1:cookies0 (1,024 bytes) */
    bit<2048>  names0;
    bit<2048>  names1;
    bit<16>    namesLen;
    bit<2048>  cookies0;
    bit<2048>  cookies1;
    bit<2048>  cookies2;
    bit<2048>  cookies3;
    bit<16>    cookiesLen;
    bit<32>    lang;
    bit<8>     langLen;
    bit<8>     overflow;
}

/* What the parser learned from a DHCP or DHCPv6 message (JA4D / JA4D6), see parser_dhcp.p4. */
struct dhcp_meta_t {
    bit<1>    walked;
    bit<1>    parsed;
    bit<8>    version;          // 4 or 6
    bit<16>   left;             // bytes not read yet
    bit<16>   code;
    bit<16>   len;
    bit<16>   listLeft;
    bit<8>    msgType;
    bit<1>    hasType;
    bit<16>   maxSize;
    bit<1>    hasMaxSize;
    bit<1>    requestedIp;
    bit<1>    domain;
    bit<16>   duidLen;
    bit<1>    hasDuid;
    bit<8>    optCount;
    bit<1024> opts;             // option codes in order, 16 bits each
    bit<8>    reqCount;
    bit<2048> req;              // requested codes in order, 16 bits each
    bit<8>    overflow;         // bit 0 options, bit 1 requested codes
}

/* What the parser learned from an X.509 certificate (JA4X), see parser_x509.p4. Each list holds OIDs as
   <length byte><OID content bytes>, one after the other, in order. */
struct x509_meta_t {
    bit<1>    walked;
    bit<1>    parsed;
    bit<8>    ret;              // where the shared TLV reader returns to
    bit<8>    tag;
    bit<32>   len;
    bit<32>   hdrLen;           // tag + length bytes of the element just read
    bit<8>    lenBytes;         // long-form length: bytes still to read
    bit<32>   tbsLeft;          // bytes of tbsCertificate not read yet
    bit<32>   nameLeft;         // bytes of the issuer / subject Name not read yet
    bit<32>   setLeft;          // bytes of the current RDN (SET) not read yet
    bit<32>   itemLeft;         // bytes of the current attribute / extension not read yet
    bit<32>   extLeft;          // bytes of the Extensions SEQUENCE not read yet
    bit<32>   oidLeft;          // bytes of the current OID not copied yet
    bit<8>    list;             // 1 issuer, 2 subject, 3 extensions
    bit<8>    b;
    bit<2048> issuer;
    bit<16>   issuerLen;
    bit<2048> subject;
    bit<16>   subjectLen;
    bit<2048> exts;
    bit<16>   extsLen;
    bit<8>    overflow;         // a list longer than 256 bytes
}

/* The TCP handshake record (handshake.p4), sent to the controller as a digest by main.p4. */
struct hs_digest_t {
    bit<8>   kind;
    bit<8>   ipVersion;
    bit<128> src;           // of the packet that completed the record
    bit<128> dst;
    bit<16>  srcPort;
    bit<16>  dstPort;
    /* JA4T / JA4TS */
    bit<16>  window;
    bit<8>   optCount;
    bit<320> optKinds;
    bit<16>  mss;
    bit<8>   wscale;
    bit<8>   optFlags;      // bit 0: MSS present, bit 1: window scale present
    /* JA4L */
    bit<48>  latencyC;
    bit<48>  latencyS;
    bit<8>   ttlC;
    bit<8>   ttlS;
    bit<32>  connId;        // the connection's number (ConnId in main.p4)
}

#define CONN_SLOTS 65536            // per-connection register slots (ConnKey hashes into these)
#define COPY_SESSION 100            // clone session to the CPU port, set up by the controller

struct metadata_t {
    tcp_opts_meta_t opt;
    tls_meta_t tls;
    http_meta_t http;
    dhcp_meta_t dhcp;
    x509_meta_t x509;
    bit<16>  ipPayLen;      // bytes after the IP header (IPv4 total length - header, IPv6 payload length)
    bit<16>  payLen;        // TCP payload bytes
    bit<32>  slot;          // the connection's slot in the per-connection registers
    bit<32>  check;         // and its check value (tells two connections in one slot apart)
    /* the connection's number (ConnId in main.p4); kept across the resubmit and in the copy for the controller */
    @field_list(0, 1) bit<32> connId;
    bit<1>   connReused;    // this SYN starts a new connection on the endpoints of the connection prevConnId
    bit<32>  prevConnId;
    bit<1>   digestSent;    // a control other than Handshake sent a digest on this pass (one per packet on BMv2)
    bit<1>   sshBanner;     // the TCP payload begins with "SSH-" (ssh.p4: SSH on any port)
    bit<1>   srcIsFirst;    // the source endpoint is the smaller one (ConnKey's fixed order)
    bit<1>   reinjected;    // a packet sent by the controller (packet-out): never forwarded
    bit<8>   outKind;       // its packet_out.kind
    bit<8>   certIndex;     // its packet_out.index (OUT_CERT)
    bit<1>   fromClient;    // set by Stream: this packet goes client -> server
    /* the port the packet arrived on; kept across the resubmit (the second pass does not get it back) */
    @field_list(0) port_t inPort;
    /* a handshake record waiting to be sent (main.p4): on a packet whose message was walked, it goes out on the
       second pass, because the first pass already carries that message's digest (one digest per packet on BMv2) */
    @field_list(0) bit<1> hsPending;
    @field_list(0) hs_digest_t hsd;
    /* a copy for the controller (stream.p4). It is made at egress (an egress clone keeps the packet's bytes as
       they leave; an ingress clone is parsed again, which would walk the message again and drop its bytes). A packet
       whose message was walked is forwarded and copied on its second pass, so these travel with the resubmitted
       packet (field list 0) and with the copy (field list 1). */
    @field_list(0, 1) bit<1>  copy;
    @field_list(0, 1) bit<32> copyOffset;
    @field_list(0, 1) bit<8>  copyFromClient;
    @field_list(0, 1) bit<8>  copyMsgStart;
    @field_list(0, 1) bit<8>  copyMsgType;
    bit<8>   ipVersion;     // 4 or 6
    bit<128> srcAddr;       // IPv4 addresses are zero-extended
    bit<128> dstAddr;
    bit<8>   ttl;           // IPv4 TTL or IPv6 hop limit
    bit<1>   isTcp;
}

#endif
