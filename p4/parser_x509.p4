/* X.509 certificate walk (JA4X). Included inside MyParser (parser.p4).

   Entered for a packet from the controller of kind OUT_CERT: its TCP payload is one certificate, in DER, taken by
   the controller out of a TLS 1.2 Certificate message (stream.p4 copies the server's flight after the ServerHello;
   the controller only follows TLS framing to cut the certificates out).

       Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
       tbsCertificate ::= SEQUENCE {
           [0] version (optional), serialNumber, signature, issuer Name, validity, subject Name,
           subjectPublicKeyInfo, [1] issuerUniqueID, [2] subjectUniqueID (optional),
           [3] Extensions (optional) }
       Name ::= SEQUENCE OF RDN;  RDN ::= SET OF SEQUENCE { type OID, value }
       Extensions ::= SEQUENCE OF SEQUENCE { extnID OID, critical BOOLEAN (optional), extnValue }

   JA4X needs, in order: the OID of every attribute of the issuer, of the subject, and of every extension. Each OID's
   content bytes are copied into its list (issuer / subject / exts) as <length><bytes>.

   DER elements all start with a tag and a length (short form: one byte; long form: 0x8n, then n bytes). One reader,
   `tlv`, reads them for every element; meta.x509.ret says which state continues after it (the parser has no calls).
   Every level keeps a countdown of its bytes (tbsLeft, nameLeft, setLeft, itemLeft, extLeft), so the walk knows
   where each SEQUENCE / SET ends. */

#define X509_LIST_CAP 256           // bytes per list (2,048 bits)

#define R_CERT 1
#define R_TBS 2
#define R_VERSION 3
#define R_SERIAL 4
#define R_SIGALG 5
#define R_NAME 6
#define R_SET 7
#define R_ATV 8
#define R_OID 9
#define R_VALIDITY 10
#define R_SPKI 11
#define R_TBS_OPT 12
#define R_EXTSEQ 13
#define R_EXT 14

    state x509_start {
        meta.x509.walked = 1;
        meta.x509.ret = R_CERT;
        transition tlv;
    }

    /* ---- the shared TLV header reader ---- */

    state tlv {
        meta.x509.tag = pkt.lookahead<bit<8>>();
        pkt.advance(8);
        meta.x509.b = pkt.lookahead<bit<8>>();
        pkt.advance(8);
        transition select(meta.x509.b[7:7]) {
            0: tlv_short;
            1: tlv_long_start;
        }
    }

    state tlv_short {
        meta.x509.len = (bit<32>) meta.x509.b;
        meta.x509.hdrLen = 2;
        transition tlv_ret;
    }

    state tlv_long_start {
        meta.x509.lenBytes = meta.x509.b & 0x7f;
        meta.x509.len = 0;
        meta.x509.hdrLen = 2 + (bit<32>) (meta.x509.b & 0x7f);
        transition select(meta.x509.lenBytes > 3) {
            true:  accept;                          // over 16 MB: not a certificate
            false: tlv_long;
        }
    }

    state tlv_long {
        transition select(meta.x509.lenBytes) {
            0:       tlv_ret;
            default: tlv_long_byte;
        }
    }

    state tlv_long_byte {
        meta.x509.len = (meta.x509.len << 8) | (bit<32>) pkt.lookahead<bit<8>>();
        pkt.advance(8);
        meta.x509.lenBytes = meta.x509.lenBytes - 1;
        transition tlv_long;
    }

    state tlv_ret {
        transition select(meta.x509.ret) {
            R_CERT:     r_cert;
            R_TBS:      r_tbs;
            R_VERSION:  r_version;
            R_SERIAL:   r_serial;
            R_SIGALG:   r_sigalg;
            R_NAME:     r_name;
            R_SET:      r_set;
            R_ATV:      r_atv;
            R_OID:      r_oid;
            R_VALIDITY: r_validity;
            R_SPKI:     r_spki;
            R_TBS_OPT:  r_tbs_opt;
            R_EXTSEQ:   r_extseq;
            R_EXT:      r_ext;
            default:    accept;
        }
    }

    /* ---- Certificate, tbsCertificate ---- */

    state r_cert {                                  // inside Certificate: tbsCertificate comes first
        meta.x509.ret = R_TBS;
        transition tlv;
    }

    state r_tbs {
        meta.x509.tbsLeft = meta.x509.len;
        transition select(pkt.lookahead<bit<8>>()) {
            0xa0:    x_version;                     // [0] version is present
            default: x_serial;
        }
    }

    state x_version {
        meta.x509.ret = R_VERSION;
        transition tlv;
    }

    state r_version {
        meta.x509.tbsLeft = meta.x509.tbsLeft - meta.x509.hdrLen - meta.x509.len;
        pkt.advance(meta.x509.len * 8);
        transition x_serial;
    }

    state x_serial {
        meta.x509.ret = R_SERIAL;
        transition tlv;
    }

    state r_serial {
        meta.x509.tbsLeft = meta.x509.tbsLeft - meta.x509.hdrLen - meta.x509.len;
        pkt.advance(meta.x509.len * 8);
        meta.x509.ret = R_SIGALG;
        transition tlv;
    }

    state r_sigalg {
        meta.x509.tbsLeft = meta.x509.tbsLeft - meta.x509.hdrLen - meta.x509.len;
        pkt.advance(meta.x509.len * 8);
        meta.x509.list = 1;                         // the issuer Name follows
        meta.x509.ret = R_NAME;
        transition tlv;
    }

    /* ---- Name (issuer, then subject): SEQUENCE OF SET OF SEQUENCE { OID, value } ---- */

    state r_name {
        meta.x509.tbsLeft = meta.x509.tbsLeft - meta.x509.hdrLen - meta.x509.len;
        meta.x509.nameLeft = meta.x509.len;
        transition name_next;
    }

    state name_next {
        transition select(meta.x509.nameLeft == 0, meta.x509.list) {
            (true, 1):  x_validity;                 // after the issuer: validity, then the subject
            (true, 2):  x_spki;                     // after the subject: the public key
            (false, _): x_set;
            default:    accept;
        }
    }

    state x_set {
        meta.x509.ret = R_SET;
        transition tlv;
    }

    state r_set {
        meta.x509.nameLeft = meta.x509.nameLeft - meta.x509.hdrLen - meta.x509.len;
        meta.x509.setLeft = meta.x509.len;
        transition atv_next;
    }

    state atv_next {
        transition select(meta.x509.setLeft == 0) {
            true:  name_next;
            false: x_atv;
        }
    }

    state x_atv {
        meta.x509.ret = R_ATV;
        transition tlv;
    }

    state r_atv {
        meta.x509.setLeft = meta.x509.setLeft - meta.x509.hdrLen - meta.x509.len;
        meta.x509.itemLeft = meta.x509.len;
        meta.x509.ret = R_OID;
        transition tlv;
    }

    /* an OID (attribute type, or extnID): copy <length><content bytes> into the current list, then skip the rest
       of its attribute / extension */
    state r_oid {
        meta.x509.itemLeft = meta.x509.itemLeft - meta.x509.hdrLen - meta.x509.len;
        meta.x509.oidLeft = meta.x509.len;
        meta.x509.b = meta.x509.len[7:0];
        transition x_append;
    }

    state x_oid_byte {
        meta.x509.b = pkt.lookahead<bit<8>>();
        pkt.advance(8);
        meta.x509.oidLeft = meta.x509.oidLeft - 1;
        transition x_append;
    }

    state x_append {
        transition select(meta.x509.list) {
            1:       app_issuer;
            2:       app_subject;
            default: app_ext;
        }
    }

    state app_issuer {
        transition select(meta.x509.issuerLen == X509_LIST_CAP) {
            true:  x_overflow;
            false: app_issuer_byte;
        }
    }

    state app_issuer_byte {
        meta.x509.issuer = meta.x509.issuer[2039:0] ++ meta.x509.b;
        meta.x509.issuerLen = meta.x509.issuerLen + 1;
        transition x_after_append;
    }

    state app_subject {
        transition select(meta.x509.subjectLen == X509_LIST_CAP) {
            true:  x_overflow;
            false: app_subject_byte;
        }
    }

    state app_subject_byte {
        meta.x509.subject = meta.x509.subject[2039:0] ++ meta.x509.b;
        meta.x509.subjectLen = meta.x509.subjectLen + 1;
        transition x_after_append;
    }

    state app_ext {
        transition select(meta.x509.extsLen == X509_LIST_CAP) {
            true:  x_overflow;
            false: app_ext_byte;
        }
    }

    state app_ext_byte {
        meta.x509.exts = meta.x509.exts[2039:0] ++ meta.x509.b;
        meta.x509.extsLen = meta.x509.extsLen + 1;
        transition x_after_append;
    }

    state x_overflow {
        meta.x509.overflow = 1;
        transition x_after_append;
    }

    state x_after_append {
        transition select(meta.x509.oidLeft == 0) {
            true:  x_oid_done;
            false: x_oid_byte;
        }
    }

    state x_oid_done {
        pkt.advance(meta.x509.itemLeft * 8);       // the attribute's value, or the extension's criticality + value
        transition select(meta.x509.list) {
            3:       x_ext_next;
            default: atv_next;
        }
    }

    /* ---- validity, subject, public key ---- */

    state x_validity {
        meta.x509.ret = R_VALIDITY;
        transition tlv;
    }

    state r_validity {
        meta.x509.tbsLeft = meta.x509.tbsLeft - meta.x509.hdrLen - meta.x509.len;
        pkt.advance(meta.x509.len * 8);
        meta.x509.list = 2;                         // the subject Name follows
        meta.x509.ret = R_NAME;
        transition tlv;
    }

    state x_spki {
        meta.x509.ret = R_SPKI;
        transition tlv;
    }

    state r_spki {
        meta.x509.tbsLeft = meta.x509.tbsLeft - meta.x509.hdrLen - meta.x509.len;
        pkt.advance(meta.x509.len * 8);
        transition tbs_opt;
    }

    /* ---- optional parts: [1], [2] unique IDs (skipped), [3] extensions ---- */

    state tbs_opt {
        transition select(meta.x509.tbsLeft == 0) {
            true:  x509_done;
            false: x_tbs_opt;
        }
    }

    state x_tbs_opt {
        meta.x509.ret = R_TBS_OPT;
        transition tlv;
    }

    state r_tbs_opt {
        meta.x509.tbsLeft = meta.x509.tbsLeft - meta.x509.hdrLen - meta.x509.len;
        transition select(meta.x509.tag) {
            0xa3:    x_extseq;                      // [3] holds the Extensions SEQUENCE
            default: tbs_opt_skip;
        }
    }

    state tbs_opt_skip {
        pkt.advance(meta.x509.len * 8);
        transition tbs_opt;
    }

    state x_extseq {
        meta.x509.ret = R_EXTSEQ;
        transition tlv;
    }

    state r_extseq {
        meta.x509.extLeft = meta.x509.len;
        meta.x509.list = 3;
        transition x_ext_next;
    }

    state x_ext_next {
        transition select(meta.x509.extLeft == 0) {
            true:  x509_done;
            false: x_ext_read;
        }
    }

    state x_ext_read {
        meta.x509.ret = R_EXT;
        transition tlv;
    }

    state r_ext {
        meta.x509.extLeft = meta.x509.extLeft - meta.x509.hdrLen - meta.x509.len;
        meta.x509.itemLeft = meta.x509.len;
        meta.x509.ret = R_OID;
        transition tlv;
    }

    state x509_done {
        meta.x509.parsed = 1;
        transition accept;
    }
