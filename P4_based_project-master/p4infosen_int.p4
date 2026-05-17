/* ============================================================
 * P4InfoSen-INT: Information-Sensitive In-band Network Telemetry
 * Runs on BMv2 simple_switch (v1model)
 *
 * Topology:  h1 --- s1 --- s2 --- s3 --- h2
 *                                  |
 *                                  da  (collector / data-analyser)
 *
 * s1 = INT ingress  : initialises INT shim, inserts hop-0 record
 * s2 = INT transit  : appends hop-1 record
 * s3 = INT egress   : appends hop-2 record, clones full INT pkt
 *                     to da via mirror session 100, then strips INT
 *                     from the copy going to h2
 *
 * PMT (Priority Mapping Table):
 *   Each switch decides whether queue-depth or egress-port is the
 *   more "information-rich" telemetry type for the current moment.
 *   Control plane can flip this per-switch via table_set_default.
 *   Whichever wins is embedded in the hop record.
 *
 * Sampling: every INT_INTERVAL-th packet per flow becomes INT.
 * ============================================================ */

#include <core.p4>
#include <v1model.p4>

/* ---- Constants ---- */
const bit<16> TYPE_IPV4    = 0x0800;
const bit<8>  PROTO_INT    = 0xFD;   /* RFC-3692 experimental */
const bit<8>  TELEM_QUEUE  = 0x01;
const bit<8>  TELEM_PORT   = 0x02;
const bit<32> INT_INTERVAL = 5;      /* 1-in-5 sampling */

/* ---- Typedef ---- */
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/* ===========================================================
 *  HEADERS
 * =========================================================== */

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

/* INT shim: sits immediately after IP header */
header int_shim_t {
    bit<8>  hopCount;   /* how many switches have inserted a hop record */
    bit<8>  origProto;  /* original IP protocol (TCP=6, UDP=17)         */
    bit<16> reserved;
}

/* Each switch inserts exactly one hop record (8 bytes) */
header int_hop_t {
    bit<32> switchId;
    bit<8>  telemType;   /* TELEM_QUEUE or TELEM_PORT */
    bit<8>  telemPrio;   /* priority assigned by local PMT */
    bit<16> telemValue;  /* actual measured value */
}

/* Fixed stack for 3 hops (s1, s2, s3) */
header int_hop1_t { bit<32> switchId; bit<8> telemType; bit<8> telemPrio; bit<16> telemValue; }
header int_hop2_t { bit<32> switchId; bit<8> telemType; bit<8> telemPrio; bit<16> telemValue; }
header int_hop3_t { bit<32> switchId; bit<8> telemType; bit<8> telemPrio; bit<16> telemValue; }

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    int_shim_t  int_shim;
    int_hop1_t  int_hop1;
    int_hop2_t  int_hop2;
    int_hop3_t  int_hop3;
}

struct metadata {
    bit<1>  is_int_pkt;
    bit<1>  is_ingress_sw;
    bit<1>  is_egress_sw;
    bit<8>  pmt_queue_prio;
    bit<8>  pmt_port_prio;
    bit<32> switch_id;

}

/* ===========================================================
 *  PARSER
 * =========================================================== */

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start { transition parse_ethernet; }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_ipv4;
            default   : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_INT : parse_int_shim;
            default   : accept;
        }
    }

    state parse_int_shim {
        packet.extract(hdr.int_shim);
        transition select(hdr.int_shim.hopCount) {
            0       : accept;
            default : parse_hop1;
        }
    }

    state parse_hop1 {
        packet.extract(hdr.int_hop1);
        transition select(hdr.int_shim.hopCount) {
            1       : accept;
            default : parse_hop2;
        }
    }

    state parse_hop2 {
        packet.extract(hdr.int_hop2);
        transition select(hdr.int_shim.hopCount) {
            2       : accept;
            default : parse_hop3;
        }
    }

    state parse_hop3 {
        packet.extract(hdr.int_hop3);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/* ===========================================================
 *  INGRESS
 * =========================================================== */

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(256) pkt_counter;

    action drop() { mark_to_drop(standard_metadata); }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl         = hdr.ipv4.ttl - 1;
    }

    action set_switch_id(bit<32> sw_id) {
        meta.switch_id = sw_id;
    }

    action mark_as_int_ingress() { meta.is_ingress_sw = 1; }
    action mark_as_int_egress()  { meta.is_egress_sw  = 1; }

    /* PMT: control plane picks which metric is high-priority */
    action set_queue_high_priority() {
        meta.pmt_queue_prio = 9;
        meta.pmt_port_prio  = 3;
    }
    action set_port_high_priority() {
        meta.pmt_queue_prio = 3;
        meta.pmt_port_prio  = 9;
    }

    table ipv4_lpm {
        key     = { hdr.ipv4.dstAddr : lpm; }
        actions = { ipv4_forward; drop; NoAction; }
        size    = 64;
        default_action = drop();
    }

    table switch_id_tbl {
        key     = { }
        actions = { set_switch_id; NoAction; }
        size    = 1;
        default_action = NoAction();
    }

    /* Keyed on src+dst IP: which flows get INT? and ingress or egress? */
    table int_role_tbl {
        key = {
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
        }
        actions = { mark_as_int_ingress; mark_as_int_egress; NoAction; }
        size    = 16;
        default_action = NoAction();
    }

    /* PMT table — keyless, driven entirely by default action */
    table pmt_tbl {
        key     = { }
        actions = { set_queue_high_priority; set_port_high_priority; }
        size    = 1;
        default_action = set_queue_high_priority();
    }

    apply {
        if (!hdr.ipv4.isValid()) { return; }

        ipv4_lpm.apply();
        switch_id_tbl.apply();

        meta.is_ingress_sw = 0;
        meta.is_egress_sw  = 0;
        int_role_tbl.apply();

        pmt_tbl.apply();

        /* Sampling: 1-in-INT_INTERVAL per flow (hashed src+dst+proto) */
        bit<32> idx;
        hash(idx, HashAlgorithm.crc32, (bit<32>)0,
             { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol },
             (bit<32>)256);

        bit<32> cnt;
        pkt_counter.read(cnt, idx);
        cnt = cnt + 1;

        if (cnt == INT_INTERVAL) {
            meta.is_int_pkt = 1;
            cnt = 0;
        } else {
            meta.is_int_pkt = 0;
        }
        pkt_counter.write(idx,cnt);

        /* Ingress switch: initialise INT shim on sampled packets */
        if (meta.is_ingress_sw == 1 && meta.is_int_pkt == 1) {
            hdr.int_shim.setValid();
            hdr.int_shim.hopCount  = 0;
            hdr.int_shim.origProto = hdr.ipv4.protocol;
            hdr.int_shim.reserved  = 0;
            hdr.ipv4.protocol      = PROTO_INT;
            hdr.ipv4.totalLen      = hdr.ipv4.totalLen + 4; /* shim = 4 B */
         }
    }
}

/* ===========================================================
 *  EGRESS
 * =========================================================== */

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    /* Insert into the correct hop slot based on hopCount BEFORE insert */
    action insert_hop1(bit<32> sw_id, bit<8> t_type, bit<8> t_prio, bit<16> t_val) {
        hdr.int_hop1.setValid();
        hdr.int_hop1.switchId   = sw_id;
        hdr.int_hop1.telemType  = t_type;
        hdr.int_hop1.telemPrio  = t_prio;
        hdr.int_hop1.telemValue = t_val;
        hdr.int_shim.hopCount   = hdr.int_shim.hopCount + 1;
        hdr.ipv4.totalLen       = hdr.ipv4.totalLen + 8;
    }

    action insert_hop2(bit<32> sw_id, bit<8> t_type, bit<8> t_prio, bit<16> t_val) {
        hdr.int_hop2.setValid();
        hdr.int_hop2.switchId   = sw_id;
        hdr.int_hop2.telemType  = t_type;
        hdr.int_hop2.telemPrio  = t_prio;
        hdr.int_hop2.telemValue = t_val;
        hdr.int_shim.hopCount   = hdr.int_shim.hopCount + 1;
        hdr.ipv4.totalLen       = hdr.ipv4.totalLen + 8;
    }

    action insert_hop3(bit<32> sw_id, bit<8> t_type, bit<8> t_prio, bit<16> t_val) {
        hdr.int_hop3.setValid();
        hdr.int_hop3.switchId   = sw_id;
        hdr.int_hop3.telemType  = t_type;
        hdr.int_hop3.telemPrio  = t_prio;
        hdr.int_hop3.telemValue = t_val;
        hdr.int_shim.hopCount   = hdr.int_shim.hopCount + 1;
        hdr.ipv4.totalLen       = hdr.ipv4.totalLen + 8;
    }

    action nop() { }

    /* Keyed on hopCount: each switch fills the next available slot */
    table int_insert_tbl {
        key     = { hdr.int_shim.hopCount : exact; }
        actions = { insert_hop1; insert_hop2; insert_hop3; nop; }
        size    = 8;
        default_action = nop();
    }

    apply {
        if (!hdr.int_shim.isValid()) { return; }

        /* Choose telemetry value based on PMT priorities */
        bit<16> chosen_type;
        bit<8>  chosen_prio;
        bit<16> chosen_val;

        if (meta.pmt_queue_prio >= meta.pmt_port_prio) {
            chosen_type = (bit<16>) TELEM_QUEUE;
            chosen_prio = meta.pmt_queue_prio;
            chosen_val  = (bit<16>) standard_metadata.enq_qdepth;
        } else {
            chosen_type = (bit<16>) TELEM_PORT;
            chosen_prio = meta.pmt_port_prio;
            chosen_val  = (bit<16>) standard_metadata.egress_port;
        }

        /* Insert this switch's hop record */
        /* We pass the runtime-chosen values via the action parameters.
         * The table matches on current hopCount (before our insert).  */
        int_insert_tbl.apply();

        /* Overwrite the placeholder values set by the table action
         * with the real runtime values chosen above.
         * We use if-ladder on hopCount (which is now post-increment). */
        bit<8> hc = hdr.int_shim.hopCount;
        if (hc == 1) {
            hdr.int_hop1.switchId   = meta.switch_id;
            hdr.int_hop1.telemType  = (bit<8>) chosen_type;
            hdr.int_hop1.telemPrio  = chosen_prio;
            hdr.int_hop1.telemValue = chosen_val;
        } else if (hc == 2) {
            hdr.int_hop2.switchId   = meta.switch_id;
            hdr.int_hop2.telemType  = (bit<8>) chosen_type;
            hdr.int_hop2.telemPrio  = chosen_prio;
            hdr.int_hop2.telemValue = chosen_val;
        } else if (hc == 3) {
            hdr.int_hop3.switchId   = meta.switch_id;
            hdr.int_hop3.telemType  = (bit<8>) chosen_type;
            hdr.int_hop3.telemPrio  = chosen_prio;
            hdr.int_hop3.telemValue = chosen_val;
        }

        /* Egress switch: clone full INT packet to collector, then strip */
        if (meta.is_egress_sw == 1) {
            /* Mirror session 100 must be configured before run:
             *   mirroring_add 100 <da_port>
             * The clone carries the full INT packet; da reads it.     */
            clone(CloneType.E2E, 100);


            /* Strip INT from the copy going to h2 */
            bit<16> int_bytes;
            /* shim = 4, each hop = 8 */
            if      (hdr.int_hop3.isValid()) { int_bytes = 4 + 8 + 8 + 8; }
            else if (hdr.int_hop2.isValid()) { int_bytes = 4 + 8 + 8; }
            else if (hdr.int_hop1.isValid()) { int_bytes = 4 + 8; }
            else                             { int_bytes = 4; }

            hdr.ipv4.protocol = hdr.int_shim.origProto;
            hdr.ipv4.totalLen = hdr.ipv4.totalLen - int_bytes;

            hdr.int_shim.setInvalid();
            hdr.int_hop1.setInvalid();
            hdr.int_hop2.setInvalid();
            hdr.int_hop3.setInvalid();
        }
    }
}

/* ===========================================================
 *  CHECKSUM
 * =========================================================== */

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
              hdr.ipv4.totalLen, hdr.ipv4.identification,
              hdr.ipv4.flags, hdr.ipv4.fragOffset,
              hdr.ipv4.ttl, hdr.ipv4.protocol,
              hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/* ===========================================================
 *  DEPARSER
 * =========================================================== */

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
            packet.emit(hdr.int_shim);
            packet.emit(hdr.int_hop1);
            packet.emit(hdr.int_hop2);
            packet.emit(hdr.int_hop3);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;