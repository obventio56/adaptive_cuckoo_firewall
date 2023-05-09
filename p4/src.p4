/*******************************************************************************
 *  INTEL CONFIDENTIAL
 *
 *  Copyright (c) 2021 Intel Corporation
 *  All Rights Reserved.
 *
 *  This software and the related documents are Intel copyrighted materials,
 *  and your use of them is governed by the express license under which they
 *  were provided to you ("License"). Unless the License provides otherwise,
 *  you may not use, modify, copy, publish, distribute, disclose or transmit
 *  this software or the related documents without Intel's prior written
 *  permission.
 *
 *  This software and the related documents are provided as is, with no express
 *  or implied warranties, other than those that are expressly stated in the
 *  License.
 ******************************************************************************/


#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

struct metadata_t {
    bit<32> fingerprint_input;
    bit<32> fingerprint;
    bool stage_one_result;
    bool stage_two_result;
    bool stage_three_result;
    bit<32> return_val;
}

#include "common/headers.p4"
#include "common/util.p4"

struct reg_value {
    bit<32>     val;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {

        // Start with some random values for easy debugging
        ig_md.fingerprint = 42;
        ig_md.fingerprint_input = 43;
        ig_md.stage_one_result = false;
        ig_md.stage_two_result = false;
        ig_md.stage_three_result = false;
        ig_md.return_val = 44;

        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_ICMP : parse_icmp;
            IP_PROTOCOLS_TCP: parse_tcp;
            default : accept;
        }
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(packet_out pkt,
                              inout header_t hdr,
                              in metadata_t ig_md,
                              in ingress_intrinsic_metadata_for_deparser_t
                                ig_intr_dprsr_md
                              ) {

    apply {
        pkt.emit(hdr);
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    
    BypassEgress() bypass_egress;

    action drop() {
        ig_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    // Setup hash function for fingerprints
    CRCPolynomial<bit<32>>(32w0x04C11DB7, 
                        false, 
                        false, 
                        false, 
                        32w0xFFFFFFFF,
                        32w0xFFFFFFFF
                        ) poly1;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly1) fingerprint;

    // Wrap hash in action for multi-use
    action action_compute_fingerprint() {
        ig_md.fingerprint = fingerprint.get({
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,
            hdr.tcp.src_port,
            hdr.tcp.dst_port,
            hdr.ipv4.protocol
            //32w5
        });
    }

    // Register array for storing cuckoo filter
    Register<reg_value, bit<10>>(size=32w1024) stage_one;
    Register<reg_value, bit<10>>(size=32w1024) stage_two;
    Register<reg_value, bit<10>>(size=32w1024) stage_three;

    // Compute fingerprint and check it matches reg array entry at idx
    RegisterAction<reg_value, bit<10>, bool>(stage_one) stage_one_lookup = {
        void apply(inout reg_value val, out bool rv) {
            rv = val.val == ig_md.fingerprint;
        }
    };

    // Compute fingerprint and check it matches reg array entry at idx
    RegisterAction<reg_value, bit<10>, bool>(stage_two) stage_two_lookup = {
        void apply(inout reg_value val, out bool rv) {
            rv = val.val == ig_md.fingerprint;
        }
    };

    // Compute fingerprint and check it matches reg array entry at idx
    RegisterAction<reg_value, bit<10>, bool>(stage_three) stage_three_lookup = {
        void apply(inout reg_value val, out bool rv) {
            rv = val.val == ig_md.fingerprint;
        }
    };

    action action_check_membership_stage_one() {
        ig_md.stage_one_result = stage_one_lookup.execute(ig_md.fingerprint[9:0]);
    }

    action action_check_membership_stage_two() {
        ig_md.stage_two_result = stage_two_lookup.execute(ig_md.fingerprint[19:10]);
    }

    action action_check_membership_stage_three() {
        ig_md.stage_three_result = stage_three_lookup.execute(ig_md.fingerprint[29:20]);
    }

    apply {
        if (ig_intr_md.ingress_port == 0) {
            ig_tm_md.ucast_egress_port = 64;
            // Send to cpu (this should be copy to cpu)
        } else {
            ig_tm_md.ucast_egress_port = 0;
            if (hdr.ipv4.protocol == 1) {
                ig_tm_md.ucast_egress_port = 64;
            } else {
                action_compute_fingerprint();
                action_check_membership_stage_one();
                action_check_membership_stage_two();
                action_check_membership_stage_three();

                bool lookup_result = ig_md.stage_one_result || ig_md.stage_two_result || ig_md.stage_three_result;
                if (!lookup_result) {
                    drop();
                }
            }
        }    

        bypass_egress.apply(ig_tm_md);
        
    }
}

Pipeline(SwitchIngressParser(),
       SwitchIngress(),
       SwitchIngressDeparser(),
       EmptyEgressParser(),
       EmptyEgress(),
       EmptyEgressDeparser()) pipe;

Switch(pipe) main;
