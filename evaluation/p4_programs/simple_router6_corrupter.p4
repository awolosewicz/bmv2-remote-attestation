/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type ipv6_t {
	fields {
		version : 4;
		tc : 8;
		flow_lbl : 20;
		payload_len : 16;
		nxt_hdr : 8;
		hlim: 8;
		srcAddr: 128;
		dstAddr: 128;
	}
}

header_type hbh_t {
	fields {
		dummy: 16;
		id: 8;
		len: 8;
		padding: 32;
		switch_register: 128;
		switch_table: 128;
		switch_program: 128;
		path_register: 128;
		path_table: 128;
		path_program: 128;
	}
}

parser start {
    return parse_ethernet;
}

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86dd
#define EXTENSION_HBH 0x00
header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
	ETHERTYPE_IPV6 : parse_ipv6;
        default: ingress;
    }
}

header ipv4_t ipv4;
header ipv6_t ipv6;
header hbh_t hbh;

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

parser parse_ipv4 {
    extract(ipv4);
    return ingress;
}

parser parse_ipv6 {
    extract(ipv6);
    return select(latest.nxt_hdr) {
	EXTENSION_HBH: parse_hbh;
	default: ingress;
    }
}

parser parse_hbh {
    extract(hbh);
    hbh.switch_table = 0x1;
    hbh.path_table = 0x2;
    hbh.padding = 0x1;
    return ingress;
}

action _drop() {
    drop();
}

header_type routing_metadata_t {
    fields {
        nhop_ipv4 : 32;
    }
}

metadata routing_metadata_t routing_metadata;

header_type routing_metadata6_t {
    fields {
        nhop_ipv6 : 128;
    }
}

metadata routing_metadata6_t routing_metadata6;

action set_nhop(nhop_ipv4, port) {
    modify_field(routing_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    modify_field(ipv4.ttl, ipv4.ttl - 1);
}

action set_nhop6(nhop_ipv6, port) {
    modify_field(routing_metadata6.nhop_ipv6, nhop_ipv6);
    modify_field(standard_metadata.egress_spec, port);
    modify_field(ipv6.hlim, ipv6.hlim - 1);
}

table ipv4_lpm {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        set_nhop;
        _drop;
    }
    size: 1024;
}

table ipv6_lpm {
    reads {
        ipv6.dstAddr : lpm;
    }
    actions {
        set_nhop6;
        _drop;
    }
    size: 1024;
}

action set_dmac(dmac) {
    modify_field(ethernet.dstAddr, dmac);
}

table forward {
    reads {
        routing_metadata.nhop_ipv4 : exact;
    }
    actions {
        set_dmac;
        _drop;
    }
    size: 512;
}

table forward6 {
    reads {
        routing_metadata6.nhop_ipv6 : exact;
    }
    actions {
        set_dmac;
        _drop;
    }
    size: 512;
}

action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    size: 256;
}

control ingress {
    if(valid(ipv4) and ipv4.ttl > 0) {
        apply(ipv4_lpm);
        apply(forward);
    }
    if(valid(ipv6) and ipv6.hlim > 0) {
        apply(ipv6_lpm);
        apply(forward6);
    }
}

control egress {
    apply(send_frame);
}


