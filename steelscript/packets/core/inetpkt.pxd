# cython: profile=False

# Copyright (c) 2017 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from cpython.array cimport array
from libc.stdint cimport int64_t, uint64_t, \
    int32_t, uint32_t, uint16_t, intptr_t


# codes from
# http://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
# MARS and OP_EXP not implemented.
cpdef enum ARP_OPS:
    request = 1
    reply = 2
    rarp_request = 3
    rarp_reply = 4
    dyn_rarp_request = 5
    dyn_rarp_reply = 6
    dyn_rarp_err = 7
    inverse_arp_request = 8
    inverse_arp_reply = 9

cpdef enum ARP_CONST:
    hwt_ether = 1
    ipv4_len = 4
    eth_mac_len = 6

cpdef enum ETHERTYPES:
    ipv4 = 0x0800
    arp = 0x0806
    rarp = 0x8035
    ipv6 = 0x86dd
    mpls_unicast = 0x8847
    mpls_multicast = 0x8848

ctypedef enum PQTYPES:
    t_pkt = 0
    t_frame = 1
    t_eth = 2
    t_ip = 3
    t_tcp = 4
    t_udp = 5
    t_arp = 6
    # 7 and 8 reserved
    t_mpls = 9
    t_netflow_simple = 2005
    t_nullpkt = 0xffff

cpdef enum PROTO:
    tcp = 6
    udp = 17

cdef:
    unsigned char PTR_VAL = 0
    object offset_re
    char NOT_FOUND = -1

cdef uint16_t checksum(bytes pkt)

cdef unsigned char is_ipv4(bytes ip)

cdef void set_short_nibble(uint16_t* short_word,
                           unsigned char nibble,
                           unsigned char which)

cdef void set_char_nibble(unsigned char* char_word,
                          unsigned char nibble,
                          unsigned char which)

cdef uint16_t get_short_nibble(uint16_t short_word,
                               unsigned char which)

cdef unsigned char get_char_nibble(unsigned char char_word,
                                   unsigned char which)

cdef void set_bit(uint16_t* flags, unsigned char offset)

cdef void set_word_bit(uint32_t* flags, unsigned char offset)

cdef void set_cbit(unsigned char* flags, unsigned char offset)

cdef void unset_bit(uint16_t* flags, unsigned char offset)

cdef void unset_word_bit(uint32_t* flags, unsigned char offset)

cdef void unset_cbit(unsigned char* flags, unsigned char offset)


cdef class PKT:
    cdef:
        public dict l7_ports, query_field_map
        public bytes pkt_name
        public uint16_t pq_type
        public tuple query_fields

    cpdef PKT get_layer(self, bytes name, int instance=*, int found=*)

    cpdef PKT get_layer_by_type(self,
                                uint16_t pq_type,
                                int instance=*,
                                int found=*)

    cpdef bytes pkt2net(self, dict kwargs)

    cpdef tuple from_buffer(self, tuple args, dict kwargs)

    cpdef object get_field_val(self, bytes field)


cdef class ARP(PKT):
    cdef:
        array _buffer
        uint16_t _operation
        public uint16_t hardware_type, proto_type,
        public unsigned char hardware_len, proto_len
        public bytes sender_hw_addr, sender_proto_addr, target_hw_addr, \
            target_proto_addr

    cpdef bytes pkt2net(self, dict kwargs)


cdef class NullPkt(PKT):
    cdef:
        array _buffer
        public bytes payload

    cpdef bytes pkt2net(self, dict kwargs)


cdef class Ip4Ph:
    cdef:
        public bytes src, dst
        public unsigned char reserved, proto
        public uint16_t payload_len


cdef class NetflowSimple(PKT):
    cdef:
        array _buffer
        public uint16_t version, count
        public uint32_t sys_uptime, unix_secs, unix_nano_seconds
        public bytes payload

    cpdef bytes pkt2net(self, dict kwargs)


cdef class UDP(PKT):

    cdef:
        public uint16_t sport, dport, ulen, checksum
        public PKT payload
        array _buffer

    cpdef bytes pkt2net(self, dict kwargs)

    cdef app_layer(self, array plbuffer)


cdef class TCP(PKT):

    cdef:
        array _buffer
        public uint16_t sport, dport, window, checksum, urg_ptr, ws_len
        uint16_t _off_flags
        public uint32_t sequence, acknowledgment
        bytes _options, _pad
        public PKT payload

    cpdef bytes pkt2net(self, dict kwargs)

    cdef app_layer(self, array plbuffer)


cdef class IP(PKT):

    cdef:
        array _src, _dst, _buffer, _pad
        uint16_t _flags_offset
        unsigned char _version_iphl, _proto
        Ip4Ph ipv4_pheader

        public unsigned char ttl, tos
        public uint16_t checksum, total_len, ident
        public PKT payload


    cpdef bytes pkt2net(self, dict kwargs)


cdef class MPLS(PKT):
    cdef:
        array _buffer
        uint32_t _data
        public PKT payload

    cpdef bytes pkt2net(self, dict kwargs)


cdef class Ethernet(PKT):

    cdef:
        array _buffer, _src_mac, _dst_mac
        public uint16_t type
        public PKT payload

    cpdef bytes pkt2net(self, dict kwargs)
