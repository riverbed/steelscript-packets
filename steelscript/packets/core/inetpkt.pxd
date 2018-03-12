# cython: profile=False

# Copyright (c) 2017 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from cpython.array cimport array
from libc.stdint cimport uint32_t, uint16_t


cdef:
    unsigned char IPV4_LEN
    unsigned char IPV4_VER
    unsigned char IPV4_MIN_HDR_LEN
    unsigned char IPV6_LEN
    unsigned char IPV6_VER
    unsigned char MAC_LEN
    # ARP
    unsigned char ARP_TYPE_ETH
    unsigned char ARP_OP_REQUEST
    unsigned char ARP_OP_REPLY
    unsigned char ARP_OP_RARP_REQUEST
    unsigned char ARP_OP_RARP_REPLY
    unsigned char ARP_OP_DYN_RARP_REQUEST
    unsigned char ARP_OP_DYN_RARP_REPLY
    unsigned char ARP_OP_DYN_RARP_ERR
    unsigned char ARP_OP_INV_REQUEST
    unsigned char ARP_OP_INV_REPLY
    # ETHERTYPES
    uint16_t ETH_TYPE_IPV4
    uint16_t ETH_TYPE_ARP
    uint16_t ETH_TYPE_RARP
    uint16_t ETH_TYPE_8021Q
    uint16_t ETH_TYPE_IPV6
    uint16_t ETH_TYPE_MPLS_UCAST
    uint16_t ETH_TYPE_MPLS_MCAST
    # ICMP
    unsigned char ICMP_TYPE_ECHO_REPLY
    unsigned char ICMP_TYPE_DU
    unsigned char ICMP_TYPE_SRC_QUENCH
    unsigned char ICMP_TYPE_REDIR
    unsigned char ICMP_TYPE_ECHO
    unsigned char ICMP_TYPE_TIME_EX
    unsigned char ICMP_TYPE_PER_PROB
    unsigned char ICMP_TYPE_TS
    unsigned char ICMP_TYPE_TS_REPLY
    unsigned char ICMP_TYPE_INFO
    unsigned char ICMP_TYPE_INFO_REPLY
    unsigned char ICMP_DU_CODE_NET_UNREACH
    unsigned char ICMP_DU_CODE_HOST_UNREACH
    unsigned char ICMP_DU_CODE_PROTO_UNREACH
    unsigned char ICMP_DU_CODE_PORT_UNREACH
    unsigned char ICMP_DU_CODE_FRAG_NEEDED
    unsigned char ICMP_DU_CODE_SRC_RT_FAIL
    unsigned char ICMP_DU_CODE_DEST_NET_UNKNOWN
    unsigned char ICMP_DU_CODE_DEST_HOST_UNKNOWN
    unsigned char ICMP_DU_CODE_SRC_HOST_ISOLATED
    unsigned char ICMP_DU_CODE_NET_ADMIN_PROHIBIT
    unsigned char ICMP_DU_CODE_HOST_ADMIN_PROHIBIT
    unsigned char ICMP_DU_CODE_NET_TOS_UNREACH
    unsigned char ICMP_DU_CODE_HOST_TOS_UNREACH
    unsigned char ICMP_DU_CODE_COMMS_ADMIN_PROHIBIT
    unsigned char ICMP_DU_CODE_HOST_PRECEDENCE
    unsigned char ICMP_DU_CODE_PRECEDENCE_CUTOFF
    unsigned char ICMP_REDIR_CODE_NET
    unsigned char ICMP_REDIR_CODE_HOST
    unsigned char ICMP_REDIR_CODE_NET_TOS
    unsigned char ICMP_REDIR_CODE_HOST_TOS
    unsigned char ICMP_TIME_EX_CODE_TTL_EXCEEDED
    unsigned char ICMP_TIME_EX_CODE_FRAG_EXCEEDED
    unsigned char ICMP_PER_PROB_CODE_POINTER
    unsigned char ICMP_PER_PROB_CODE_OPTION_MISSING
    unsigned char ICMP_PER_PROB_CODE_LENGTH
    # PROTO IDs
    unsigned char PROTO_ICMP
    unsigned char PROTO_TCP
    unsigned char PROTO_UDP
    # PACKET QUERY TYPES
    unsigned char PQ_PKT
    unsigned char PQ_ETH
    unsigned char PQ_FRAME
    unsigned char PQ_ICMP
    uint16_t PQ_IP
    unsigned char PQ_TCP
    unsigned char PQ_UDP
    uint16_t PQ_ARP
    uint16_t PQ_MPLS
    uint16_t PQ_NETFLOW_SIMPLE
    uint16_t PQ_NULLPKT
    unsigned char PTR_VAL
    object offset_re
    char NOT_FOUND = -1

cdef uint16_t checksum(bytes pkt)

cdef unsigned char is_ipv4(bytes ip)

cdef void set_short_nibble(uint16_t* short_word,
                           unsigned char nibble,
                           unsigned char offset)

cdef void set_char_nibble(unsigned char* char_word,
                          unsigned char nibble,
                          unsigned char offset)

cdef uint16_t get_short_nibble(uint16_t short_word,
                               unsigned char offset)

cdef unsigned char get_char_nibble(unsigned char char_word,
                                   unsigned char offset)

cdef void set_bit(uint16_t* flags, unsigned char offset)

cdef void set_word_bit(uint32_t* flags, unsigned char offset)

cdef void set_cbit(unsigned char* flags, unsigned char offset)

cdef void unset_bit(uint16_t* flags, unsigned char offset)

cdef void unset_word_bit(uint32_t* flags, unsigned char offset)

cdef void unset_cbit(unsigned char* flags, unsigned char offset)

cdef class IP_CONST:
    cdef:
        readonly unsigned char IPV4_LEN
        readonly unsigned char IPV4_VER
        readonly unsigned char IPV4_MIN_HDR_LEN
        readonly unsigned char IPV6_LEN
        readonly unsigned char IPV6_VER
        readonly unsigned char MAC_LEN
        readonly unsigned char ARP_TYPE_ETH
        readonly unsigned char ARP_OP_REQUEST
        readonly unsigned char ARP_OP_REPLY
        readonly unsigned char ARP_OP_RARP_REQUEST
        readonly unsigned char ARP_OP_RARP_REPLY
        readonly unsigned char ARP_OP_DYN_RARP_REQUEST
        readonly unsigned char ARP_OP_DYN_RARP_REPLY
        readonly unsigned char ARP_OP_DYN_RARP_ERR
        readonly unsigned char ARP_OP_INV_REQUEST
        readonly unsigned char ARP_OP_INV_REPLY
        readonly uint16_t ETH_TYPE_IPV4
        readonly uint16_t ETH_TYPE_ARP
        readonly uint16_t ETH_TYPE_RARP
        readonly uint16_t ETH_TYPE_8021Q
        readonly uint16_t ETH_TYPE_IPV6
        readonly uint16_t ETH_TYPE_MPLS_UCAST
        readonly uint16_t ETH_TYPE_MPLS_MCAST
        readonly unsigned char ICMP_TYPE_ECHO_REPLY
        readonly unsigned char ICMP_TYPE_DU
        readonly unsigned char ICMP_TYPE_SRC_QUENCH
        readonly unsigned char ICMP_TYPE_REDIR
        readonly unsigned char ICMP_TYPE_ECHO
        readonly unsigned char ICMP_TYPE_TIME_EX
        readonly unsigned char ICMP_TYPE_PER_PROB
        readonly unsigned char ICMP_TYPE_TS
        readonly unsigned char ICMP_TYPE_TS_REPLY
        readonly unsigned char ICMP_TYPE_INFO
        readonly unsigned char ICMP_TYPE_INFO_REPLY
        readonly unsigned char ICMP_DU_CODE_NET_UNREACH
        readonly unsigned char ICMP_DU_CODE_HOST_UNREACH
        readonly unsigned char ICMP_DU_CODE_PROTO_UNREACH
        readonly unsigned char ICMP_DU_CODE_PORT_UNREACH
        readonly unsigned char ICMP_DU_CODE_FRAG_NEEDED
        readonly unsigned char ICMP_DU_CODE_SRC_RT_FAIL
        readonly unsigned char ICMP_DU_CODE_DEST_NET_UNKNOWN
        readonly unsigned char ICMP_DU_CODE_DEST_HOST_UNKNOWN
        readonly unsigned char ICMP_DU_CODE_SRC_HOST_ISOLATED
        readonly unsigned char ICMP_DU_CODE_NET_ADMIN_PROHIBIT
        readonly unsigned char ICMP_DU_CODE_HOST_ADMIN_PROHIBIT
        readonly unsigned char ICMP_DU_CODE_NET_TOS_UNREACH
        readonly unsigned char ICMP_DU_CODE_HOST_TOS_UNREACH
        readonly unsigned char ICMP_DU_CODE_COMMS_ADMIN_PROHIBIT
        readonly unsigned char ICMP_DU_CODE_HOST_PRECEDENCE
        readonly unsigned char ICMP_DU_CODE_PRECEDENCE_CUTOFF
        readonly unsigned char ICMP_REDIR_CODE_NET
        readonly unsigned char ICMP_REDIR_CODE_HOST
        readonly unsigned char ICMP_REDIR_CODE_NET_TOS
        readonly unsigned char ICMP_REDIR_CODE_HOST_TOS
        readonly unsigned char ICMP_TIME_EX_CODE_TTL_EXCEEDED
        readonly unsigned char ICMP_TIME_EX_CODE_FRAG_EXCEEDED
        readonly unsigned char ICMP_PER_PROB_CODE_POINTER
        readonly unsigned char ICMP_PER_PROB_CODE_OPTION_MISSING
        readonly unsigned char ICMP_PER_PROB_CODE_LENGTH
        readonly unsigned char PROTO_ICMP
        readonly unsigned char PROTO_TCP
        readonly unsigned char PROTO_UDP
        readonly unsigned char PQ_PKT
        readonly unsigned char PQ_ETH
        readonly unsigned char PQ_FRAME
        readonly unsigned char PQ_ICMP
        readonly uint16_t PQ_IP
        readonly unsigned char PQ_TCP
        readonly unsigned char PQ_UDP
        readonly uint16_t PQ_ARP
        readonly uint16_t PQ_MPLS
        readonly uint16_t PQ_NETFLOW_SIMPLE
        readonly uint16_t PQ_NULLPKT

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

    cpdef object get_field_val(self, bytes field)


cdef class NullPkt(PKT):
    cdef:
        array _buffer
        public bytes payload

    cpdef bytes pkt2net(self, dict kwargs)

    cpdef object get_field_val(self, bytes field)


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

    cpdef object get_field_val(self, bytes field)


cdef class UDP(PKT):

    cdef:
        public uint16_t sport, dport, ulen, checksum
        public PKT payload
        array _buffer

    cpdef bytes pkt2net(self, dict kwargs)

    cdef app_layer(self, array plbuffer)

    cpdef object get_field_val(self, bytes field)


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

    cpdef object get_field_val(self, bytes field)


cdef class ICMP(PKT):
    cdef:
        array _buffer
        public array data
        bint have_data
        public unsigned char type, code, pointer
        public uint16_t checksum, identifier, sequence, mtu
        public uint32_t orig_ts, rec_ts, trans_ts
        public PKT hdr_pkt
        public bytes echo_data
        array _address

    cpdef object get_field_val(self, bytes field)

    cpdef bytes pkt2net(self, dict kwargs)

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

    cpdef object get_field_val(self, bytes field)


cdef class MPLS(PKT):
    cdef:
        array _buffer
        uint32_t _data
        public PKT payload

    cpdef bytes pkt2net(self, dict kwargs)

    cpdef object get_field_val(self, bytes field)


cdef class Ethernet(PKT):

    cdef:
        array _buffer, _src_mac, _dst_mac
        uint16_t _tci
        public uint16_t type, tpid
        public PKT payload

    cpdef bytes pkt2net(self, dict kwargs)

    cpdef object get_field_val(self, bytes field)
