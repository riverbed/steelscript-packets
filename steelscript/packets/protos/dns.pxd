# Copyright (c) 2017 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from cpython.array cimport array
from libc.stdint cimport int64_t, uint64_t, \
    int32_t, uint32_t, uint16_t, intptr_t

from steelscript.packets.core.inetpkt cimport PKT

cpdef enum:
    DNS_PACKET_TYPE = 53
    DNS_PACKET_PORT = 53
    DNSTYPE_ANY = 0
    DNSTYPE_A = 1
    DNSTYPE_NS = 2
    DNSTYPE_CNAME = 5
    DNSTYPE_SOA = 6
    DNSTYPE_WKS = 11
    DNSTYPE_PTR = 12
    DNSTYPE_HINFO = 13
    DNSTYPE_MX = 15
    DNSTYPE_TXT = 16
    DNSTYPE_SIG = 24
    DNSTYPE_KEY = 25
    DNSTYPE_GPOS = 27
    DNSTYPE_AAAA = 28
    DNSTYPE_LOC = 29
    DNSTYPE_EID = 31
    DNSTYPE_SRV = 33
    DNSTYPE_KX = 36
    DNSTYPE_CERT = 37
    DNSTYPE_OPT = 41
    DNSTYPE_RRSIG = 46
    DNSTYPE_NSEC = 47
    DNSTYPE_DNSKEY = 48
    DNSTYPE_DHCID = 49
    DNSTYPE_NSEC3 = 50
    DNSTYPE_NSEC3PARAM = 51
    DNSTYPE_IXFR = 251
    DNSTYPE_AXFR = 252
    DNSTYPE_ALL = 255
    DNSTYPE_RESERVED = 65535
    OPTCODE_QUERY = 0
    OPTCODE_STATUS = 2
    OPTCODE_NOTIFY = 4
    OPTCODE_UPDATE = 5
    RCODE_NOERROR = 0
    RCODE_FORMERR = 1
    RCODE_SERVFAIL = 2
    RCODE_NXDOMAIN = 3
    RCODE_NOTIMP = 4
    RCODE_REFUSED = 5
    RCODE_YXDOMAIN = 6
    RCODE_YXRRSET = 7
    RCODE_NXRRSET = 8
    RCODE_NOTAUTH = 9
    RCODE_NOTZONE = 10
    RCLASS_IN = 1
    RCLASS_NONE = 254
    RCLASS_ANY = 255
    PNTR=0
    LABEL = 49152
    SOA_MNAME = 2
    SOA_RNAME = 4
    SOA_SER = 6
    SOA_REF = 8
    SOA_RET = 10
    SOA_EXP = 12
    SOA_MIN = 14

cdef array hostname_to_label_array(bytes hostname)

cdef bytes read_dns_name_bytes(array byte_array,
                               uint16_t* offset,
                               dict label_store)

cdef bytes write_dns_name_bytes(bytes dns_name,
                                uint16_t* offset,
                                dict labels,
                                bint compress=*)

cdef tuple parse_resource(array byte_array,
                          uint16_t* offset,
                          dict label_store)

cdef bytes parse_soa(array res_data, uint16_t* offset, uint16_t* rlen,
                     dict labels)

cdef bytes pack_soa(bytes res_data, uint16_t* offset, dict labels,
                    bint compress=*)


cdef class DNSQuery:
    cdef:
        bytes _query_name
        public uint16_t query_type, query_class

    cdef bytes pack(self, uint16_t* offset, dict labels, bint compress=*)


cdef class DNSResource:
    cdef:
        bytes _domain_name
        public uint16_t res_type, res_class, res_len
        public uint32_t res_ttl
        bytes res_data

    cdef bytes pack(self, uint16_t* offset,
                          dict labels,
                          bint compress=*,
                          bint update=*)


cdef class DNS(PKT):
    cdef:
        array _buffer
        public uint16_t ident, query_count, answer_count, auth_count, ad_count
        uint16_t _flags
        public list queries, answers, authority, ad
        dict labels

    cpdef object get_field_val(self, bytes field)

    cpdef bytes pkt2net(self, dict kwargs)
