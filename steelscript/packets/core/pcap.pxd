# cython: profile=False

# Copyright (c) 2017 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from libc.stdint cimport int32_t, int64_t, uint16_t, uint32_t, uint64_t

ctypedef enum MAGIC:
    ident = 0xa1b2c3d4
    ident_nano = 0xa1b23c4d
    swapped = 0xd4c3b2a1
    swapped_nano = 0x4d3cb2a1

ctypedef enum NGMAGIC:
    sec_hdr = 0x0a0d0d0a
    iface_descr = 0x00000001
    spb = 0x00000003
    epb = 0x00000006
    little = 0x1a2b3c4d
    big = 0x4d3c2b1a

ctypedef enum pktypes:
    bytes_data = 1
    array_data = 2

cdef:
    uint32_t SHB_MIN_SIZE
    int64_t SECTION_LEN_UNDEFINED
    uint16_t SEEK_FROM_CUR_POS, OPT_CODE_TSRES, OPT_CODE_TSLEN
    unsigned char INVALID_IFACE


cdef class PcapHeader:
    cdef:
        bytes _buffer, _order
        int32_t _tz_offset
        uint16_t use_buffer
        public uint32_t magic, ts_accuracy, snap_len, net_layer
        public uint32_t PCAP_MAGIC_IDENT, PCAP_MAGIC_IDENT_NANO
        public uint32_t PCAP_MAGIC_SWAPPED_NANO, PCAP_MAGIC_SWAPPED
        public uint16_t nano, major_version, minor_version


cdef class PktHeader:
    cdef:
        bytes _buffer, _order
        uint16_t use_buffer
        public uint32_t ts_sec, ts_usec, incl_len, orig_len

    cpdef double get_timestamp(self, uint16_t file_header_nano)


cdef class Decode:
    cdef:
        object fh
        object _iter
        unsigned char pk_format


cdef class PCAPDecode(Decode):
    cdef:
        PcapHeader header
        uint16_t PCAP_HDR_LEN, PKT_HDR_LEN

    cpdef int tz_offset(self)

    cpdef list pkts(self)


cdef class SectionHeaderBlock:
    cdef:
        object fh
        bytes b_len_data, _order
        public int64_t section_len
        public uint32_t block_type, block_len, magic
        public uint16_t use_buffer, major, minor


cdef class PCAPNGDecode(Decode):
    cdef:
        uint64_t pkt_count
        bytes order, int_unpack
        list iface_descrs
        SectionHeaderBlock sec_hdr

    cpdef list pkts(self)


cdef class PCAPReader:
    cdef:
        public Decode decoder

cdef class PCAPWriter:
    cdef:
        object _f
        PcapHeader _header
        PktHeader _p_header_c
        uint32_t _magic, _n
        double _ts

    cpdef writepkt(self, bytes pkt, double ts)


cdef tuple parse_epb(object fh, bytes order, list ifaces, unsigned char ptype)

cdef tuple parse_iface_descr(object fh, bytes order)

cpdef dict pcap_info(object f)
