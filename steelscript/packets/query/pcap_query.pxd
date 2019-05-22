# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from libc.stdint cimport uint16_t

from steelscript.packets.core.pcap cimport PCAPBase, pcap_pkthdr_t

cdef:
    uint16_t ERRBUF_SIZE
    unsigned char PLOAD_F_LEN

cdef:
    object offset_re
    dict known_fields
    char NOT_FOUND

cdef class Frame:
    cdef:
        double ts
        pcap_pkthdr_t hdr

    cpdef object get_field_val(self, str field)

cdef class PcapQuery:
    cdef:
        str srcname
        bint use_device
        PCAPBase reader
        bint live
        public dict fields
        dict l7_ports
        object local_tz
        public list field_functions, layer_order, wshark_fields
        double timeout
        public object stop_event

    cpdef bint fields_supported(self, list field_names)

    cpdef dict show_fields(self)
