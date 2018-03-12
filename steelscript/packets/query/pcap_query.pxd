# cython: profile=False

# Copyright (c) 2017 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from libc.stdint cimport uint16_t
from steelscript.packets.core.inetpkt cimport PKT

cdef:
    object offset_re
    dict known_fields
    char NOT_FOUND

cdef class PcapQuery:
    cdef:
        dict fields
        dict l7_ports
        object local_tz

    cpdef unsigned char fields_supported(self, list field_names)

    cpdef pcap_query(self,
                     object file_handle,
                     list wshark_fields,
                     double starttime,
                     double endtime,
                     unsigned char rdf=*,
                     unsigned char as_datetime=*)
