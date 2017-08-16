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

"""
Supported fields:
ARP -
    arp.hw.type                 Hardware type   Unsigned integer, 2 bytes
    arp.proto.type	            Protocol type	Unsigned integer, 2 bytes
    arp.hw.size	                Hardware size	Unsigned integer, 1 byte
    arp.proto.size	            Protocol size	Unsigned integer, 1 byte
    arp.src.hw_mac	            Sender MAC address	Ethernet or other MAC address
    arp.src.proto_ipv4	        Sender IP address	IPv4 address
    arp.dst.hw_mac	            Target MAC address	Ethernet or other MAC address
    arp.dst.proto_ipv4	        Target IP address	IPv4 address
    
IP - 
    ip.checksum	                Header checksum	Unsigned integer, 2 bytes
    ip.dst	                    Destination	IPv4 address
    ip.flags	                Flags	Unsigned integer, 1 byte
    ip.hdr_len	                Header Length	Unsigned integer, 1 byte
    ip.id	                    Identification	Unsigned integer, 2 bytes
    ip.len	                    Total Length	Unsigned integer, 2 bytes
    ip.proto	                Protocol	Unsigned integer, 1 byte
    ip.src	                    Source	IPv4 address
    ip.tos	                    Type of Service	Unsigned integer, 1 byte
    ip.ttl	                    Time to live	Unsigned integer, 1 byte
    ip.version	                Version	Unsigned integer, 1 byte
    
MPLS - TODO
    mpls.bottom	                MPLS Bottom Of Label Stack
                                            Unsigned integer, 4 bytes <-why???
    mpls.label	                MPLS Label	Unsigned integer, 4 bytes
    mpls.ttl	                MPLS TTL	Unsigned integer, 4 bytes <- wtf??
    
TCP - 
    tcp.srcport	                Source Port	Unsigned integer, 2 bytes
    tcp.dstport	                Destination Port	Unsigned integer, 2 bytes
    tcp.seq	                    Sequence number	Unsigned integer, 4 bytes
    tcp.ack	                    Acknowledgment number	Unsigned integer, 4 bytes
    tcp.hdr_len	                Header Length	Unsigned integer, 1 byte
                                    Return data_offset?
    tcp.len	                    TCP Segment Len	Unsigned integer, 4 bytes
    tcp.flags	                Flags	Unsigned integer, 2 bytes
    tcp.flags.urg	            Urgent	Boolean
    tcp.flags.ack	            Acknowledgment	Boolean
    tcp.flags.push	            Push	Boolean
    tcp.flags.reset	            Reset	Boolean
    tcp.flags.syn	            Syn	Boolean
    tcp.flags.fin	            Fin	Boolean
    tcp.window_size_value	    Window size value	Unsigned integer, 2 bytes
    tcp.checksum	            Checksum	Unsigned integer, 2 bytes
    tcp.urgent_pointer	        Urgent pointer	Unsigned integer, 2 bytes
    tcp.payload                 The entire tcp payload if any
    tcp.payload.offset[x:y]     bytes of the payload from x -> y but not 
                                including y. Like string slices.
    
UDP -
    udp.srcport	                Source Port	Unsigned integer, 2 bytes
    udp.dstport	                Destination Port	Unsigned integer, 2 bytes
    udp.length	                Length	Unsigned integer, 2 bytes
    udp.checksum	            Checksum	Unsigned integer, 2 bytes
    udp.payload                 The entire tcp payload if any
    upd.payload.offset[x:y]     bytes of the payload from x -> y but not 
                                including y. Like string slices.

"""
