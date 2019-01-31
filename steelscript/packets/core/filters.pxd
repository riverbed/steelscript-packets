# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

cdef:
    bytes ether_proto_ip
    unsigned char ip_proto_igmp

cpdef bint match_ip_proto(bytes pkt,
                          unsigned char ip_proto=*)

