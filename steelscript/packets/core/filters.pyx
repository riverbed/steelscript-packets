# cython: language_level=3

# Copyright (c) 2018 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

ether_proto_ip = b'\x08\x00'
ip_proto_igmp = 2

cpdef bint match_ip_proto(bytes pkt,
                          unsigned char ip_proto=ip_proto_igmp):

    if pkt[12:14] == ether_proto_ip and pkt[23] == ip_proto:
        return 1
    return 0